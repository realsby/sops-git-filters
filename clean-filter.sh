#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Clean Filter for Git                                       ║
# ║                                                                  ║
# ║  Git calls this script automatically during `git add` for any    ║
# ║  file matched by the "sops" filter in .gitattributes.            ║
# ║                                                                  ║
# ║  How git clean/smudge filters work:                              ║
# ║                                                                  ║
# ║    Working dir ──[clean]──▶ Git repo (staged/committed)          ║
# ║    Git repo ──[smudge]──▶ Working dir (checkout/pull)            ║
# ║                                                                  ║
# ║  This is the "clean" side: it receives plaintext on stdin and    ║
# ║  must output the encrypted version for git to store.             ║
# ║                                                                  ║
# ║  The problem: SOPS encryption is non-deterministic — encrypting  ║
# ║  the same plaintext twice produces different ciphertext (new IV  ║
# ║  each time). This means git would see every file as "changed"    ║
# ║  on every checkout, even if nothing actually changed.            ║
# ║                                                                  ║
# ║  The fix: before encrypting, we decrypt what's already in the    ║
# ║  index (or HEAD) and compare it to the new content. If it is     ║
# ║  identical, we reuse the existing ciphertext — no false diff.    ║
# ║                                                                  ║
# ║  That comparison needs the stored version to decrypt. When it    ║
# ║  does not (keys or cloud credentials missing) the filter stops   ║
# ║  with sops' own error. It does NOT re-encrypt blindly: that      ║
# ║  showed unchanged secrets as modified and committed them again.  ║
# ║  SOPS_FILTER_FORCE_REENCRYPT=1 skips the comparison on purpose   ║
# ║  (storage-format change, fresh data keys). It acts on every run  ║
# ║  of the filter in the command it is set on, not only on the file ║
# ║  you mean: set it on `git add <file>` and commit without it. On  ║
# ║  `git commit -a` it re-encrypts every managed file git checks    ║
# ║  again, and unchanged secrets get new ciphertext.                ║
# ║                                                                  ║
# ║  Git runs this filter again each time it looks at a secret with  ║
# ║  uncommitted changes. A run remembers its answer for 10 minutes  ║
# ║  (no plaintext: see "What a run a moment ago found" below), and  ║
# ║  the next run asked the same question needs no call to sops.     ║
# ║  SOPS_FILTER_CACHE=0 turns that off.                             ║
# ║                                                                  ║
# ║  The filter is also idempotent: input that is the ciphertext     ║
# ║  git holds (a working copy that was never decrypted, also with   ║
# ║  the CRLF line endings core.autocrlf adds) is stored unchanged,  ║
# ║  never encrypted a second time. Any other SOPS document must     ║
# ║  decrypt with your keys first; its plaintext is then handled     ║
# ║  like any edit. One that does not decrypt (another project's     ║
# ║  keys, a forged one) is refused.                                 ║
# ║                                                                  ║
# ║  Failure policy: this filter FAILS HARD. If sops is missing or   ║
# ║  .sops.yaml is absent, it exits non-zero and (combined with      ║
# ║  filter.sops.required=true, set by install.sh) git aborts the    ║
# ║  add/commit instead of silently staging plaintext secrets.       ║
# ║                                                                  ║
# ║  It also does not take sops' word for it. What sops returns is   ║
# ║  checked before git gets it: the result must be a completely     ║
# ║  encrypted SOPS document (lib.sh). A creation rule with          ║
# ║  encrypted_regex and friends, or an old sops, can otherwise      ║
# ║  leave the content in clear inside a valid-looking envelope.     ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	echo "ERROR: lib.sh is missing next to clean-filter.sh (${SCRIPT_DIR}) — update or re-copy sops-git-filters" >&2
	exit 1
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

# Git passes the filename as %f (configured in filter.sops.clean).
# We need it so SOPS can look up the right .sops.yaml creation rule.
if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <filename>" >&2
	exit 1
fi

FILENAME="$1"

# Git pipes the file content (plaintext from working dir) to stdin.
# Capture it so we can compare and/or encrypt it. The capture ends in a
# trailer ("x" and the number of NUL bytes, see lib.sh), which also
# preserves the trailing newlines that $(...) would otherwise strip.
if ! SGF_CAPTURED="$(sgf_cat_counting_nuls)" || ! sgf_split_counted; then
	echo "ERROR: could not read the content of ${FILENAME} from git — refusing to stage it" >&2
	exit 1
fi
INPUT="${SGF_CONTENT}"

# ── Text files only: refuse content with NUL bytes ────
# A shell variable cannot hold a NUL byte, so INPUT has already lost
# them: encrypting it would store a damaged file with exit status 0, and
# the next checkout would replace the good working copy with it.
# refuse_nul_bytes <what holds them> : say why, and stop
refuse_nul_bytes() {
	echo "ERROR: $1 holds NUL bytes (${SGF_NUL_COUNT}) — refusing to stage it." >&2
	echo "       sops-git-filters handles text files only: a binary file (a keystore, a DER" >&2
	echo "       certificate) or UTF-16 text would be stored damaged. Store a text form" >&2
	echo "       instead (base64 or PEM; UTF-8 for text), or keep the file out of the sops" >&2
	echo "       filter and encrypt it with sops by hand." >&2
	exit 1
}
[[ "${SGF_NUL_COUNT}" == "0" ]] || refuse_nul_bytes "${FILENAME}"

# Git runs clean filters from the top level of the working tree, but
# resolve the root explicitly so this also works when invoked by hand.
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "ERROR: not inside a git repository" >&2
	exit 1
}

# The file as the commands this filter suggests name it (lib.sh): the
# full path in single quotes, so a line can be pasted as it is, from any
# directory of the working tree. PASTE_SPEC is for the git commands: git
# takes their paths as patterns, and "[ab].env" would reach a.env too.
PASTE_PATH="$(sgf_paste_path "${PROJECT_ROOT}/${FILENAME}")"
PASTE_SPEC="$(sgf_paste_pathspec "${PROJECT_ROOT}/${FILENAME}")"

# Run from the copy under .git/ while the checkout holds a newer version?
# Then say that install.sh has to run again (one line, see lib.sh).
sgf_warn_if_outdated "${SCRIPT_DIR}" "${PROJECT_ROOT}"

# ── Guards: fail hard, never pass plaintext through ────
# Exiting non-zero makes git abort the add/commit
# (filter.sops.required=true) instead of storing plaintext.
if ! command -v sops >/dev/null 2>&1; then
	echo "ERROR: sops not found on PATH — refusing to stage ${FILENAME} as plaintext" >&2
	exit 1
fi

if [[ ! -f "${PROJECT_ROOT}/.sops.yaml" ]]; then
	echo "ERROR: .sops.yaml missing — refusing to stage ${FILENAME} as plaintext" >&2
	exit 1
fi

# ── Storage format ────
# SOPS_STORE_FORMAT in .sops-filter.conf at the project root:
#   json   (default): encrypt binary→json  / decrypt json→binary
#   dotenv          : encrypt dotenv→dotenv / decrypt dotenv→dotenv
STORE_FORMAT="$(sgf_store_format "${PROJECT_ROOT}")" || exit 1

case "${STORE_FORMAT}" in
json)
	ENCRYPT_ARGS=(--input-type binary --output-type json)
	DECRYPT_ARGS=(--input-type json --output-type binary)
	;;
dotenv)
	ENCRYPT_ARGS=(--input-type dotenv --output-type dotenv)
	DECRYPT_ARGS=(--input-type dotenv --output-type dotenv)
	;;
esac
OTHER_FORMAT="$(sgf_other_format "${STORE_FORMAT}")"

# ── The version git holds ────
# The INDEX version first (`:0:path`), then HEAD. Why index over HEAD?
# During pre-commit's stash/unstash cycle:
#   1. You stage the file (index has encrypted blob A)
#   2. Pre-commit stashes unstaged changes, clean filter runs again
#   3. Comparing against HEAD (old blob) → plaintext differs →
#      re-encrypt with a new IV
#   4. New-IV blob ≠ stash blob → `git stash pop` sees a conflict
# By comparing against the index we reuse blob A → stash pop is clean.
# Empty when the file is new (in neither).
#
# ":0:path", not ":path": git reads ":2:prod.secret" as stage 2 of
# prod.secret, so a file named "2:prod.secret" was never found in the
# index (its new version looked new at every git status, an edit was
# compared with HEAD's version and re-encrypted each time). Stage 0 is
# the entry of a path outside a merge conflict, the one git status and
# git add compare with. "HEAD:path" has no such reading.
STORED_ID="$(git rev-parse -q --verify ":0:${FILENAME}" 2>/dev/null ||
	git rev-parse -q --verify "HEAD:${FILENAME}" 2>/dev/null || true)"

# ── Input that already is ciphertext ────
# The working copy can hold a SOPS document instead of plaintext: a clone
# made before install.sh ran, or one where install.sh could not decrypt
# (keys or credentials missing). Encrypting that again would nest
# ciphertext in ciphertext.
#
# That copy is the very blob git holds, so it is stored unchanged when its
# bytes are those of the stored version (the one the comparison below
# uses: the index version, else HEAD's): git sees no change, no key is
# needed (no call to sops, which with a KMS key is a request to the key
# service), and install.sh can still decrypt the working copy later.
# Equal to HEAD's version while the index holds another is not enough:
# after rekey.sh, say, the old ciphertext in the working copy would then
# look like an edit that undoes the re-key. The decrypt below finds that
# its plaintext is the same.
#
# Any other SOPS document is not taken on trust (audit A-13). It may have
# been copied from another project, encrypted for keys that nobody listed
# in .sops.yaml holds, or have been forged: its structure is right, but
# only a decrypt checks the MAC. Stored as it is, it went in with exit
# status 0 and stopped the next checkout of every teammate half-way. So
# it must decrypt with your keys, and its plaintext then goes the way of
# any edit below: compared with the stored version (unchanged → the
# stored blob is reused), else encrypted for the recipients .sops.yaml
# names. Its own recipients are not kept: .sops.yaml alone decides who
# can read a secret of this repository (see the next sections).
#
# INPUT_WAS_CIPHERTEXT is set when the input is such a document and it
# decrypts.
INPUT_WAS_CIPHERTEXT=
if sgf_is_sops_doc "${STORE_FORMAT}" "${INPUT}"; then
	# --stdin: no filter runs (that would be this one again).
	input_id="$(printf '%s' "${INPUT}" | git hash-object --stdin 2>/dev/null || true)"
	if [[ -n "${input_id}" && "${input_id}" == "${STORED_ID}" ]]; then
		echo "sops clean filter: ${FILENAME} holds the ciphertext git holds (the working copy was never decrypted) — storing it unchanged" >&2
		printf '%s' "${INPUT}"
		exit 0
	fi
	# The same blob with CRLF line endings: core.autocrlf=true (or eol=crlf)
	# on a path without -text converts what git checks out, and sops never
	# writes a CR into a document. Without its CRs the input is the stored
	# blob, so that blob goes back to git. No sops call here either: sops
	# cannot parse a dotenv document with CRLF, and json would need the key.
	if [[ -n "${STORED_ID}" && "${INPUT}" == *$'\r'* ]]; then
		input_id="$(printf '%s' "${INPUT}" | tr -d '\r' | git hash-object --stdin 2>/dev/null || true)"
		if [[ -n "${input_id}" && "${input_id}" == "${STORED_ID}" ]]; then
			echo "sops clean filter: ${FILENAME} holds the ciphertext git holds, with CRLF line endings (the working copy was never decrypted) — storing the blob git holds" >&2
			git cat-file blob "${STORED_ID}"
			exit 0
		fi
	fi

	echo "sops clean filter: ${FILENAME} is a SOPS document, but not the version git holds — decrypting it to check it" >&2
	# sops' stderr is left alone: if this fails, its message is the reason.
	# (pipefail: the status of the pipeline is that of sops.)
	if ! SGF_CAPTURED=$(printf '%s' "${INPUT}" | sops decrypt \
		"${DECRYPT_ARGS[@]}" \
		--filename-override "${FILENAME}" \
		/dev/stdin | sgf_cat_counting_nuls) || ! sgf_split_counted; then
		echo "ERROR: ${FILENAME} is a SOPS document that does not decrypt with your keys, and not" >&2
		echo "       the version git holds (sops' message is above). Refusing to stage it: nobody" >&2
		echo "       could check it, and it would stop the checkout of everyone who cannot decrypt it." >&2
		echo "       Likely causes:" >&2
		echo "         - it was copied from another project, encrypted for that project's keys" >&2
		echo "         - it was edited or forged by hand: its MAC or a value no longer matches" >&2
		echo "         - your keys or credentials are not available right now:" >&2
		# shellcheck disable=SC2046  # one word per key type
		sgf_credential_hint "             " $(printf '%s' "${INPUT}" | sgf_doc_key_types) >&2
		echo "       To store its content: decrypt it where its keys are (in its own project) and" >&2
		echo "       save the plaintext here in its place; git add encrypts it for .sops.yaml." >&2
		if [[ -n "${STORED_ID}" ]]; then
			# The checkout runs the smudge filter, which decrypts: without
			# the keys it fails and leaves the file deleted. The blob itself
			# (ciphertext, the way install.sh leaves a file it cannot
			# decrypt) needs no key.
			echo "       To get back the version git holds, as ciphertext (no key needed):" >&2
			echo "         git cat-file blob ${STORED_ID} > ${PASTE_PATH}" >&2
			echo "       or decrypted (needs your keys):" >&2
			echo "         rm ${PASTE_PATH} && git checkout -- ${PASTE_SPEC}" >&2
		fi
		# SOPS_FILTER_FORCE_REENCRYPT is no way out here: re-encrypting
		# needs the plaintext, and that needs this decrypt.
		exit 1
	fi
	[[ "${SGF_NUL_COUNT}" == "0" ]] || refuse_nul_bytes "the decrypted content of ${FILENAME}"
	INPUT="${SGF_CONTENT}"
	INPUT_WAS_CIPHERTEXT=1
	echo "sops clean filter: it decrypts with your keys; its content is stored like any edit (recipients from .sops.yaml)." >&2
	echo "  The working copy keeps that ciphertext. For the plaintext there: rm ${PASTE_PATH} && git checkout -- ${PASTE_SPEC}" >&2
elif sgf_is_sops_doc "${OTHER_FORMAT}" "${INPUT}"; then
	echo "ERROR: the working copy of ${FILENAME} is a SOPS document in the ${OTHER_FORMAT} format," >&2
	echo "       but .sops-filter.conf says ${STORE_FORMAT}. Refusing to encrypt ciphertext again." >&2
	echo "       Decrypt the working copy first, then stage it." >&2
	exit 1
fi

# ── dotenv: refuse input the format would store in clear ────
# sops' dotenv parser is line-based and keeps everything left of the
# first "=" as a plaintext key. Lines it would mis-read (the continuation
# lines of a quoted multi-line value, text without "=") are refused here,
# before sops can store them or print them in an error. The message
# names the line number only.
if [[ "${STORE_FORMAT}" == "dotenv" ]]; then
	if ! problem="$(printf '%s' "${INPUT}" | sgf_dotenv_input_problem)"; then
		echo "ERROR: ${FILENAME} cannot be stored in the dotenv format: ${problem}" >&2
		echo "       Allowed: '# comment' lines and KEY=VALUE lines. Refusing to stage it." >&2
		exit 1
	fi
fi

# ── .sops.yaml alone decides the recipients ────
# sops lets these variables replace the keys of the matching creation
# rule. Exported in a shell for some other project, they would encrypt
# this repository's secrets for the wrong recipients, and nobody listed
# in .sops.yaml could decrypt the result. Drop them before encrypting.
for var in SOPS_AGE_RECIPIENTS SOPS_KMS_ARN SOPS_GCP_KMS_IDS SOPS_AZURE_KEYVAULT_URLS \
	SOPS_VAULT_URIS SOPS_PGP_FP SOPS_HUAWEICLOUD_KMS_IDS; do
	if [[ -n "${!var:-}" ]]; then
		echo "sops clean filter: ignoring ${var} from the environment (.sops.yaml decides the recipients)" >&2
		unset "${var}"
	fi
done

# ── Who can read it from now on ────
# A re-encryption takes the keys from the .sops.yaml of today. A change
# there (a recipient added in a merged pull request, say) takes effect
# with the next edit of each secret, and nothing else showed it (audit
# A-15). When the keys differ from those of the version git holds, one
# line names the keys added and removed, from the metadata of the two
# documents (sops stores it in clear: recipients, ARNs, key URLs). No
# call to sops.
# KEYS_BEFORE holds the stored document to compare with, in the format
# KEYS_BEFORE_FORMAT; empty when there is none (a new file, a stored
# version in clear).
KEYS_BEFORE=""
KEYS_BEFORE_FORMAT=""
say_key_change() { # <new document>
	local before after
	[[ -n "${KEYS_BEFORE_FORMAT}" ]] || return 0
	before="$(printf '%s' "${KEYS_BEFORE}" | sgf_doc_keys "${KEYS_BEFORE_FORMAT}" | sort -u)" || return 0
	after="$(printf '%s' "$1" | sgf_doc_keys "${STORE_FORMAT}" | sort -u)" || return 0
	[[ -n "${before}" && -n "${after}" && "${before}" != "${after}" ]] || return 0
	# The lines are "<key group> TAB <type> <name>" (lib.sh). The group is
	# named only when a document has more than one.
	SGF_BEFORE="${before}" SGF_AFTER="${after}" SGF_FILE="${FILENAME}" awk '
	function group(x) { return substr(x, 1, index(x, "\t") - 1) + 0 }
	function shown(x) {
		return substr(x, index(x, "\t") + 1) (groups ? " (key group " group(x) ")" : "")
	}
	BEGIN {
		nb = split(ENVIRON["SGF_BEFORE"], b, "\n")
		na = split(ENVIRON["SGF_AFTER"], a, "\n")
		for (i = 1; i <= nb; i++) { old[b[i]] = 1; if (group(b[i]) > 1) groups = 1 }
		for (i = 1; i <= na; i++) { new[a[i]] = 1; if (group(a[i]) > 1) groups = 1 }
		for (i = 1; i <= na; i++) if (!(a[i] in old)) added = added (added == "" ? "" : ", ") shown(a[i])
		for (i = 1; i <= nb; i++) if (!(b[i] in new)) removed = removed (removed == "" ? "" : ", ") shown(b[i])
		line = "sops clean filter: the keys of " ENVIRON["SGF_FILE"] " change with this version (from .sops.yaml):"
		if (added != "") line = line " added: " added (removed != "" ? ";" : "")
		if (removed != "") line = line " removed: " removed
		print line
	}' >&2
}

# encrypt_input : encrypt INPUT, check the result, print it. The result
# stays in ENCRYPTED, for remember_encryption.
ENCRYPTED=""
encrypt_input() {
	local encrypted why
	# --filename-override tells SOPS which .sops.yaml creation rule to
	# match (stdin has no filename of its own). The result is held back
	# until it has been checked; the trailing x keeps its final newline.
	encrypted="$(printf '%s' "${INPUT}" | sops encrypt \
		"${ENCRYPT_ARGS[@]}" \
		--filename-override "${FILENAME}" \
		/dev/stdin && printf x)" || return 1
	encrypted="${encrypted%x}"

	# ── Never trust the output unseen ────
	# It must be a SOPS document with every value encrypted, and for a
	# non-empty file in json mode the "data" value must be ciphertext.
	if ! is_complete_doc "${encrypted}"; then
		echo "ERROR: sops did not encrypt ${FILENAME} completely — refusing to stage it." >&2
		# What the check found: a line number or a key name, never a value.
		why="$(printf '%s' "${encrypted}" | sgf_doc_problem "${STORE_FORMAT}")"
		[[ -z "${why}" ]] || echo "       Found: ${why}." >&2
		echo "       Likely cause: the matching .sops.yaml rule has encrypted_regex, unencrypted_regex," >&2
		echo "       encrypted_suffix or unencrypted_suffix (this filter needs the whole file encrypted)," >&2
		echo "       or sops is older than ${SGF_MIN_SOPS_VERSION}. Keys ending in _unencrypted are refused too." >&2
		echo "       If a key that sops does not write was found: your sops is newer than this" >&2
		echo "       tool knows. Update sops-git-filters." >&2
		return 1
	fi
	say_key_change "${encrypted}"
	ENCRYPTED="${encrypted}"
	printf '%s' "${encrypted}"
}

# is_complete_doc <document> : a SOPS document in the storage format with
# every value encrypted; for a non-empty file in json mode, "data" must be
# ciphertext too.
is_complete_doc() {
	sgf_is_sops_doc "${STORE_FORMAT}" "$1" &&
		[[ "${STORE_FORMAT}" != "json" || -z "${INPUT}" || "${SGF_DATA_KIND}" == "enc" ]]
}

# ── What a run a moment ago found ────
# Git runs this filter again each time it looks at a secret with
# uncommitted changes (issue #21): `git status`, twice for `git diff`,
# `git add`, `git commit -a`. Each run decrypted the stored version and
# encrypted the edit anew: two calls to the key service, and a new
# ciphertext each time. So a run remembers its answer for some minutes
# (lib.sh: where, how long, and why nothing there can be read without a
# key that never leaves the machine), and a later run that is asked the
# same question gives the same answer without sops:
#
#   question   this plaintext, with this stored version (its object id),
#              this path and storage format, this .sops.yaml (its whole
#              text), these SOPS_* variables, this version of the tool
#   answers    the stored version itself: the content is unchanged. Only
#                written after a decrypt that showed it, so a run never
#                skips a decrypt that never worked (audit A-04: git add
#                can encrypt for a rule that does not list your key, and
#                the next check of the file must say so).
#              a blob this filter encrypted: the content changed, and the
#                encryption of a moment ago is given again. git status
#                does not keep what the filter returns, so the filter
#                writes it into the object store itself (ciphertext, as
#                git add would); before it is given again, it must still
#                be there and pass the same check as a fresh one.
#
# Everything that decides what sops would return is part of the
# question, so an answer given again is one this filter could have given:
# a change to .sops.yaml (a recipient added) is a new question, and the
# next run encrypts for the new recipients. The answer itself is not
# trusted: a blob is checked again, and anything that does not fit is a
# question without an answer.
#
# Not used:
#   - with SOPS_FILTER_CACHE=0;
#   - with SOPS_FILTER_FORCE_REENCRYPT=1, which asks for a new encryption;
#   - with SOPS_CONFIG set, or outside the top of the working tree: sops
#     would read another .sops.yaml than the one in the question.
# Any failure of the cache (see lib.sh) leaves the filter as it was.
CACHE_COMMON_DIR=""
CACHE_SOPS_YAML=""
CACHE_NAME=""
CACHE_CHECK=""
CACHE_ANSWER=""
CACHE_AGE=""

# cache_question : the question, on stdout, for the HMAC. Each field is
# "<length>:<bytes>" and a newline, and the plaintext comes last: no two
# questions are written the same way.
cache_question() {
	local field name
	printf 'sops-git-filters clean filter cache 1\n'
	for field in "${SGF_VERSION}" "${STORE_FORMAT}" "${FILENAME}" "${STORED_ID}" "${CACHE_SOPS_YAML}"; do
		printf '%s:%s\n' "${#field}" "${field}"
	done
	# The SOPS_* variables sops sees (the filter dropped those that name
	# recipients, above). Their values only go into the HMAC.
	for name in ${!SOPS_*}; do
		field="${name}=${!name}"
		printf '%s:%s\n' "${#field}" "${field}"
	done
	printf 'plaintext\n%s' "${INPUT}"
}

# cache_lookup : prints "<name> <check>" and, when an answer is
# remembered, " <object id> <age in seconds>". Prints nothing when the
# cache cannot be used. Runs in a subshell.
cache_lookup() {
	local mac answer
	sgf_cache_open "${CACHE_COMMON_DIR}" || return 1
	mac="$(sgf_hmac_sha256 cache_question)" || return 1
	answer="$(sgf_cache_get "${mac:0:32}" "${mac:32:32}")" || answer=""
	printf '%s %s %s\n' "${mac:0:32}" "${mac:32:32}" "${answer}"
}

# cache_answer <name> <check> [<object id> <age>] : takes cache_lookup apart
cache_answer() {
	CACHE_NAME="${1:-}"
	CACHE_CHECK="${2:-}"
	CACHE_ANSWER="${3:-}"
	CACHE_AGE="${4:-}"
}

# remember <object id> : the answer of this run, for the next one. After
# the output is written, so that nothing here can change it.
remember() {
	[[ -n "${CACHE_NAME}" ]] || return 0
	(
		sgf_cache_open "${CACHE_COMMON_DIR}" &&
			sgf_cache_put "${CACHE_NAME}" "${CACHE_CHECK}" "$1"
	) >/dev/null 2>&1 || true
}

# remember_encryption : the blob encrypt_input returned, written into the
# object store (--stdin: without a filter), and remembered.
remember_encryption() {
	local oid
	[[ -n "${CACHE_NAME}" && -n "${ENCRYPTED}" ]] || return 0
	oid="$(printf '%s' "${ENCRYPTED}" | git hash-object -w --stdin 2>/dev/null)" || return 0
	remember "${oid}"
}

# replay_encryption <what> : print the blob a run a moment ago encrypted
# this content to, if there is one and it passes the check of
# encrypt_input. Never the stored version: that answer means "unchanged",
# and is taken where the comparison is.
replay_encryption() {
	local out header doc
	[[ -n "${CACHE_ANSWER}" && "${CACHE_ANSWER}" != "${STORED_ID}" ]] || return 1
	# One read gives the size and the bytes: "<id> blob <size>", a newline,
	# the content, a newline. The size must be the length of what the
	# variable holds: a NUL byte the shell dropped would make it shorter.
	# GIT_NO_LAZY_FETCH: in a partial clone, a blob that is gone is not
	# asked for from the remote (it never had it).
	out="$(printf '%s\n' "${CACHE_ANSWER}" |
		GIT_NO_LAZY_FETCH=1 git cat-file --batch 2>/dev/null && printf x)" || return 1
	header="${out%%$'\n'*}"
	doc="${out#*$'\n'}"
	doc="${doc%$'\n'x}"
	[[ "${header}" == "${CACHE_ANSWER} blob "* && "${header##* }" == "${#doc}" ]] || return 1
	is_complete_doc "${doc}" || return 1
	echo "sops clean filter: $1, reusing its encryption of ${CACHE_AGE} s ago for ${FILENAME}" >&2
	say_key_change "${doc}"
	printf '%s' "${doc}"
}

if [[ "${SOPS_FILTER_CACHE:-}" != "0" && "${SOPS_FILTER_FORCE_REENCRYPT:-}" != "1" && -z "${SOPS_CONFIG:-}" ]] &&
	[[ . -ef "${PROJECT_ROOT}" && -r "${PROJECT_ROOT}/.sops.yaml" ]] &&
	CACHE_COMMON_DIR="$(git rev-parse --git-common-dir 2>/dev/null)" && [[ -n "${CACHE_COMMON_DIR}" ]] &&
	! IFS= read -r -d '' CACHE_SOPS_YAML <"${PROJECT_ROOT}/.sops.yaml"; then
	# (read stops early, and succeeds, at a NUL byte: no cache for that.)
	# shellcheck disable=SC2046  # hex digits and numbers only
	cache_answer $(cache_lookup 2>/dev/null || true)
fi

# ── New file: no previous version in the index or HEAD ────────
# For new files there is nothing to compare — just encrypt and exit.
if [[ -z "${STORED_ID}" ]]; then
	if replay_encryption "new file"; then
		exit 0
	fi
	echo "sops clean filter: encrypting new file ${FILENAME}" >&2
	encrypt_input
	remember_encryption
	exit 0
fi

# The stored version (index, else HEAD: see "The version git holds").
EXISTING_ENCRYPTED=$( (git cat-file -p "${STORED_ID}" 2>/dev/null || true) && printf x)
EXISTING_ENCRYPTED="${EXISTING_ENCRYPTED%x}"

# ── Asked to re-encrypt no matter what ────
# For a storage-format change, or to get fresh data keys:
#   SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- <files>
# The variable reaches every run of this filter in the git command it is
# set on, and git runs it for each managed file it checks again (one whose
# timestamp changed or cannot be trusted), not only for the file named
# (audit S9). With git add <file> only that file is staged; with
# git commit -a, every file checked again is staged re-encrypted.
if [[ "${SOPS_FILTER_FORCE_REENCRYPT:-}" == "1" ]]; then
	echo "sops clean filter: SOPS_FILTER_FORCE_REENCRYPT=1, re-encrypting ${FILENAME}" >&2
	KEYS_BEFORE="${EXISTING_ENCRYPTED}"
	if sgf_is_sops_doc "${STORE_FORMAT}" "${EXISTING_ENCRYPTED}"; then
		KEYS_BEFORE_FORMAT="${STORE_FORMAT}"
	elif sgf_is_sops_doc "${OTHER_FORMAT}" "${EXISTING_ENCRYPTED}"; then
		KEYS_BEFORE_FORMAT="${OTHER_FORMAT}"
	fi
	encrypt_input
	exit 0
fi

# ── Existing file: compare before re-encrypting ────────

# ── The stored version is not a SOPS document in this format ────
if ! sgf_is_sops_doc "${STORE_FORMAT}" "${EXISTING_ENCRYPTED}"; then
	if sgf_is_sops_doc "${OTHER_FORMAT}" "${EXISTING_ENCRYPTED}"; then
		# Encrypted, in the other storage format. Re-encrypting every file
		# is a deliberate step, not something to start because a config
		# line changed.
		echo "ERROR: git holds ${FILENAME} in the ${OTHER_FORMAT} format, but .sops-filter.conf says ${STORE_FORMAT}." >&2
		echo "       To finish the format change, re-encrypt the SOPS-managed files:" >&2
		echo "         SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- <files>" >&2
		exit 1
	fi
	# Plaintext committed before the filter existed (or by a clone
	# without it). There is nothing to compare with: encrypt.
	if replay_encryption "the stored version is not encrypted"; then
		exit 0
	fi
	echo "sops clean filter: the stored version of ${FILENAME} is not encrypted, encrypting it now" >&2
	encrypt_input
	remember_encryption
	exit 0
fi

# ── Remembered: the answer of a run a moment ago (see above) ────
if [[ -n "${CACHE_ANSWER}" && "${CACHE_ANSWER}" == "${STORED_ID}" ]]; then
	echo "sops clean filter: content unchanged, reusing existing encrypted blob for ${FILENAME} (compared ${CACHE_AGE} s ago)" >&2
	if [[ -n "${INPUT_WAS_CIPHERTEXT}" ]]; then
		echo "  Its recipients are not taken over. To change recipients: edit .sops.yaml, run rekey.sh" >&2
	fi
	printf '%s' "${EXISTING_ENCRYPTED}"
	exit 0
fi
KEYS_BEFORE="${EXISTING_ENCRYPTED}"
KEYS_BEFORE_FORMAT="${STORE_FORMAT}"
if replay_encryption "content changed"; then
	exit 0
fi
KEYS_BEFORE=""
KEYS_BEFORE_FORMAT=""

# ── Decrypt the stored version to compare plaintext with plaintext ────
# sops' stderr is left alone: if this fails, its message is the reason.
# (pipefail: the status of the pipeline is that of sops.)
if ! SGF_CAPTURED=$(printf '%s' "${EXISTING_ENCRYPTED}" | sops decrypt \
	"${DECRYPT_ARGS[@]}" \
	--filename-override "${FILENAME}" \
	/dev/stdin | sgf_cat_counting_nuls) || ! sgf_split_counted; then
	echo "ERROR: cannot decrypt the version of ${FILENAME} that git holds (sops' message is above)." >&2
	echo "       Without it this filter cannot tell whether the file changed, and it does not" >&2
	echo "       re-encrypt blindly. Are your keys or credentials available?" >&2
	# shellcheck disable=SC2046  # one word per key type
	sgf_credential_hint "         " $(printf '%s' "${EXISTING_ENCRYPTED}" | sgf_doc_key_types) >&2
	# Encrypting needs the public keys of the rule only, so git add works
	# for a path whose rule lists none of your keys, and the next check of
	# the file (git commit, git status) fails here (audit A-04).
	echo "       Or are you not one of its recipients? The rule for it in .sops.yaml may not list your key:" >&2
	echo "       you can encrypt for keys you do not hold, not decrypt. Then have a recipient add the" >&2
	echo "       file, or commit what is staged (not with -a):  SOPS_FILTER_FORCE_REENCRYPT=1 git commit" >&2
	echo "       To re-encrypt regardless: SOPS_FILTER_FORCE_REENCRYPT=1 git add -- ${PASTE_SPEC}" >&2
	exit 1
fi
EXISTING_DECRYPTED="${SGF_CONTENT}"

# A stored version with NUL bytes (written by another tool) can never
# equal the input, which has none: the variable only looks the same.
if [[ "${SGF_NUL_COUNT}" == "0" && "${EXISTING_DECRYPTED}" == "${INPUT}" ]]; then
	# Content unchanged — reuse the existing ciphertext verbatim.
	# Same plaintext → same stored blob → no false diff. (This holds for
	# an empty file too: what counts is that the decryption worked.)
	echo "sops clean filter: content unchanged, reusing existing encrypted blob for ${FILENAME}" >&2
	# A copy encrypted for other keys does not bring its recipients along.
	if [[ -n "${INPUT_WAS_CIPHERTEXT}" ]]; then
		echo "  Its recipients are not taken over. To change recipients: edit .sops.yaml, run rekey.sh" >&2
	fi
	printf '%s' "${EXISTING_ENCRYPTED}"
	remember "${STORED_ID}"
else
	# Content actually changed — encrypt the new version.
	echo "sops clean filter: content changed, re-encrypting ${FILENAME}" >&2
	KEYS_BEFORE="${EXISTING_ENCRYPTED}"
	KEYS_BEFORE_FORMAT="${STORE_FORMAT}"
	encrypt_input
	remember_encryption
fi

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
# Capture it so we can compare and/or encrypt it. The trailing "x"
# trick preserves trailing newlines that $(...) would otherwise strip.
INPUT=$(cat && printf x)
INPUT="${INPUT%x}"

# Git runs clean filters from the top level of the working tree, but
# resolve the root explicitly so this also works when invoked by hand.
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "ERROR: not inside a git repository" >&2
	exit 1
}

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

encrypt_input() {
	local encrypted
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
	if ! sgf_is_sops_doc "${STORE_FORMAT}" "${encrypted}" ||
		[[ "${STORE_FORMAT}" == "json" && -n "${INPUT}" && -z "${SGF_DATA_TOKEN}" ]]; then
		echo "ERROR: sops did not encrypt ${FILENAME} completely — refusing to stage it." >&2
		echo "       Likely cause: the matching .sops.yaml rule has encrypted_regex, unencrypted_regex," >&2
		echo "       encrypted_suffix or unencrypted_suffix (this filter needs the whole file encrypted)," >&2
		echo "       or sops is older than ${SGF_MIN_SOPS_VERSION}. Keys ending in _unencrypted are refused too." >&2
		return 1
	fi
	printf '%s' "${encrypted}"
}

# ── New file: no previous version in the index or HEAD ────────
# git cat-file -e checks if the object exists without reading it.
# For new files there is nothing to compare — just encrypt and exit.
if ! git cat-file -e ":${FILENAME}" 2>/dev/null &&
	! git cat-file -e "HEAD:${FILENAME}" 2>/dev/null; then
	echo "sops clean filter: encrypting new file ${FILENAME}" >&2
	encrypt_input
	exit 0
fi

# ── Existing file: compare before re-encrypting ────────

# Compare against the INDEX version first (`:path`), then fall back to
# HEAD. Why index over HEAD? During pre-commit's stash/unstash cycle:
#   1. You stage the file (index has encrypted blob A)
#   2. Pre-commit stashes unstaged changes, clean filter runs again
#   3. Comparing against HEAD (old blob) → plaintext differs →
#      re-encrypt with a new IV
#   4. New-IV blob ≠ stash blob → `git stash pop` sees a conflict
# By comparing against the index we reuse blob A → stash pop is clean.
EXISTING_ENCRYPTED=$( (git cat-file -p ":${FILENAME}" 2>/dev/null ||
	git cat-file -p "HEAD:${FILENAME}" 2>/dev/null ||
	true) && printf x)
EXISTING_ENCRYPTED="${EXISTING_ENCRYPTED%x}"

# Decrypt the stored version so we can compare plaintext-to-plaintext.
# If decryption fails (corrupted, no keys), fall through to re-encrypt.
EXISTING_DECRYPTED=$( (printf '%s' "${EXISTING_ENCRYPTED}" | sops decrypt \
	"${DECRYPT_ARGS[@]}" \
	--filename-override "${FILENAME}" \
	/dev/stdin 2>/dev/null || true) && printf x)
EXISTING_DECRYPTED="${EXISTING_DECRYPTED%x}"

if [[ -n "${EXISTING_DECRYPTED}" && "${EXISTING_DECRYPTED}" == "${INPUT}" ]]; then
	# Content unchanged — reuse the existing ciphertext verbatim.
	# Same plaintext → same stored blob → no false diff.
	echo "sops clean filter: content unchanged, reusing existing encrypted blob for ${FILENAME}" >&2
	printf '%s' "${EXISTING_ENCRYPTED}"
else
	# Content actually changed — encrypt the new version.
	echo "sops clean filter: content changed, re-encrypting ${FILENAME}" >&2
	encrypt_input
fi

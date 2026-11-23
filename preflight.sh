#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Can sops decrypt right now? Ask BEFORE git needs it.            ║
# ║                                                                  ║
# ║  Git removes a SOPS-managed file from the working tree before it ║
# ║  runs the smudge filter. When sops cannot decrypt at that moment ║
# ║  (an expired cloud session, a key that is not on this machine),  ║
# ║  a pull, checkout or rebase stops half-way: the secret is gone   ║
# ║  from the working tree, some files are already written, and the  ║
# ║  plain retry fails. See "When decryption fails half-way" in the  ║
# ║  README for the way back.                                        ║
# ║                                                                  ║
# ║  This script finds that out first. It decrypts stored blobs to   ║
# ║  /dev/null: one for every set of keys the tracked SOPS-managed   ║
# ║  files name (with one .sops.yaml rule for all files that is a    ║
# ║  single decryption, one call to the key service). A "set" is the ║
# ║  whole access rule of a file: its key groups, the keys in each   ║
# ║  and the threshold. Nothing is written, and no plaintext is      ║
# ║  printed.                                                        ║
# ║                                                                  ║
# ║    ./utilities/sops-git-filters/preflight.sh && git pull         ║
# ║                                                                  ║
# ║  What it cannot know: commits you have not fetched yet may name  ║
# ║  other keys than the files you have now.                         ║
# ║                                                                  ║
# ║  Usage:                                                          ║
# ║    preflight.sh [--quiet]                                        ║
# ║                                                                  ║
# ║    --quiet   print nothing when decryption works                 ║
# ║                                                                  ║
# ║  Exit status:                                                    ║
# ║    0  decryption works (or no SOPS-managed file is tracked)      ║
# ║    1  sops could not decrypt: do not pull, check out or rebase   ║
# ║    2  the check could not run or is incomplete (not a            ║
# ║       repository, sops missing, the index or a blob unreadable)  ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	echo "preflight: lib.sh is missing next to preflight.sh (${SCRIPT_DIR})." >&2
	exit 2
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

QUIET=0
while [[ $# -gt 0 ]]; do
	case "$1" in
	--quiet | -q)
		QUIET=1
		shift
		;;
	--help | -h)
		echo "Usage: preflight.sh [--quiet]"
		exit 0
		;;
	*)
		echo "preflight: unknown argument: $1" >&2
		echo "Usage: preflight.sh [--quiet]" >&2
		exit 2
		;;
	esac
done

TARGET_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "preflight: not inside a git repository." >&2
	exit 2
}
if ! command -v sops >/dev/null 2>&1; then
	echo "preflight: sops not found on PATH." >&2
	exit 2
fi
STORE_FORMAT="$(sgf_store_format "${TARGET_ROOT}")" || exit 2

case "${STORE_FORMAT}" in
json) DECRYPT_ARGS=(--input-type json --output-type binary) ;;
dotenv) DECRYPT_ARGS=(--input-type dotenv --output-type dotenv) ;;
esac

# access_of <format>   (SOPS document on stdin)
# Prints everything in the metadata of a document that decides who can
# decrypt it: the key groups in their order, the keys in each of them and
# the threshold. That is the metadata without the fields that differ from
# file to file by nature (the encrypted data key, the time stamps, the
# MAC) and without the version of sops that wrote the file, which says
# nothing about who can read it. Two documents with the same output need
# the same keys, so one
# decryption answers for both. Group boundaries count: recipients A and B
# in one group (either key will do) are not the same as A and B in two
# groups (both are needed).
#
# Only metadata that sops stores in clear is read. Returns 1 when the
# document does not have the layout sops writes (one field per line): the
# caller then checks that file on its own.
access_of() {
	case "$1" in
	json)
		awk '
		/^[ \t]*"(enc|created_at|lastmodified)"[ \t]*:/ { next }
		# The version of sops, X.Y.Z. Not the "version" of an Azure key,
		# which belongs to the name of the key.
		/^[ \t]*"version"[ \t]*:[ \t]*"[0-9]+\.[0-9]+\.[0-9]+"/ { next }
		/^[ \t]*"(data|mac)"[ \t]*:/ { own_line++; next }
		{ sub(/\r$/, ""); print }
		END { if (own_line != 2) exit 1 }
		'
		;;
	dotenv)
		awk '
		/^sops_/ {
			key = $0
			sub(/=.*/, "", key)
			if (key == "sops_mac") { mac++; next }
			if (key == "sops_lastmodified" || key == "sops_version" || key ~ /__map_(enc|created_at)$/) next
			sub(/\r$/, "")
			print
		}
		END { if (mac != 1) exit 1 }
		'
		;;
	esac
}

# ── Can the files be listed at all? ────
# The loop below reads this list through a process substitution, whose
# exit status is lost. A list that is cut short (an index that cannot be
# read) must not look like "nothing to check": ask once here, where the
# status counts.
if ! git -C "${TARGET_ROOT}" ls-files -z | git -C "${TARGET_ROOT}" check-attr --stdin -z filter >/dev/null; then
	echo "preflight: cannot list the tracked files and their attributes (git's message is above)." >&2
	exit 2
fi

# ── Walk the tracked SOPS-managed files ────
# One decryption per distinct answer of access_of. Blobs that are not
# SOPS documents in this repository's storage format are not checked:
# they are install.sh's and the guard's business, and nothing can decrypt
# them. A blob that cannot be read at all makes the check incomplete.
checked=0
failed=0
unreadable=0
not_documents=0
seen_sets=""

while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
	[[ "${attr}" == "filter" && "${value}" == "sops" ]] || continue

	# "<mode> <object id>" of the index entry. GIT_LITERAL_PATHSPECS: the
	# path is a file name here, not a pattern.
	entry=$(GIT_LITERAL_PATHSPECS=1 git -C "${TARGET_ROOT}" ls-files -s -- "${path}" | awk 'NR == 1 {print $1, $2}') || entry=""
	mode="${entry%% *}"
	sha="${entry#* }"
	if [[ -z "${sha}" ]]; then
		echo "preflight: cannot read the index entry of ${path}." >&2
		unreadable=$((unreadable + 1))
		continue
	fi
	# A symlink or a submodule: git never runs a filter on these.
	[[ "${mode}" != "120000" && "${mode}" != "160000" ]] || continue

	doc_status=0
	sgf_blob_is_sops_doc "${STORE_FORMAT}" "${sha}" "${TARGET_ROOT}" || doc_status=$?
	case "${doc_status}" in
	0) ;;
	1)
		not_documents=$((not_documents + 1))
		continue
		;;
	*)
		echo "preflight: cannot read the stored version of ${path}." >&2
		unreadable=$((unreadable + 1))
		continue
		;;
	esac

	# The same access as a file that was checked already? Compared by a
	# hash of what access_of prints. A layout it does not know gets an id
	# of its own, so that file is decrypted in any case.
	if ! set_id="$(git -C "${TARGET_ROOT}" cat-file blob "${sha}" | access_of "${STORE_FORMAT}" | git hash-object --stdin)"; then
		set_id="blob-${sha}"
	fi
	case "${seen_sets}" in
	*"|${set_id}|"*) continue ;;
	esac
	seen_sets="${seen_sets}|${set_id}|"

	checked=$((checked + 1))
	# sops' own message is the reason, so its stderr is left alone.
	if git -C "${TARGET_ROOT}" cat-file blob "${sha}" |
		sops decrypt "${DECRYPT_ARGS[@]}" --filename-override "${path}" /dev/stdin >/dev/null; then
		continue
	fi
	failed=$((failed + 1))
	{
		echo "preflight: sops cannot decrypt ${path} (its message is above)."
		echo "  Are your keys or credentials available?"
		# shellcheck disable=SC2046  # one word per key type
		sgf_credential_hint "    " $(git -C "${TARGET_ROOT}" cat-file blob "${sha}" | sgf_doc_key_types)
	} >&2
done < <(git -C "${TARGET_ROOT}" ls-files -z | git -C "${TARGET_ROOT}" check-attr --stdin -z filter)

if [[ "${failed}" -ne 0 ]]; then
	{
		echo "preflight: do NOT pull, check out, merge or rebase now. Git would stop half-way"
		echo "  and remove the working copy of the secret. Fix the access first and run this again."
	} >&2
	exit 1
fi

# Not a failed decryption, but not an answer either.
if [[ "${unreadable}" -ne 0 ]]; then
	echo "preflight: the check is incomplete: ${unreadable} file(s) could not be read from git (see above)." >&2
	exit 2
fi

if [[ "${QUIET}" -eq 0 ]]; then
	if [[ "${checked}" -eq 0 ]]; then
		echo "preflight: no encrypted SOPS-managed file is tracked here; nothing to check."
	else
		echo "preflight: decryption works (${checked} set(s) of keys checked)."
	fi
	if [[ "${not_documents}" -ne 0 ]]; then
		echo "preflight: ${not_documents} SOPS-managed file(s) are not encrypted SOPS documents in the ${STORE_FORMAT} format and were not checked; run install.sh for the list."
	fi
fi

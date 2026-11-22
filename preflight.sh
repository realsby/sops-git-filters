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
# ║  single decryption, one call to the key service). Nothing is     ║
# ║  written, and no plaintext is printed.                           ║
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
# ║    2  the check could not run (not a repository, sops missing)   ║
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

# key_set   (SOPS document on stdin)
# The keys a document names, on one line: recipients, key ids and the
# like, sorted. Two files with the same line are decrypted with the same
# keys, so checking one of them is enough. Only metadata that sops stores
# in clear is read.
key_set() {
	awk '
	/"(recipient|arn|resource_id|vault_url|vault_address|key_name|name|fp|key_id)"[ \t]*:/ {
		line = $0
		gsub(/^[ \t]+|[ \t,]+$/, "", line)
		print line
	}
	/^sops_.*__map_(recipient|arn|resource_id|vault_url|vault_address|key_name|name|fp|key_id)=/ {
		line = $0
		sub(/^sops_.*__map_/, "", line)
		print line
	}
	' | sort -u | tr '\n' ' '
}

# ── Walk the tracked SOPS-managed files ────
# One decryption per distinct set of keys. Blobs that are not SOPS
# documents in this repository's storage format are skipped: they are
# install.sh's and the guard's business, and nothing can decrypt them.
checked=0
failed=0
seen_sets=""

while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
	[[ "${attr}" == "filter" && "${value}" == "sops" ]] || continue

	# "<mode> <object id>" of the index entry. GIT_LITERAL_PATHSPECS: the
	# path is a file name here, not a pattern.
	entry=$(GIT_LITERAL_PATHSPECS=1 git -C "${TARGET_ROOT}" ls-files -s -- "${path}" | awk 'NR == 1 {print $1, $2}')
	mode="${entry%% *}"
	sha="${entry#* }"
	[[ -n "${sha}" ]] || continue
	# A symlink or a submodule: git never runs a filter on these.
	[[ "${mode}" != "120000" && "${mode}" != "160000" ]] || continue
	sgf_blob_is_sops_doc "${STORE_FORMAT}" "${sha}" "${TARGET_ROOT}" || continue

	set_of_keys="$(git -C "${TARGET_ROOT}" cat-file blob "${sha}" | key_set)"
	case "${seen_sets}" in
	*"|${set_of_keys}|"*) continue ;;
	esac
	seen_sets="${seen_sets}|${set_of_keys}|"

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

if [[ "${QUIET}" -eq 0 ]]; then
	if [[ "${checked}" -eq 0 ]]; then
		echo "preflight: no encrypted SOPS-managed file is tracked here; nothing to check."
	else
		echo "preflight: decryption works (${checked} set(s) of keys checked)."
	fi
fi

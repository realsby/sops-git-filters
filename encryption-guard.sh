#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Encryption Guard (pre-commit hook)                         ║
# ║                                                                  ║
# ║  Second line of defense behind the clean filter: blocks a        ║
# ║  commit while any file managed by the "sops" git filter is       ║
# ║  tracked in plaintext. Catches the cases the filter can't: a     ║
# ║  clone where the filters were never configured, a bypassed       ║
# ║  filter, or an index entry written before the filter existed.    ║
# ║                                                                  ║
# ║  What is checked: EVERY entry in the index whose filter          ║
# ║  attribute is "sops", not only the paths staged for this         ║
# ║  commit. A secret that was committed in plaintext long ago is    ║
# ║  reported until it is fixed.                                     ║
# ║                                                                  ║
# ║  How: each blob is read by object id and must be a completely    ║
# ║  encrypted SOPS document in the repository's storage format      ║
# ║  (lib.sh). A search for the string ENC[AES256_GCM is not         ║
# ║  enough: a plaintext file can mention it, a dotenv file can      ║
# ║  have one encrypted value next to plaintext ones, and a SOPS     ║
# ║  envelope can carry plaintext (its MAC is always ENC[...]).      ║
# ║                                                                  ║
# ║  The guard fails closed: if it cannot list the index, read the   ║
# ║  attributes or read a blob, the commit is blocked.               ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

# This script may be reached through a symlink
# (.git/hooks/pre-commit -> ../../utilities/sops-git-filters/encryption-guard.sh).
# Follow it, so lib.sh is found next to the real file.
SELF="${BASH_SOURCE[0]}"
while [[ -L "${SELF}" ]]; do
	SELF_DIR="$(cd -P "$(dirname "${SELF}")" && pwd)"
	SELF="$(readlink "${SELF}")"
	[[ "${SELF}" == /* ]] || SELF="${SELF_DIR}/${SELF}"
done
SCRIPT_DIR="$(cd -P "$(dirname "${SELF}")" && pwd)"

blocked() { # <headline> : print the banner; details follow from the caller
	echo "========================================================" >&2
	echo " COMMIT BLOCKED: $1" >&2
	echo "========================================================" >&2
	echo "" >&2
}

if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	blocked "the encryption guard is incomplete"
	echo " lib.sh is missing next to encryption-guard.sh (${SCRIPT_DIR})." >&2
	echo " Update or re-copy sops-git-filters." >&2
	exit 1
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
STORE_FORMAT="$(sgf_store_format "${PROJECT_ROOT}")" || exit 1
OTHER_FORMAT="$(sgf_other_format "${STORE_FORMAT}")"

# ── Check the entries ────────────────────────────────────────────
# check_entries reads the answer of `git check-attr -z` on stdin:
# <path> NUL <attribute> NUL <value> NUL, one triple per index entry and
# in the same order as the arrays filled by check_index. Exit status:
#   0 every SOPS-managed blob is an encrypted SOPS document
#   1 at least one is not (already reported)
#   2 the check itself could not be completed
check_entries() {
	local i=0 path attr value status managed=0
	local unencrypted="" unreadable="" other_format=""

	while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
		if [[ "${path}" != "${INDEX_PATHS[i]:-}" ]]; then
			echo "encryption-guard: git check-attr answered out of order — cannot verify the index" >&2
			return 2
		fi
		if [[ "${attr}" == "filter" && "${value}" == "sops" ]]; then
			case "${INDEX_MODES[i]}" in
			120000 | 160000)
				# A symlink or a submodule: git never runs a filter on these.
				;;
			*)
				managed=$((managed + 1))
				status=0
				sgf_blob_is_sops_doc "${STORE_FORMAT}" "${INDEX_OIDS[i]}" || status=$?
				case "${status}" in
				0) ;;
				2) unreadable="${unreadable}   - ${path}"$'\n' ;;
				*)
					# Encrypted, but in the format .sops-filter.conf does not
					# name: a storage-format change that is not finished.
					if sgf_blob_is_sops_doc "${OTHER_FORMAT}" "${INDEX_OIDS[i]}"; then
						other_format="${other_format}   - ${path}"$'\n'
					else
						unencrypted="${unencrypted}   - ${path}"$'\n'
					fi
					;;
				esac
				;;
			esac
		fi
		i=$((i + 1))
	done

	if [[ "${i}" -ne "${#INDEX_PATHS[@]}" ]]; then
		echo "encryption-guard: git check-attr answered for ${i} of ${#INDEX_PATHS[@]} index entries — cannot verify the index" >&2
		return 2
	fi

	if [[ -n "${unreadable}" ]]; then
		blocked "cannot read SOPS-managed files from the index"
		printf '%s' "${unreadable}" >&2
		return 2
	fi

	if [[ -n "${unencrypted}" ]]; then
		blocked "SOPS-managed files are not encrypted"
		echo " These files have filter=sops in .gitattributes, but the version" >&2
		echo " in the index is not a completely encrypted SOPS document" >&2
		echo " (expected format: ${STORE_FORMAT}):" >&2
		echo "" >&2
		printf '%s' "${unencrypted}" >&2
		echo "" >&2
		echo " To fix:" >&2
		echo "   1. Configure the filters: run install.sh from this tool's directory." >&2
		echo "   2. Re-stage through the filter:  git add --renormalize -- <file>" >&2
		echo "   3. A file that was already committed like this is in history:" >&2
		echo "      rotate that secret." >&2
		echo "========================================================" >&2
		return 1
	fi

	if [[ -n "${other_format}" ]]; then
		blocked "SOPS-managed files are stored in the other format"
		echo " .sops-filter.conf says ${STORE_FORMAT}, but the index holds these files" >&2
		echo " as ${OTHER_FORMAT} (encrypted, in the other format):" >&2
		echo "" >&2
		printf '%s' "${other_format}" >&2
		echo "" >&2
		echo " To finish the format change, re-run install.sh, then re-encrypt:" >&2
		echo "   SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- <files>" >&2
		echo "========================================================" >&2
		return 1
	fi

	# SOPS-managed files are tracked — encryption must be possible at all.
	if [[ "${managed}" -gt 0 && ! -f "${PROJECT_ROOT}/.sops.yaml" ]]; then
		blocked "SOPS not configured"
		echo " ${managed} tracked file(s) require SOPS encryption but" >&2
		echo " .sops.yaml is missing." >&2
		echo "" >&2
		echo " To fix:" >&2
		echo "   1. Create .sops.yaml with your encryption keys" >&2
		echo "   2. Run install.sh to configure the git filters" >&2
		echo "========================================================" >&2
		return 1
	fi
	return 0
}

# check_index reads `git ls-files -s -z` on stdin:
# "<mode> <object id> <stage>" TAB <path> NUL per entry. Blobs are later
# read by object id, so no path is ever turned into a revision (a file
# named like "2:prod.secret" would otherwise be read as index stage 2),
# and unusual file names need no quoting.
INDEX_MODES=()
INDEX_OIDS=()
INDEX_PATHS=()
check_index() {
	local record meta mode oid n=0
	while IFS= read -r -d '' record; do
		meta="${record%%$'\t'*}"
		mode="${meta%% *}"
		oid="${meta#* }"
		oid="${oid%% *}"
		INDEX_MODES[n]="${mode}"
		INDEX_OIDS[n]="${oid}"
		INDEX_PATHS[n]="${record#*$'\t'}"
		n=$((n + 1))
	done
	[[ "${n}" -gt 0 ]] || return 0

	# pipefail: a failing check-attr fails this pipeline even when
	# check_entries saw nothing wrong in the part it received.
	printf '%s\0' "${INDEX_PATHS[@]}" |
		git check-attr --stdin -z filter |
		check_entries
}

# `|| status=$?` keeps errexit from ending the script before the
# message below. With pipefail, a failing `git ls-files` fails the
# pipeline too.
status=0
git ls-files -s -z | check_index || status=$?

case "${status}" in
0) exit 0 ;;
1) exit 1 ;;
*)
	blocked "the encryption guard could not finish its check"
	echo " The index could not be listed, or its attributes or blobs could" >&2
	echo " not be read (see above). Nothing was verified, so nothing is let through." >&2
	exit 1
	;;
esac

#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Re-key SOPS-managed files after .sops.yaml changed              ║
# ║                                                                  ║
# ║  You added or removed a recipient in .sops.yaml (a teammate's    ║
# ║  age key, a KMS key, the break-glass key). The files already in  ║
# ║  git are still encrypted for the OLD recipients, and the clean   ║
# ║  filter keeps it that way: it reuses the stored blob whenever    ║
# ║  the plaintext is unchanged, so touching and re-adding a file    ║
# ║  changes nothing.                                                ║
# ║                                                                  ║
# ║  This script runs `sops updatekeys` on the stored blobs and      ║
# ║  stages the result:                                              ║
# ║                                                                  ║
# ║    1. copy each SOPS-managed blob from the index into a private  ║
# ║       directory under .git/ (ciphertext only, never plaintext)   ║
# ║    2. `sops updatekeys` rewrites its key list to match the       ║
# ║       creation rule in .sops.yaml                                ║
# ║    3. `git update-index` stages the re-keyed blob                ║
# ║                                                                  ║
# ║  The working tree is not touched. Review with                    ║
# ║  `git diff --cached --stat`, then commit.                        ║
# ║                                                                  ║
# ║  Needs decryption access (sops must read the data key with one   ║
# ║  of the current recipients).                                     ║
# ║                                                                  ║
# ║  REMOVING a recipient: updatekeys keeps the data key, and        ║
# ║  history keeps the old blobs. Whoever was removed could read     ║
# ║  everything until now. Rotate the secret VALUES; after editing   ║
# ║  them the clean filter encrypts with a fresh data key anyway.    ║
# ║                                                                  ║
# ║  Usage:                                                          ║
# ║    rekey.sh [--dry-run] [--] [<path>...]                         ║
# ║                                                                  ║
# ║    --dry-run   show which files would change, stage nothing      ║
# ║    <path>      limit to these files (default: every tracked      ║
# ║                file with filter=sops)                            ║
# ║                                                                  ║
# ║  Exit status: 0 done (or nothing to do), 1 at least one file     ║
# ║  could not be re-keyed.                                          ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	echo "Error: lib.sh is missing next to rekey.sh (${SCRIPT_DIR})." >&2
	exit 1
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

DRY_RUN=0
LIMIT=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run | -n)
		DRY_RUN=1
		shift
		;;
	--help | -h)
		echo "Usage: rekey.sh [--dry-run] [--] [<path>...]"
		exit 0
		;;
	--)
		shift
		while [[ $# -gt 0 ]]; do
			LIMIT[${#LIMIT[@]}]="$1"
			shift
		done
		;;
	-*)
		echo "Error: unknown option $1" >&2
		exit 1
		;;
	*)
		LIMIT[${#LIMIT[@]}]="$1"
		shift
		;;
	esac
done

PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "Error: not inside a git repository." >&2
	exit 1
}
# Paths given on the command line are relative to where the caller stands.
CALLER_PREFIX="$(git rev-parse --show-prefix)"
cd "${PROJECT_ROOT}"

if ! command -v sops >/dev/null 2>&1; then
	echo "Error: sops not found on PATH." >&2
	exit 1
fi
if [[ ! -f .sops.yaml ]]; then
	echo "Error: .sops.yaml missing in ${PROJECT_ROOT}." >&2
	exit 1
fi
STORE_FORMAT="$(sgf_store_format "${PROJECT_ROOT}")" || exit 1

# ── A private place for the ciphertext copies ────
# Under .git, with .sops.yaml copied next to them: sops matches a
# creation rule's path_regex against the path relative to the config
# file, so the copies must sit at the same relative paths as the real
# files.
GIT_DIR_ABS="$(git rev-parse --absolute-git-dir)"
WORK="$(mktemp -d "${GIT_DIR_ABS}/sops-rekey.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
trap 'exit 1' HUP INT TERM
cp .sops.yaml "${WORK}/.sops.yaml"

rekeyed=0
unchanged=0
failed=0

# rekey_entries: stdin is the answer of `git check-attr -z filter` for
# the index entries collected by rekey_index, in the same order.
rekey_entries() {
	local i=0 path attr value copy new_oid output
	while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
		if [[ "${path}" != "${INDEX_PATHS[i]:-}" ]]; then
			echo "Error: git check-attr answered out of order." >&2
			return 2
		fi
		if [[ "${attr}" == "filter" && "${value}" == "sops" ]]; then
			case "${INDEX_MODES[i]}:${INDEX_STAGES[i]}" in
			120000:* | 160000:*) ;; # symlink or submodule: never filtered
			*:0)
				copy="${WORK}/${path}"
				mkdir -p "$(dirname "${copy}")"
				git cat-file blob "${INDEX_OIDS[i]}" >"${copy}"
				if ! sgf_blob_is_sops_doc "${STORE_FORMAT}" "${INDEX_OIDS[i]}"; then
					echo "FAILED  ${path}: the stored version is not a SOPS document in the ${STORE_FORMAT} format (run install.sh for details)" >&2
					failed=$((failed + 1))
				elif ! output="$(sops --config "${WORK}/.sops.yaml" updatekeys --yes --input-type "${STORE_FORMAT}" "${copy}" 2>&1)"; then
					echo "FAILED  ${path}: sops updatekeys said:" >&2
					printf '%s\n' "${output}" | sed 's/^/          /' >&2
					failed=$((failed + 1))
				else
					new_oid="$(git hash-object --no-filters -- "${copy}")"
					if [[ "${new_oid}" == "${INDEX_OIDS[i]}" ]]; then
						unchanged=$((unchanged + 1))
					elif ! sgf_is_sops_doc "${STORE_FORMAT}" "$(cat "${copy}")"; then
						echo "FAILED  ${path}: sops updatekeys returned something that is not a SOPS document" >&2
						failed=$((failed + 1))
					elif [[ "${DRY_RUN}" -eq 1 ]]; then
						echo "would re-key  ${path}"
						rekeyed=$((rekeyed + 1))
					else
						git hash-object -w --no-filters -- "${copy}" >/dev/null
						git update-index --cacheinfo "${INDEX_MODES[i]}" "${new_oid}" "${path}"
						echo "re-keyed  ${path}"
						rekeyed=$((rekeyed + 1))
					fi
				fi
				;;
			*)
				echo "FAILED  ${path}: unmerged (conflict in progress); resolve it first" >&2
				failed=$((failed + 1))
				;;
			esac
		fi
		i=$((i + 1))
	done
	if [[ "${i}" -ne "${#INDEX_PATHS[@]}" ]]; then
		echo "Error: git check-attr answered for ${i} of ${#INDEX_PATHS[@]} index entries." >&2
		return 2
	fi

	echo
	if [[ "${DRY_RUN}" -eq 1 ]]; then
		echo "Dry run: ${rekeyed} file(s) would be re-keyed, ${unchanged} already match .sops.yaml, ${failed} failed."
	else
		echo "${rekeyed} file(s) re-keyed and staged, ${unchanged} already match .sops.yaml, ${failed} failed."
		if [[ "${rekeyed}" -gt 0 ]]; then
			echo "Review with: git diff --cached --stat    then commit."
		fi
	fi
	[[ "${failed}" -eq 0 ]]
}

# rekey_index: stdin is `git ls-files -s -z`:
# "<mode> <object id> <stage>" TAB <path> NUL per entry.
INDEX_MODES=()
INDEX_OIDS=()
INDEX_STAGES=()
INDEX_PATHS=()
rekey_index() {
	local record meta rest n=0
	while IFS= read -r -d '' record; do
		meta="${record%%$'\t'*}"
		INDEX_MODES[n]="${meta%% *}"
		rest="${meta#* }"
		INDEX_OIDS[n]="${rest%% *}"
		INDEX_STAGES[n]="${rest#* }"
		INDEX_PATHS[n]="${record#*$'\t'}"
		n=$((n + 1))
	done
	if [[ "${n}" -eq 0 ]]; then
		echo "No tracked files match."
		return 0
	fi
	printf '%s\0' "${INDEX_PATHS[@]}" |
		git check-attr --stdin -z filter |
		rekey_entries
}

status=0
if [[ ${#LIMIT[@]} -gt 0 ]]; then
	# Turn the caller's paths into paths from the repository root.
	ROOTED=()
	for item in "${LIMIT[@]}"; do
		case "${item}" in
		/*) ROOTED[${#ROOTED[@]}]="${item}" ;;
		*) ROOTED[${#ROOTED[@]}]="${CALLER_PREFIX}${item}" ;;
		esac
	done
	git ls-files -s -z -- "${ROOTED[@]}" | rekey_index || status=$?
else
	git ls-files -s -z | rekey_index || status=$?
fi

[[ "${status}" -eq 0 ]] || exit 1

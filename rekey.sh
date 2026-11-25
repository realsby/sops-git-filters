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
# ║                file with filter=sops in the .gitattributes       ║
# ║                files of the index)                               ║
# ║                                                                  ║
# ║  Exit status: 0 done (or nothing to do), 1 at least one file     ║
# ║  could not be re-keyed.                                          ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# rekey_entry <mode> <object id> <stage> <path> : one SOPS-managed index
# entry. It runs with errexit off (see below), so every command that
# writes is checked by hand: a file counts as re-keyed only when git
# really took the new version.
rekey_entry() {
	local mode="$1" oid="$2" stage="$3" path="$4" copy new_oid output
	case "${mode}:${stage}" in
	120000:* | 160000:*) ;; # symlink or submodule: never filtered
	*:0)
		copy="${WORK}/${path}"
		if ! mkdir -p "$(dirname "${copy}")" ||
			! git cat-file blob "${oid}" >"${copy}"; then
			echo "FAILED  ${path}: could not copy the stored version (see the message above)" >&2
			failed=$((failed + 1))
		elif ! sgf_blob_is_sops_doc "${STORE_FORMAT}" "${oid}"; then
			echo "FAILED  ${path}: the stored version is not a SOPS document in the ${STORE_FORMAT} format (run install.sh for details)" >&2
			failed=$((failed + 1))
		elif ! output="$(sops --config "${WORK}/.sops.yaml" updatekeys --yes --input-type "${STORE_FORMAT}" "${copy}" 2>&1)"; then
			echo "FAILED  ${path}: sops updatekeys said:" >&2
			printf '%s\n' "${output}" | sed 's/^/          /' >&2
			failed=$((failed + 1))
		elif ! new_oid="$(git hash-object --no-filters -- "${copy}")"; then
			echo "FAILED  ${path}: could not read what sops updatekeys wrote (see the message above)" >&2
			failed=$((failed + 1))
		elif [[ "${new_oid}" == "${oid}" ]]; then
			unchanged=$((unchanged + 1))
		elif ! sgf_is_sops_doc "${STORE_FORMAT}" "$(cat "${copy}")"; then
			echo "FAILED  ${path}: sops updatekeys returned something that is not a SOPS document" >&2
			failed=$((failed + 1))
		elif [[ "${DRY_RUN}" -eq 1 ]]; then
			echo "would re-key  ${path}"
			rekeyed=$((rekeyed + 1))
		elif git hash-object -w --no-filters -- "${copy}" >/dev/null &&
			git update-index --cacheinfo "${mode}" "${new_oid}" "${path}"; then
			echo "re-keyed  ${path}"
			rekeyed=$((rekeyed + 1))
		else
			echo "FAILED  ${path}: git could not stage the re-keyed version (see the message above); the index still holds the old one" >&2
			failed=$((failed + 1))
		fi
		;;
	*)
		echo "FAILED  ${path}: unmerged (conflict in progress); resolve it first" >&2
		failed=$((failed + 1))
		;;
	esac
}

# ── Which files ────
# The SOPS-managed entries of the index, as the guard finds them
# (lib.sh): one `git ls-files` and one `git check-attr --cached` joined
# in awk, so only those entries reach bash. A bash loop over every
# tracked path took 19 seconds with 60,000 of them (audit A-01).
# --cached: the attributes of the .gitattributes files in the index.
# rekey.sh stages its result, and the commit that follows carries those,
# not an edit of .gitattributes that is not staged; the guard reads them
# the same way (audit A-11). Paths given on the command line limit the
# list, as pathspecs from where the caller stands.
#
# The whole list is read before anything is re-keyed: when git cannot
# list the index or answers out of order, nothing is staged.
SPEC=()
for item in ${LIMIT[@]+"${LIMIT[@]}"}; do
	if sgf_is_absolute "${item}"; then
		SPEC[${#SPEC[@]}]="${item}"
	else
		SPEC[${#SPEC[@]}]="${CALLER_PREFIX}${item}"
	fi
done
if ! LISTING="$(sgf_managed_entries "${PROJECT_ROOT}" rekey.sh "nothing was re-keyed" ${SPEC[@]+"${SPEC[@]}"})"; then
	echo "Error: could not list the SOPS-managed files of the index (see above). Nothing was re-keyed." >&2
	exit 1
fi

ENTRY_MODES=()
ENTRY_OIDS=()
ENTRY_STAGES=()
ENTRY_PATHS=()
while IFS= read -r line; do
	[[ -n "${line}" ]] || continue
	if ! sgf_unquote_path "${line#*$'\t'}"; then
		echo "Error: cannot read the name git printed for an index entry. Nothing was re-keyed." >&2
		exit 1
	fi
	meta="${line%%$'\t'*}"
	n="${#ENTRY_PATHS[@]}"
	ENTRY_PATHS[n]="${REPLY}"
	ENTRY_MODES[n]="${meta%% *}"
	meta="${meta#* }"
	ENTRY_OIDS[n]="${meta%% *}"
	ENTRY_STAGES[n]="${meta#* }"
done <<<"${LISTING}"

# Nothing managed: say whether the paths match anything at all.
if [[ "${#ENTRY_PATHS[@]}" -eq 0 && -z "$(git ls-files -- ${SPEC[@]+"${SPEC[@]}"})" ]]; then
	echo "No tracked files match."
	exit 0
fi

# `|| true`: errexit stays off inside rekey_entry. A command that fails
# there is reported and counted, and the next file is still tried.
for ((i = 0; i < ${#ENTRY_PATHS[@]}; i++)); do
	rekey_entry "${ENTRY_MODES[i]}" "${ENTRY_OIDS[i]}" "${ENTRY_STAGES[i]}" "${ENTRY_PATHS[i]}" || true
done

echo
if [[ "${DRY_RUN}" -eq 1 ]]; then
	echo "Dry run: ${rekeyed} file(s) would be re-keyed, ${unchanged} already match .sops.yaml, ${failed} failed."
else
	echo "${rekeyed} file(s) re-keyed and staged, ${unchanged} already match .sops.yaml, ${failed} failed."
	if [[ "${rekeyed}" -gt 0 ]]; then
		echo "Review with: git diff --cached --stat    then commit."
	fi
fi
[[ "${failed}" -eq 0 ]] || exit 1

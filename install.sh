#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Git Filter Setup                                           ║
# ║                                                                  ║
# ║  Configures the enclosing git repository to transparently        ║
# ║  encrypt/decrypt files that match the "sops" filter in           ║
# ║  .gitattributes. Run it from anywhere inside the repository      ║
# ║  you want to configure (idempotent — safe to run on every        ║
# ║  clone, in a setup task, or repeatedly).                         ║
# ║                                                                  ║
# ║  Once configured, the workflow becomes git-crypt-like:           ║
# ║                                                                  ║
# ║    git pull / checkout  →  files are decrypted automatically     ║
# ║    git add / commit     →  files are encrypted automatically     ║
# ║    git diff / log -p    →  shows decrypted content               ║
# ║                                                                  ║
# ║  Three git mechanisms are used:                                  ║
# ║                                                                  ║
# ║  1. filter.sops.smudge   (checkout → working dir)                ║
# ║     Decrypts the encrypted blob from git into plaintext.         ║
# ║                                                                  ║
# ║  2. filter.sops.clean    (working dir → staging)                 ║
# ║     Encrypts plaintext before git stores it. Delegates to        ║
# ║     clean-filter.sh, which reuses existing ciphertext when       ║
# ║     content is unchanged (prevents false diffs) and fails hard   ║
# ║     rather than ever staging plaintext.                          ║
# ║                                                                  ║
# ║  3. diff.sops.textconv   (git diff / git log -p)                 ║
# ║     Routes diffs through the smudge filter so they show          ║
# ║     meaningful plaintext changes instead of ciphertext.          ║
# ║                                                                  ║
# ║  Finally, a re-smudge pass fixes the fresh-clone gap: files      ║
# ║  checked out BEFORE the filters were configured still hold raw   ║
# ║  ciphertext in the working tree — they are decrypted in place    ║
# ║  (only when the working copy is byte-identical to the stored     ║
# ║  blob, so local edits are never touched).                        ║
# ║                                                                  ║
# ║  Requires:                                                       ║
# ║    - sops on PATH                                                ║
# ║    - .sops.yaml in the target repo root (creation rules / keys)  ║
# ║    - .gitattributes with `filter=sops diff=sops` on target files ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILTER_SCRIPT="${SCRIPT_DIR}/clean-filter.sh"

# ── Resolve the repository to configure ────
# The target is the repo the caller is standing in. If the caller is
# standing inside this tool's own checkout (e.g. ran ./install.sh from
# a submodule directory), configure the superproject instead.
TARGET_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "Error: not inside a git repository. cd into the repo you want to configure." >&2
	exit 1
}

if [[ "${TARGET_ROOT}" == "${SCRIPT_DIR}" ]]; then
	SUPERPROJECT="$(git rev-parse --show-superproject-working-tree 2>/dev/null || true)"
	if [[ -n "${SUPERPROJECT}" ]]; then
		TARGET_ROOT="${SUPERPROJECT}"
	else
		echo "Error: you are inside the sops-git-filters checkout itself." >&2
		echo "cd into the repository you want to configure and run:" >&2
		echo "  ${SCRIPT_DIR}/install.sh" >&2
		exit 1
	fi
fi

if [[ ! -x "${FILTER_SCRIPT}" ]]; then
	echo "Error: clean filter script not found or not executable: ${FILTER_SCRIPT}" >&2
	exit 1
fi

if ! command -v sops >/dev/null 2>&1; then
	echo "Error: sops not found on PATH. Install it first (mise/brew/apt)." >&2
	exit 1
fi

# ── Storage format (must match clean-filter.sh) ────
STORE_FORMAT="json"
if [[ -f "${TARGET_ROOT}/.sops-filter.conf" ]]; then
	conf_value=$(grep -E '^SOPS_STORE_FORMAT=' "${TARGET_ROOT}/.sops-filter.conf" | tail -1 | cut -d= -f2 | tr -d '[:space:]')
	[[ -n "${conf_value}" ]] && STORE_FORMAT="${conf_value}"
fi

case "${STORE_FORMAT}" in
json) DECRYPT_ARGS="--input-type json --output-type binary" ;;
dotenv) DECRYPT_ARGS="--input-type dotenv --output-type dotenv" ;;
*)
	echo "Error: invalid SOPS_STORE_FORMAT '${STORE_FORMAT}' in .sops-filter.conf (expected: json or dotenv)" >&2
	exit 1
	;;
esac

# ── Compose the filter commands ────
# Prefer a REPO-RELATIVE path for the clean filter: git runs filters
# from the top level of the working tree, and a relative path keeps
# working when the repository directory is moved or renamed (an
# absolute path in .git/config silently breaks on the next move).
if [[ "${SCRIPT_DIR}" == "${TARGET_ROOT}"/* ]]; then
	CLEAN_CMD="${SCRIPT_DIR#"${TARGET_ROOT}"/}/clean-filter.sh %f"
else
	CLEAN_CMD="${FILTER_SCRIPT} %f"
	echo "⚠  sops-git-filters lives outside the target repo — using an absolute" >&2
	echo "   path in .git/config. It will break if either directory moves." >&2
	echo "   Consider vendoring or adding it as a submodule inside the repo." >&2
fi

SMUDGE_CMD="sops decrypt ${DECRYPT_ARGS} --filename-override %f /dev/stdin"
# textconv = cat is NOT a mistake. Git materializes textconv temp files
# through convert_to_working_tree(), i.e. the smudge filter runs FIRST
# and textconv already receives decrypted plaintext. Without a textconv
# driver git diffs the raw blobs instead (ciphertext gibberish) — so
# `cat` is exactly the switch that flips diffs to the smudged path.
# (A `sops decrypt` textconv double-decrypts and errors on plaintext.)
TEXTCONV_CMD="cat"

# ── Configure git (local to the target repo only) ────
# Idempotency: compare the SMUDGE command, not just the clean path —
# the clean path is stable across storage-format migrations, so
# comparing only it would skip smudge/textconv updates on existing
# clones when the format changes.
git_cfg() { git -C "${TARGET_ROOT}" config --local "$@"; }

CURRENT_CLEAN=$(git_cfg --get filter.sops.clean 2>/dev/null || echo "")
CURRENT_SMUDGE=$(git_cfg --get filter.sops.smudge 2>/dev/null || echo "")
CURRENT_TEXTCONV=$(git_cfg --get diff.sops.textconv 2>/dev/null || echo "")

if [[ "${CURRENT_CLEAN}" == "${CLEAN_CMD}" &&
	"${CURRENT_SMUDGE}" == "${SMUDGE_CMD}" &&
	"${CURRENT_TEXTCONV}" == "${TEXTCONV_CMD}" ]]; then
	echo "SOPS git filters already configured (format: ${STORE_FORMAT})."
else
	git_cfg filter.sops.smudge "${SMUDGE_CMD}"
	git_cfg filter.sops.clean "${CLEAN_CMD}"
	# required=true: fail the operation if the filter fails — never
	# silently commit plaintext because sops or the script is broken.
	git_cfg filter.sops.required true
	git_cfg diff.sops.textconv "${TEXTCONV_CMD}"
	echo "SOPS git filters configured (format: ${STORE_FORMAT})."
fi

# ── Re-smudge pass: heal files checked out before setup ────
# On a fresh clone the filters are not yet in .git/config, so SOPS-
# managed files land in the working tree as raw ciphertext. Decrypt
# them in place — but ONLY when the working copy is byte-identical to
# the blob in the index (proof the smudge never ran and there are no
# local edits to lose).
FOUND_ANY=0
while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
	[[ "${attr}" == "filter" && "${value}" == "sops" ]] || continue
	FOUND_ANY=1
	f="${TARGET_ROOT}/${path}"
	[[ -f "${f}" ]] || continue

	index_sha=$(git -C "${TARGET_ROOT}" ls-files -s -- "${path}" | awk '{print $2}')
	[[ -n "${index_sha}" ]] || continue
	worktree_sha=$(git hash-object --no-filters -- "${f}")
	[[ "${worktree_sha}" == "${index_sha}" ]] || continue

	# Working copy == stored ciphertext → smudge never ran. Decrypt it.
	# shellcheck disable=SC2086  # DECRYPT_ARGS is a flag list
	if plaintext=$( (git -C "${TARGET_ROOT}" cat-file -p ":${path}" |
		sops decrypt ${DECRYPT_ARGS} --filename-override "${path}" /dev/stdin 2>/dev/null) && printf x); then
		printf '%s' "${plaintext%x}" >"${f}"
		# The write above bypassed git, so the index's cached stat still
		# describes the ciphertext checkout — and git flags size deltas
		# as "modified" without consulting filters. update-index re-runs
		# the clean filter (which reuses the identical blob) and records
		# fresh stat data, so `git status` is clean again.
		git -C "${TARGET_ROOT}" update-index -- "${path}" 2>/dev/null ||
			echo "⚠  Could not refresh index stat for ${path}; run: git add ${path}" >&2
		echo "Re-smudged ${path} (was raw ciphertext from a pre-setup checkout)."
	else
		echo "⚠  Could not decrypt ${path} — working tree still holds ciphertext." >&2
		echo "   Configure your keys (age/KMS) and re-run this script." >&2
	fi
done < <(git -C "${TARGET_ROOT}" ls-files -z | git -C "${TARGET_ROOT}" check-attr --stdin -z filter)

if [[ "${FOUND_ANY}" -eq 0 ]]; then
	echo "Note: no tracked files carry 'filter=sops' in .gitattributes yet." >&2
	echo "Add lines like:  .env filter=sops diff=sops" >&2
fi

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
# ║  Then permissions are tightened: git cannot store mode 0600, so  ║
# ║  smudged secrets land with the caller's umask (0644 by default   ║
# ║  — world-readable private keys). harden-permissions.sh chmods    ║
# ║  every filter=sops file to 0600, and post-checkout/post-merge    ║
# ║  hooks are installed so later checkouts and merges do the same.  ║
# ║  Set SOPS_FILTER_INSTALL_HOOKS=0 to skip the hook install.       ║
# ║                                                                  ║
# ║  Requires:                                                       ║
# ║    - sops on PATH                                                ║
# ║    - .sops.yaml in the target repo root (creation rules / keys)  ║
# ║    - .gitattributes with `filter=sops diff=sops` on target files ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILTER_SCRIPT="${SCRIPT_DIR}/clean-filter.sh"
HARDEN_SCRIPT="${SCRIPT_DIR}/harden-permissions.sh"

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

# ── Tighten permissions on the decrypted files ────
# Git only round-trips the executable bit, so every smudge (including
# the pass above) writes secrets with the caller's umask — 0644 on a
# default workstation. Fix them now; the hooks below fix them later.
if [[ -x "${HARDEN_SCRIPT}" ]]; then
	"${HARDEN_SCRIPT}" --root "${TARGET_ROOT}" || true
else
	echo "⚠  ${HARDEN_SCRIPT} missing or not executable — SOPS-managed files" >&2
	echo "   keep their umask permissions (usually 0644). Update this checkout." >&2
fi

# ── Install post-checkout / post-merge permission hooks ────
# A plain `git checkout` or `git pull` re-runs the smudge filter and so
# re-creates the 0644 problem. These two hooks re-tighten afterwards.
# They are deliberately NOT the place for any other logic: they call
# harden-permissions.sh from the checkout, so updating the tool updates
# the behaviour without re-running install.sh.
if [[ "${SOPS_FILTER_INSTALL_HOOKS:-1}" == "0" ]]; then
	echo "Skipping post-checkout/post-merge hook install (SOPS_FILTER_INSTALL_HOOKS=0)."
elif [[ ! -x "${HARDEN_SCRIPT}" ]]; then
	echo "Skipping permission hooks: ${HARDEN_SCRIPT} is missing." >&2
else
	HOOK_MARKER="# managed by sops-git-filters (secret file permissions)"

	# core.hooksPath wins over $GIT_DIR/hooks when it is set. It is a pathname
	# value, so read it with --type=path (git >= 2.18): git expands a leading
	# ~ itself, and without this a "~/.githooks" setting would be treated as a
	# relative path inside the repo.
	HOOKS_DIR="$(git -C "${TARGET_ROOT}" config --type=path --get core.hooksPath 2>/dev/null || true)"
	if [[ -z "${HOOKS_DIR}" ]]; then
		HOOKS_DIR="$(git -C "${TARGET_ROOT}" rev-parse --git-path hooks)"
	fi
	case "${HOOKS_DIR}" in
	/*) ;;
	*) HOOKS_DIR="${TARGET_ROOT}/${HOOKS_DIR}" ;;
	esac

	# Prefer a repo-relative reference for the same reason the clean
	# filter does: an absolute path breaks silently when the repo moves.
	if [[ "${SCRIPT_DIR}" == "${TARGET_ROOT}"/* ]]; then
		HARDEN_REL="${SCRIPT_DIR#"${TARGET_ROOT}"/}/harden-permissions.sh"
		HOOK_HARDEN_ASSIGN='HARDEN="$root/'"${HARDEN_REL}"'"'
		HARDEN_HINT="\"\$(git rev-parse --show-toplevel)/${HARDEN_REL}\""
	else
		HOOK_HARDEN_ASSIGN='HARDEN="'"${HARDEN_SCRIPT}"'"'
		HARDEN_HINT="\"${HARDEN_SCRIPT}\""
	fi

	mkdir -p "${HOOKS_DIR}"
	for hook_name in post-checkout post-merge; do
		hook_path="${HOOKS_DIR}/${hook_name}"

		# Never clobber a hook this tool did not write — pre-commit,
		# prek, husky and hand-rolled hooks all live here.
		if [[ -e "${hook_path}" ]] && ! grep -qF "${HOOK_MARKER}" "${hook_path}" 2>/dev/null; then
			echo "⚠  ${hook_name} hook exists and is not managed by sops-git-filters." >&2
			echo "   Not overwriting. Add this line to it by hand:" >&2
			echo "     ${HARDEN_HINT} --quiet || true" >&2
			continue
		fi

		cat >"${hook_path}" <<EOF
#!/usr/bin/env bash
${HOOK_MARKER}
#
# ${hook_name}: git cannot store mode 0600, so a checkout or merge that
# re-runs the SOPS smudge filter recreates secrets with the caller's
# umask (0644 by default). Re-tighten every filter=sops file.
#
# Generated by install.sh — edit harden-permissions.sh, not this file.
# Delete it to opt out; re-running install.sh restores it.
set -u
root="\$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
${HOOK_HARDEN_ASSIGN}
[ -x "\${HARDEN}" ] || exit 0
"\${HARDEN}" --root "\${root}" --quiet || true
exit 0
EOF
		chmod +x "${hook_path}"
		echo "Installed ${hook_name} hook (re-applies 0600 after checkout/merge)."
	done
fi

#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Git Filter Setup                                           ║
# ║                                                                  ║
# ║  Configures the enclosing git repository to encrypt and decrypt  ║
# ║  the files that match the "sops" filter in .gitattributes, with  ║
# ║  no extra step. Run it from anywhere inside the repository you   ║
# ║  want to configure. It is idempotent: safe to run on every       ║
# ║  clone, in a setup task, or repeatedly.                          ║
# ║                                                                  ║
# ║  Once configured, the workflow becomes git-crypt-like:           ║
# ║                                                                  ║
# ║    git pull / checkout  →  files are decrypted automatically     ║
# ║    git add / commit     →  files are encrypted automatically     ║
# ║    git diff / log -p    →  shows decrypted content               ║
# ║                                                                  ║
# ║  Four git mechanisms are used:                                   ║
# ║                                                                  ║
# ║  1. filter.sops.smudge   (checkout → working dir)                ║
# ║     Decrypts the encrypted blob from git into plaintext          ║
# ║     (smudge-filter.sh: `sops decrypt`, plus a hint when that     ║
# ║     fails).                                                      ║
# ║                                                                  ║
# ║  2. filter.sops.clean    (working dir → staging)                 ║
# ║     Encrypts plaintext before git stores it. Delegates to        ║
# ║     clean-filter.sh, which reuses existing ciphertext when       ║
# ║     content is unchanged (no false diffs) and fails hard, so     ║
# ║     it never stages plaintext.                                   ║
# ║                                                                  ║
# ║  3. diff.sops.textconv   (git diff / git log -p)                 ║
# ║     Routes diffs through the smudge filter so they show the      ║
# ║     plaintext changes instead of ciphertext.                     ║
# ║                                                                  ║
# ║  4. merge.sops.driver    (merge / rebase / cherry-pick / stash)  ║
# ║     For paths with merge=sops in .gitattributes: merges the      ║
# ║     plaintext of the three versions (merge-driver.sh) instead    ║
# ║     of letting git merge ciphertext, which cannot work.          ║
# ║                                                                  ║
# ║  Git does NOT run these scripts from the checkout of the tool.   ║
# ║  install.sh copies the ones git needs into                       ║
# ║  <git common dir>/sops-git-filters/ and points the filter, the   ║
# ║  merge driver and the hooks at that copy, with a path that is    ║
# ║  resolved when the command runs ("$(git rev-parse                ║
# ║  --git-common-dir)"/...), so it also works in a linked worktree  ║
# ║  and after the repository moved. Checking out a branch therefore ║
# ║  cannot swap the code that sees your plaintext. But after an     ║
# ║  update of the tool, NOTHING changes until install.sh has run    ║
# ║  again. The installed copy prints a line when it notices that.   ║
# ║                                                                  ║
# ║  Finally, a re-smudge pass fixes the fresh-clone gap: files      ║
# ║  checked out BEFORE the filters were configured still hold raw   ║
# ║  ciphertext in the working tree. They are decrypted in place     ║
# ║  (only when the working copy is byte-identical to the stored     ║
# ║  blob, so local edits are never touched, and never through a     ║
# ║  symlink or a hard link, which could lead out of the tree).      ║
# ║                                                                  ║
# ║  Then permissions are tightened: git cannot store mode 0600, so  ║
# ║  smudged secrets land with the caller's umask (0644 by default,  ║
# ║  which makes private keys world-readable). harden-permissions.sh ║
# ║  chmods every filter=sops file to 0600 (SOPS_FILE_MODE           ║
# ║  overrides; a 100755 file keeps its owner execute bit, 0700),    ║
# ║  and five hooks are installed so that later git commands do the  ║
# ║  same: post-checkout, post-merge, post-rewrite, post-applypatch  ║
# ║  and post-commit. Set SOPS_FILTER_INSTALL_HOOKS=0 to skip them.  ║
# ║                                                                  ║
# ║  The hooks are written into this repository's own hooks          ║
# ║  directory only. When core.hooksPath names a directory that      ║
# ║  other repositories use too, nothing is written there (a hook    ║
# ║  in it runs for every one of them); the line to add by hand is   ║
# ║  printed instead. Hooks that an older install.sh wrote into      ║
# ║  such a directory are removed. In the repository's own           ║
# ║  directory, an existing hook is replaced only when it is, byte   ║
# ║  for byte, one that install.sh wrote; for any other the line is  ║
# ║  printed too.                                                    ║
# ║                                                                  ║
# ║  core.trustctime is set to false. The chmod changes a file's     ║
# ║  inode change time, and git would take the secret for locally    ║
# ║  modified: now and then a rebase stopped because of it. A        ║
# ║  value already set in .git/config is left alone.                 ║
# ║                                                                  ║
# ║  It also looks at what git already holds: a SOPS-managed file    ║
# ║  whose blob in the index or in HEAD is not an encrypted SOPS     ║
# ║  document was committed in plaintext (before the filter          ║
# ║  existed, or from a clone without it). Those are listed, with    ║
# ║  the command that encrypts them.                                 ║
# ║                                                                  ║
# ║  Exit status:                                                    ║
# ║    0  filters and hooks are in place, nothing left to do         ║
# ║    1  the filters were not set up (not a repo, sops missing or   ║
# ║       too old, bad .sops-filter.conf, filter.sops.process set    ║
# ║       outside .git/config). The repository is as it was, except  ║
# ║       that one set up before gets filter.sops.required=true      ║
# ║       back, which keeps git fail-closed. One exit 1 comes later: ║
# ║       when another git config file overrides the filter          ║
# ║       settings. Then .git/config holds them already, and         ║
# ║       .git/sops-git-filters/ the scripts, but no hooks were      ║
# ║       installed and no file was decrypted.                       ║
# ║    3  filters and hooks are in place, but files need attention:  ║
# ║       tracked in plaintext, still stored in the other storage    ║
# ║       format, not decrypted because sops could not (keys or      ║
# ║       credentials missing) or because the working copy is        ║
# ║       reached through a symlink or a hard link, or holding NUL   ║
# ║       bytes. See the lists printed at the end.                   ║
# ║                                                                  ║
# ║  Requires:                                                       ║
# ║    - sops >= 3.11.0 on PATH                                      ║
# ║    - .sops.yaml in the target repo root (creation rules / keys)  ║
# ║    - .gitattributes with `filter=sops diff=sops` on target files ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

# Physical paths (pwd -P), here and for the repository below: git reports
# the top level with symlinks resolved, and a path reached through a
# symlink would never match it.
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
FILTER_SCRIPT="${SCRIPT_DIR}/clean-filter.sh"
# What git runs, and therefore what is copied under .git/ further down.
# lib.sh first: the others load it.
RUNTIME_SCRIPTS="lib.sh clean-filter.sh smudge-filter.sh merge-driver.sh harden-permissions.sh"

# ── Resolve the repository to configure ────
# The target is the repo the caller is standing in. If the caller is
# standing inside this tool's own checkout (e.g. ran ./install.sh from
# a submodule directory), configure the superproject instead.
TARGET_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "Error: not inside a git repository. cd into the repo you want to configure." >&2
	exit 1
}
TARGET_ROOT="$(CDPATH='' cd -- "${TARGET_ROOT}" && pwd -P)"

if [[ "${TARGET_ROOT}" == "${SCRIPT_DIR}" ]]; then
	SUPERPROJECT="$(git rev-parse --show-superproject-working-tree 2>/dev/null || true)"
	if [[ -n "${SUPERPROJECT}" ]]; then
		TARGET_ROOT="$(CDPATH='' cd -- "${SUPERPROJECT}" && pwd -P)"
	else
		echo "Error: you are inside the sops-git-filters checkout itself." >&2
		echo "cd into the repository you want to configure and run:" >&2
		echo "  ${SCRIPT_DIR}/install.sh" >&2
		exit 1
	fi
fi

# ── Keep an existing setup fail-closed ────
# If git already routes files through the sops filter here, a failing
# filter must stop git. Make sure of that NOW, before any check below can
# end this script. What ends it (sops missing from PATH because setup ran
# outside the dev shell, a bad .sops-filter.conf, a broken copy of this
# tool) makes the clean filter fail too, and without filter.sops.required
# git takes a failing filter as no filter and stages the plaintext.
#
# Only when a clean or smudge command is set: required=true with no
# command makes git fail on every SOPS-managed file, and a clone that
# never had the filters must keep working if this script cannot finish.
# Set in a config file, that is: a command given for this one run
# (`git -c`, GIT_CONFIG_COUNT) is gone afterwards, the flag would stay.
if (
	unset GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
	git -C "${TARGET_ROOT}" config --get-regexp '^filter\.sops\.(clean|smudge)$' >/dev/null 2>&1
); then
	git -C "${TARGET_ROOT}" config --local filter.sops.required true
fi

# Only now the checks that can end this script. lib.sh comes after the
# step above on purpose: without it the clean filter fails as well.
if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	echo "Error: lib.sh is missing next to install.sh (${SCRIPT_DIR}). Update or re-copy sops-git-filters." >&2
	exit 1
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

if [[ ! -x "${FILTER_SCRIPT}" ]]; then
	echo "Error: clean filter script not found or not executable: ${FILTER_SCRIPT}" >&2
	exit 1
fi
for runtime_script in ${RUNTIME_SCRIPTS}; do
	if [[ ! -r "${SCRIPT_DIR}/${runtime_script}" ]]; then
		echo "Error: ${runtime_script} is missing next to install.sh (${SCRIPT_DIR}). Update or re-copy sops-git-filters." >&2
		exit 1
	fi
done
if ! sgf_is_version "${SGF_VERSION:-}"; then
	echo "Error: lib.sh next to install.sh (${SCRIPT_DIR}) has no usable SGF_VERSION line. Update or re-copy sops-git-filters." >&2
	exit 1
fi

if ! command -v sops >/dev/null 2>&1; then
	echo "Error: sops not found on PATH. Install it first (mise/brew/apt)." >&2
	exit 1
fi

# ── Minimum sops version ────
# Older releases can store a file in clear inside a SOPS envelope (see
# SGF_MIN_SOPS_VERSION in lib.sh). clean-filter.sh would refuse such a
# result, so nothing leaks, but every `git add` would fail. Say so now.
SOPS_VERSION="$(sgf_sops_version)"
if [[ -z "${SOPS_VERSION}" ]]; then
	echo "Error: could not read the version of $(command -v sops) ('sops --version')." >&2
	exit 1
fi
if ! sgf_version_ge "${SOPS_VERSION}" "${SGF_MIN_SOPS_VERSION}"; then
	echo "Error: sops ${SOPS_VERSION} is too old; sops-git-filters needs ${SGF_MIN_SOPS_VERSION} or newer." >&2
	echo "Up to 3.10.2, sops can leave a whole file unencrypted when the matching" >&2
	echo ".sops.yaml rule uses encrypted_regex, unencrypted_regex or a suffix option." >&2
	exit 1
fi

# ── Storage format (the same reader clean-filter.sh uses) ────
STORE_FORMAT="$(sgf_store_format "${TARGET_ROOT}")" || exit 1
OTHER_FORMAT="$(sgf_other_format "${STORE_FORMAT}")"

case "${STORE_FORMAT}" in
json) DECRYPT_ARGS="--input-type json --output-type binary" ;;
dotenv) DECRYPT_ARGS="--input-type dotenv --output-type dotenv" ;;
esac

# ── Where git finds the scripts ────
# Not in the checkout of the tool: in a copy under the git directory
# (installed below). The directory is the COMMON git directory, the one
# all worktrees of this repository share, and it is asked for when the
# command runs:
#
#   - In a linked worktree ".git" is a file, so a fixed ".git/..." path
#     does not exist there. `git rev-parse --git-common-dir` gives the
#     right directory from any worktree.
#   - Nothing absolute is stored, so the repository can be moved.
#
# Git runs these commands through sh, from the top level of the working
# tree. They are the same in every repository: the path of the tool is
# no longer part of them.
GIT_COMMON_P="$(CDPATH='' cd -- "${TARGET_ROOT}" && CDPATH='' cd -- "$(git rev-parse --git-common-dir)" && pwd -P)"
INSTALL_DIR="${GIT_COMMON_P}/sops-git-filters"
# shellcheck disable=SC2016  # $(...) must reach git's shell unexpanded
INSTALLED_Q='"$(git rev-parse --git-common-dir)"/sops-git-filters'
CLEAN_CMD="${INSTALLED_Q}/clean-filter.sh %f"
# The smudge command carries the storage format. The smudge filter cannot
# read it from .sops-filter.conf: in a new working tree git writes ".env"
# before that file exists.
SMUDGE_CMD="${INSTALLED_Q}/smudge-filter.sh ${STORE_FORMAT} %f"
MERGE_CMD="${INSTALLED_Q}/merge-driver.sh %O %A %B %L %P"

# textconv = cat is NOT a mistake. Git materializes textconv temp files
# through convert_to_working_tree(), i.e. the smudge filter runs FIRST
# and textconv already receives decrypted plaintext. Without a textconv
# driver git diffs the raw blobs instead (ciphertext gibberish), so
# `cat` is the switch that flips diffs to the smudged path.
# (A `sops decrypt` textconv double-decrypts and errors on plaintext.)
TEXTCONV_CMD="cat"

# ── git config helpers (local to the target repo only) ────
git_cfg() { git -C "${TARGET_ROOT}" config --local "$@"; }
# The value git will really use: a worktree-level or included config can
# override .git/config.
git_effective() { git -C "${TARGET_ROOT}" config "$@" 2>/dev/null || true; }

# ── A long-running filter under the same name ────
# filter.<driver>.process (a long-running filter) wins over clean/smudge.
# One left behind by another tool under the same driver name would bypass
# clean-filter.sh completely. One in .git/config is removed further down.
# One anywhere else (the global config, a worktree's, an included file,
# `git -c`, GIT_CONFIG_COUNT) is not this script's to change: stop here,
# before the copy below and before any setting is written, so that this
# exit leaves the repository as it was (audit A-03). Every value git
# reads, compared with those of .git/config alone (no includes): any
# difference is a value from somewhere else.
if [[ "$(git_effective --get-all filter.sops.process)" != "$(git_cfg --get-all filter.sops.process 2>/dev/null || true)" ]]; then
	echo "Error: filter.sops.process is set outside this repository's .git/config:" >&2
	git -C "${TARGET_ROOT}" config --show-origin --get-all filter.sops.process >&2 || true
	echo "Git prefers it over the clean/smudge filters, so clean-filter.sh would never run." >&2
	echo "Remove that setting and re-run this script." >&2
	exit 1
fi

# ── Install the copy that git runs ────
# Before any git setting is written: a setting that points at a script
# which is not there yet would make every git command on a secret fail.
# Each file is written under a temporary name and moved into place, so a
# git command that runs at this moment sees the old file or the new one.
# INSTALLED records the version and where this checkout of the tool is:
# the copy uses it to notice an update that was not installed yet.
if [[ -L "${INSTALL_DIR}" ]]; then
	echo "Error: ${INSTALL_DIR} is a symlink. Remove it and re-run this script." >&2
	exit 1
fi
if [[ "${SCRIPT_DIR}" == "${TARGET_ROOT}"/* ]]; then
	INSTALL_SOURCE="${SCRIPT_DIR#"${TARGET_ROOT}"/}"
else
	INSTALL_SOURCE="${SCRIPT_DIR}"
fi
INSTALLED_NOTE="$(printf 'version=%s\nsource=%s\n' "${SGF_VERSION}" "${INSTALL_SOURCE}" && printf x)"
INSTALLED_NOTE="${INSTALLED_NOTE%x}"
mkdir -p "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}"
copy_changed=0
for runtime_script in ${RUNTIME_SCRIPTS}; do
	if [[ ! -L "${INSTALL_DIR}/${runtime_script}" ]] &&
		cmp -s "${SCRIPT_DIR}/${runtime_script}" "${INSTALL_DIR}/${runtime_script}" 2>/dev/null &&
		[[ -x "${INSTALL_DIR}/${runtime_script}" || "${runtime_script}" == "lib.sh" ]]; then
		continue
	fi
	cp "${SCRIPT_DIR}/${runtime_script}" "${INSTALL_DIR}/${runtime_script}.new.$$"
	if [[ "${runtime_script}" == "lib.sh" ]]; then
		chmod 600 "${INSTALL_DIR}/${runtime_script}.new.$$"
	else
		chmod 700 "${INSTALL_DIR}/${runtime_script}.new.$$"
	fi
	mv -f "${INSTALL_DIR}/${runtime_script}.new.$$" "${INSTALL_DIR}/${runtime_script}"
	copy_changed=1
done
if [[ -L "${INSTALL_DIR}/INSTALLED" ]] ||
	[[ "$(cat "${INSTALL_DIR}/INSTALLED" 2>/dev/null && printf x)" != "${INSTALLED_NOTE}x" ]]; then
	printf '%s' "${INSTALLED_NOTE}" >"${INSTALL_DIR}/INSTALLED.new.$$"
	mv -f "${INSTALL_DIR}/INSTALLED.new.$$" "${INSTALL_DIR}/INSTALLED"
	copy_changed=1
fi
if [[ "${copy_changed}" -eq 1 ]]; then
	echo "Installed the scripts git runs (version ${SGF_VERSION}) into ${INSTALL_DIR}"
fi
# From here on this script uses the installed harden-permissions.sh too:
# it is the one the hooks will run, and it is executable whatever the
# file modes of the checkout are.
HARDEN_SCRIPT="${INSTALL_DIR}/harden-permissions.sh"

# ── Configure git (local to the target repo only) ────
# required=true: fail the operation if the filter fails, so that a broken
# sops or script never silently commits plaintext. Written on EVERY
# run, outside the "already configured" test below: with the two
# commands in place and this flag missing, git treats a failing filter
# as no filter at all and stages the plaintext. (An existing setup
# already got it further up, before the checks that can exit.)
#
# Not earlier than here: required=true with no command makes git fail on
# every SOPS-managed file the user edits (`git status`, `git add`: exit
# 128). From here on nothing stops this script before the commands are
# in .git/config, so a clone that never had the filters is not left in
# that state (audit A-03). And before the commands, not after them: in
# between they would be there without the flag.
git_cfg filter.sops.required true

# The filter.sops.process of .git/config (see above).
if git_cfg --get filter.sops.process >/dev/null 2>&1; then
	git_cfg --unset-all filter.sops.process
	echo "Removed filter.sops.process from .git/config (it overrides the clean/smudge filters)."
fi

# Idempotency: write the settings only when one of them differs: a first
# install, a setup from before v3.0.0 (its commands named the checkout of
# the tool), or a changed storage format (it is part of the smudge
# command).
CURRENT_CLEAN=$(git_cfg --get filter.sops.clean 2>/dev/null || echo "")
CURRENT_SMUDGE=$(git_cfg --get filter.sops.smudge 2>/dev/null || echo "")
CURRENT_TEXTCONV=$(git_cfg --get diff.sops.textconv 2>/dev/null || echo "")
CURRENT_MERGE=$(git_cfg --get merge.sops.driver 2>/dev/null || echo "")

if [[ "${CURRENT_CLEAN}" == "${CLEAN_CMD}" &&
	"${CURRENT_SMUDGE}" == "${SMUDGE_CMD}" &&
	"${CURRENT_TEXTCONV}" == "${TEXTCONV_CMD}" &&
	"${CURRENT_MERGE}" == "${MERGE_CMD}" ]]; then
	echo "SOPS git filters already configured (format: ${STORE_FORMAT})."
else
	git_cfg filter.sops.smudge "${SMUDGE_CMD}"
	git_cfg filter.sops.clean "${CLEAN_CMD}"
	git_cfg diff.sops.textconv "${TEXTCONV_CMD}"
	# The merge driver only acts on paths that carry merge=sops in
	# .gitattributes. recursive=binary: when git first has to merge two
	# common ancestors with each other, it takes one of them instead of
	# calling the driver for that inner merge.
	git_cfg merge.sops.name "three-way merge of SOPS-managed files on their plaintext"
	git_cfg merge.sops.driver "${MERGE_CMD}"
	git_cfg merge.sops.recursive binary
	echo "SOPS git filters configured (format: ${STORE_FORMAT})."
fi

# Last check: what was just written must be what git will use. The one
# exit 1 that comes after .git/config was changed: the settings stay
# there (they are right, and they keep an existing setup fail-closed), and
# the message says what was not done.
if [[ "$(git_effective --bool --get filter.sops.required)" != "true" ||
	"$(git_effective --get filter.sops.clean)" != "${CLEAN_CMD}" ||
	"$(git_effective --get filter.sops.smudge)" != "${SMUDGE_CMD}" ]]; then
	echo "Error: another git config file overrides the filter settings written to .git/config:" >&2
	git -C "${TARGET_ROOT}" config --show-origin --get-regexp '^filter\.sops\.' >&2 || true
	echo "The settings in .git/config and the scripts under ${INSTALL_DIR} are in place," >&2
	echo "but git uses the overriding entries. Not done yet: no hooks were installed and no file was decrypted." >&2
	echo "Remove the overriding entries and re-run this script." >&2
	exit 1
fi

# ── Ignore inode change times ────
# A chmod of a secret changes the file's inode change time (ctime) after
# git recorded it, and the permission hooks installed below do that after
# every checkout. Git compares ctime, so the secret then looks modified.
# `git status` finds out it is not by running the clean filter once more
# (one decryption per file). A rebase does not: when the chmod lands in a
# later second than the checkout, it stops with "Your local changes to
# the following files would be overwritten by merge".
#
# core.trustctime=false makes git ignore ctime; it still compares mtime,
# size and inode. A value already set in .git/config is left alone, so
# `git config core.trustctime true` keeps git's default.
if [[ -z "$(git_cfg --get core.trustctime 2>/dev/null || true)" ]]; then
	git_cfg core.trustctime false
	echo "Set core.trustctime=false (a chmod of a secret is not a local change)."
fi

# ── Re-smudge pass: heal files checked out before setup ────
# On a fresh clone the filters are not yet in .git/config, so SOPS-
# managed files land in the working tree as raw ciphertext. Decrypt
# them in place, but ONLY when the working copy is byte-identical to
# the blob in the index (proof the smudge never ran and there are no
# local edits to lose), or is that blob with a CR before its line ends
# (core.autocrlf, see below).
#
# The same walk answers a second question: is the version git holds
# encrypted at all? A blob that is not a SOPS document was committed in
# plaintext, before the filter existed or from a clone without it.
# Decrypting cannot work on those; they are collected and reported at
# the end instead.
FOUND_ANY=0
PLAINTEXT_IN_GIT=""
OTHER_FORMAT_IN_GIT=""
STILL_ENCRYPTED=""
STILL_ENCRYPTED_KEY_TYPES=""
HOLDS_NUL_BYTES=""
THROUGH_A_LINK=""
previous_path=""
while IFS= read -r -d '' record; do
	# "<mode> <object id> <stage>" TAB <path> (lib.sh). An unmerged path
	# is listed once per stage; its first entry stands for it.
	path="${record#*$'\t'}"
	[[ "${path}" != "${previous_path}" ]] || continue
	previous_path="${path}"
	FOUND_ANY=1
	f="${TARGET_ROOT}/${path}"

	index_mode="${record%% *}"
	index_sha="${record#* }"
	index_sha="${index_sha%% *}"
	# A symlink or a submodule: git never runs a filter on these.
	[[ "${index_mode}" != "120000" && "${index_mode}" != "160000" ]] || continue

	# ── Is the tracked version an encrypted SOPS document? ────
	# First the committed version, when it is not the staged one: is it
	# encrypted in either format? It is looked at before anything below
	# can move on to the next file, so that a plaintext commit is
	# reported whatever the index holds by now.
	head_sha="$(git -C "${TARGET_ROOT}" rev-parse -q --verify "HEAD:${path}" 2>/dev/null || true)"
	head_plain=0
	if [[ -n "${head_sha}" && "${head_sha}" != "${index_sha}" ]] &&
		! sgf_blob_is_sops_doc "${STORE_FORMAT}" "${head_sha}" "${TARGET_ROOT}" &&
		! sgf_blob_is_sops_doc "${OTHER_FORMAT}" "${head_sha}" "${TARGET_ROOT}"; then
		head_plain=1
	fi

	# Encrypted in the other storage format (a format change that is not
	# finished) is its own case: it needs re-encrypting.
	if sgf_blob_is_sops_doc "${OTHER_FORMAT}" "${index_sha}" "${TARGET_ROOT}"; then
		OTHER_FORMAT_IN_GIT="${OTHER_FORMAT_IN_GIT}   - ${path}"$'\n'
		if [[ "${head_plain}" -eq 1 ]]; then
			why="$(sgf_blob_problem "${STORE_FORMAT}" "${head_sha}" "${TARGET_ROOT}")"
			PLAINTEXT_IN_GIT="${PLAINTEXT_IN_GIT}   - ${path}  (HEAD)${why:+  [${why}]}"$'\n'
		fi
		continue
	fi
	where=""
	why=""
	if ! sgf_blob_is_sops_doc "${STORE_FORMAT}" "${index_sha}" "${TARGET_ROOT}"; then
		where="index"
		why="$(sgf_blob_problem "${STORE_FORMAT}" "${index_sha}" "${TARGET_ROOT}")"
	fi
	if [[ -n "${head_sha}" && "${head_sha}" == "${index_sha}" ]]; then
		[[ -z "${where}" ]] || where="index and HEAD"
	elif [[ "${head_plain}" -eq 1 ]]; then
		[[ -n "${where}" ]] || why="$(sgf_blob_problem "${STORE_FORMAT}" "${head_sha}" "${TARGET_ROOT}")"
		where="${where:+${where} and }HEAD"
	fi
	if [[ -n "${where}" ]]; then
		# In brackets: what the check found (a line or a key, never a value).
		PLAINTEXT_IN_GIT="${PLAINTEXT_IN_GIT}   - ${path}  (${where})${why:+  [${why}]}"$'\n'
		# Nothing to decrypt when the index version is not ciphertext.
		[[ "${where}" == "HEAD" ]] || continue
	fi

	[[ -f "${f}" ]] || continue
	# The path from the top of the working tree, not "${f}": on Windows
	# Git Bash turns an absolute /c/... path into C:/... for git, but not
	# one with a character such as ` in it, and git then cannot open it.
	worktree_sha=$(git -C "${TARGET_ROOT}" hash-object --no-filters -- "${path}")
	if [[ "${worktree_sha}" != "${index_sha}" ]]; then
		# core.autocrlf=true (or eol=crlf) on a path without -text: the
		# checkout before the filters existed put a CR before every LF of
		# the ciphertext. sops never writes a CR into a document, so a
		# copy that is the stored blob once its CRs are gone holds nothing
		# of its own to lose, and it is decrypted like the others. The
		# clean filter takes such a copy for the stored blob as well.
		# Before, it stayed ciphertext while this script exited 0 (audit
		# A-07). What is decrypted is the blob, not this copy.
		worktree_sha=$(tr -d '\r' <"${f}" | git -C "${TARGET_ROOT}" hash-object --stdin)
		[[ "${worktree_sha}" == "${index_sha}" ]] || continue
	fi

	# Working copy == stored ciphertext → smudge never ran. Decrypt it,
	# but not through a link. The plaintext is written to "${f}", and that
	# write follows a symlink in its place or on a directory of its path
	# (a shared or a dotfiles folder, say), and reaches every other name
	# of a hard link: it would land in a file outside the working tree,
	# where .gitignore does not reach (audit A-06, A-14). Git does not
	# write there either (it lists such a path as deleted or as a type
	# change). The file is left as it is and listed at the end.
	if sgf_through_symlink "${TARGET_ROOT}" "${path}" ||
		[[ -n "$(find "${f}" -prune -links +1 2>/dev/null)" ]]; then
		THROUGH_A_LINK="${THROUGH_A_LINK}   - ${path}"$'\n'
		continue
	fi

	# sops' own error is shown for the first file that fails (it says why:
	# no key, expired session, ...); the files after it are only listed.
	decrypt_stderr=/dev/stderr
	[[ -z "${STILL_ENCRYPTED}" ]] || decrypt_stderr=/dev/null
	# The plaintext passes through a shell variable, which cannot hold a
	# NUL byte: they are counted on the way in (lib.sh), and a file that
	# has any is not written, because it would be written damaged.
	# (pipefail: the status of the pipeline is that of sops.)
	# shellcheck disable=SC2086  # DECRYPT_ARGS is a flag list
	if SGF_CAPTURED=$(git -C "${TARGET_ROOT}" cat-file blob "${index_sha}" |
		sops decrypt ${DECRYPT_ARGS} --filename-override "${path}" 2>"${decrypt_stderr}" |
		sgf_cat_counting_nuls) && sgf_split_counted; then
		if [[ "${SGF_NUL_COUNT}" != "0" ]]; then
			HOLDS_NUL_BYTES="${HOLDS_NUL_BYTES}   - ${path}"$'\n'
			continue
		fi
		printf '%s' "${SGF_CONTENT}" >"${f}"
		# The write above bypassed git, so the index's cached stat still
		# describes the ciphertext checkout, and git flags size deltas
		# as "modified" without consulting filters. update-index re-runs
		# the clean filter (which reuses the identical blob) and records
		# fresh stat data, so `git status` is clean again.
		git -C "${TARGET_ROOT}" update-index -- "${path}" 2>/dev/null ||
			echo "⚠  Could not refresh index stat for ${path}; run: git add -- $(sgf_paste_pathspec "${TARGET_ROOT}/${path}")" >&2
		echo "Re-smudged ${path} (was raw ciphertext from a pre-setup checkout)."
	else
		STILL_ENCRYPTED="${STILL_ENCRYPTED}   - ${path}"$'\n'
		# For the hint at the end: the kinds of key these files name.
		for key_type in $(git -C "${TARGET_ROOT}" cat-file blob "${index_sha}" | sgf_doc_key_types); do
			case " ${STILL_ENCRYPTED_KEY_TYPES} " in
			*" ${key_type} "*) ;;
			*) STILL_ENCRYPTED_KEY_TYPES="${STILL_ENCRYPTED_KEY_TYPES} ${key_type}" ;;
			esac
		done
	fi
done < <(sgf_ls_managed "${TARGET_ROOT}")

if [[ "${FOUND_ANY}" -eq 0 ]]; then
	echo "Note: no tracked files carry 'filter=sops' in .gitattributes yet." >&2
	echo "Add lines like:  .env filter=sops diff=sops -text" >&2
fi

# ── Tighten permissions on the decrypted files ────
# Git only round-trips the executable bit, so every smudge (including
# the pass above) writes secrets with the caller's umask: 0644 on a
# default workstation. Fix them now; the hooks below fix them later.
if [[ -x "${HARDEN_SCRIPT}" ]]; then
	"${HARDEN_SCRIPT}" --root "${TARGET_ROOT}" || true
else
	echo "⚠  ${HARDEN_SCRIPT} missing or not executable — SOPS-managed files" >&2
	echo "   keep their umask permissions (usually 0644). Run install.sh again." >&2
fi

# ── Permission hooks ────
# A plain `git checkout` or `git pull` re-runs the smudge filter and so
# re-creates the 0644 problem, and so does every other command that
# writes a SOPS-managed file again. Git runs a hook after most of them:
#
#   post-checkout    checkout, switch, restore, worktree add, bisect
#   post-merge       merge, pull
#   post-rewrite     rebase, commit --amend
#   post-applypatch  am
#   post-commit      commit, cherry-pick, revert, each step of a rebase
#
# (`git stash`, `git stash pop`, `git reset --hard` and
# `git sparse-checkout add` run no hook: see "Limitations" in the README.)
# The hooks are deliberately NOT the place for any other logic. They call
# the copy of harden-permissions.sh under the git directory (installed
# above), found when the hook runs, like the filter commands: nothing in
# the working tree is executed, and the same hook text fits every
# repository and every worktree.
HOOK_MARKER="# managed by sops-git-filters (secret file permissions)"
HOOK_NAMES="post-checkout post-merge post-rewrite post-applypatch post-commit"

# hook_text <hook name> : the hook this script writes
hook_text() {
	cat <<EOF
#!/usr/bin/env bash
${HOOK_MARKER}
#
# $1: git cannot store mode 0600, so a command that writes a
# SOPS-managed file again (through the smudge filter) leaves it with
# the caller's umask (0644 by default). Re-tighten every filter=sops file.
#
# Generated by install.sh. It runs the copy of harden-permissions.sh that
# install.sh put under the git directory, not a file of the working tree.
# Delete it to opt out; re-running install.sh restores it.
set -u
root="\$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
common="\$(git rev-parse --git-common-dir 2>/dev/null)" || exit 0
HARDEN="\${common}/sops-git-filters/harden-permissions.sh"
[ -x "\${HARDEN}" ] || exit 0
"\${HARDEN}" --root "\${root}" --quiet || true
exit 0
EOF
}

# hook_text_2_1 <hook name> <the HARDEN=... line> : the hook that install.sh
# wrote in v2.1.x, byte for byte. It called harden-permissions.sh in the
# working tree. Kept to recognise those files; see is_generated_hook.
hook_text_2_1() {
	cat <<EOF
#!/usr/bin/env bash
${HOOK_MARKER}
#
# $1: git cannot store mode 0600, so a command that writes a
# SOPS-managed file again (through the smudge filter) leaves it with
# the caller's umask (0644 by default). Re-tighten every filter=sops file.
#
# Generated by install.sh — edit harden-permissions.sh, not this file.
# Delete it to opt out; re-running install.sh restores it.
set -u
root="\$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
$2
[ -x "\${HARDEN}" ] || exit 0
"\${HARDEN}" --root "\${root}" --quiet || true
exit 0
EOF
}

# hook_text_until_2_0 <hook name> <the HARDEN=... line> : the hook that
# install.sh wrote from v1.1.0 to v2.0.0, byte for byte. Kept to recognise
# those files; see is_generated_hook.
hook_text_until_2_0() {
	cat <<EOF
#!/usr/bin/env bash
${HOOK_MARKER}
#
# $1: git cannot store mode 0600, so a checkout or merge that
# re-runs the SOPS smudge filter recreates secrets with the caller's
# umask (0644 by default). Re-tighten every filter=sops file.
#
# Generated by install.sh — edit harden-permissions.sh, not this file.
# Delete it to opt out; re-running install.sh restores it.
set -u
root="\$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
$2
[ -x "\${HARDEN}" ] || exit 0
"\${HARDEN}" --root "\${root}" --quiet || true
exit 0
EOF
}

# is_generated_hook <file> <hook name>
# True when <file> is, byte for byte, a hook that this script generated
# (now or in an earlier release) and nobody changed since. In the hooks
# of before v3.0.0 only line 12 may differ, the one that names
# harden-permissions.sh. A symlink, a file with one more line, or a hook
# of another tool that merely mentions sops-git-filters is not one. This
# is the test before a file is removed, and before one is overwritten
# (audit S8). When hook_text changes, its text of today must stay here as
# an earlier release: it is the hook of v3.0.0.
is_generated_hook() {
	local file="$1" name="$2" assign content
	[[ -f "${file}" && ! -L "${file}" ]] || return 1
	content="$(cat "${file}" 2>/dev/null && printf x)" || return 1
	[[ "${content}" != "$(hook_text "${name}" && printf x)" ]] || return 0
	assign="$(sed -n '12p' "${file}" 2>/dev/null)" || return 1
	case "${assign}" in
	HARDEN=*harden-permissions.sh | HARDEN=*harden-permissions.sh\" | HARDEN=*harden-permissions.sh\') ;;
	*) return 1 ;;
	esac
	[[ "${content}" == "$(hook_text_2_1 "${name}" "${assign}" && printf x)" ||
		"${content}" == "$(hook_text_until_2_0 "${name}" "${assign}" && printf x)" ]]
}

# physical_path <path> : <path> with its symlinks resolved. The path need
# not exist: the deepest directory that does is resolved and the rest is
# appended. Fails when that cannot be done by reading names alone (a "."
# or ".." below the last existing directory, a symlink that leads nowhere).
physical_path() {
	local path="$1" rest="" base
	while [[ ! -d "${path}" ]]; do
		[[ ! -L "${path}" ]] || return 1
		base="$(basename -- "${path}")"
		case "${base}" in
		. | .. | /) return 1 ;;
		esac
		rest="/${base}${rest}"
		path="$(dirname -- "${path}")"
	done
	path="$(CDPATH='' cd -- "${path}" 2>/dev/null && pwd -P)" || return 1
	[[ "${path}" != "/" ]] || path=""
	[[ -n "${path}${rest}" ]] || path="/"
	printf '%s\n' "${path}${rest}"
}

# machine_wide_hooks_dirs : the directories that a core.hooksPath in the
# user's or the system's git config names with an absolute path (git
# expands a leading ~), one per line, symlinks resolved. Every repository
# of this user runs its hooks from there. A relative value is not listed:
# git resolves it inside each repository.
machine_wide_hooks_dirs() {
	local value
	{
		git config --global --includes --type=path --get-all core.hooksPath 2>/dev/null || true
		git config --system --includes --type=path --get-all core.hooksPath 2>/dev/null || true
	} | while IFS= read -r value; do
		if sgf_is_absolute "${value}"; then
			physical_path "${value}" || true
		fi
	done
}

GIT_DIR_P="$(CDPATH='' cd -- "$(git -C "${TARGET_ROOT}" rev-parse --absolute-git-dir)" && pwd -P)"

# hooks_dir_is_own <physical path>
# True when a hooks directory belongs to this repository alone: it lies in
# the working tree or in the git directory, and it is not the directory
# that the user's or the system's git config gives to every repository.
# Everything else is shared: a hook written there would run in every
# repository that uses the directory. Up to v2.0.0 that was a way to run
# code of any repository that was cloned (the hook called a script in the
# working tree). The hook of today calls nothing in a working tree, but
# a tool should not write into a directory it shares with others.
hooks_dir_is_own() {
	local dir="$1" wide
	[[ "${dir}" == "${TARGET_ROOT}" || "${dir}" == "${TARGET_ROOT}"/* ||
		"${dir}" == "${GIT_DIR_P}"/* || "${dir}" == "${GIT_COMMON_P}"/* ]] || return 1
	while IFS= read -r wide; do
		[[ "${wide}" != "${dir}" ]] || return 1
	done < <(machine_wide_hooks_dirs)
	return 0
}

# remove_generated_hooks <shared hooks directory>
# Up to v2.0.0 install.sh wrote its hooks into whatever core.hooksPath
# named, a shared directory included, and those hooks ran a script of the
# working tree. Take those files out again, and only those: see
# is_generated_hook.
remove_generated_hooks() {
	local dir="$1" name file
	[[ -d "${dir}" ]] || return 0
	for name in ${HOOK_NAMES}; do
		file="${dir}/${name}"
		[[ -e "${file}" || -L "${file}" ]] || continue
		if is_generated_hook "${file}" "${name}"; then
			if rm -f -- "${file}" 2>/dev/null; then
				echo "Removed ${file}: an earlier install.sh wrote it into this shared hooks directory, where it ran for every repository."
			else
				echo "⚠  Could not remove ${file}. Delete it by hand: an earlier install.sh wrote it" >&2
				echo "   into this shared hooks directory, where it runs for every repository." >&2
			fi
		elif grep -qF "${HOOK_MARKER}" "${file}" 2>/dev/null; then
			echo "⚠  ${file} carries the sops-git-filters marker but is not the file install.sh" >&2
			echo "   wrote (it was changed, or it is a symlink). It is in a shared hooks directory:" >&2
			echo "   take the lines that call harden-permissions.sh out of it by hand." >&2
		fi
	done
}

# core.hooksPath wins over $GIT_DIR/hooks when it is set. It is a pathname
# value, so read it with --type=path (git >= 2.18): git expands a leading
# ~ itself, and without this a "~/.githooks" setting would be treated as a
# relative path inside the repo.
HOOKS_DIR="$(git -C "${TARGET_ROOT}" config --type=path --get core.hooksPath 2>/dev/null || true)"
if [[ -z "${HOOKS_DIR}" ]]; then
	HOOKS_DIR="$(git -C "${TARGET_ROOT}" rev-parse --git-path hooks)"
fi
# C:/... on Windows is absolute too (lib.sh): taken for a relative path,
# a machine-wide ~/.githooks was a directory inside this repository, and
# the hooks went there, where git never runs them.
sgf_is_absolute "${HOOKS_DIR}" || HOOKS_DIR="${TARGET_ROOT}/${HOOKS_DIR}"
HOOKS_DIR_P="$(physical_path "${HOOKS_DIR}" || true)"
HOOKS_DIR_OWN=0
if [[ -n "${HOOKS_DIR_P}" ]] && hooks_dir_is_own "${HOOKS_DIR_P}"; then
	HOOKS_DIR_OWN=1
fi

# ── Take earlier hooks out of shared directories ────
# Every directory a core.hooksPath setting names, in any config file git
# reads here, plus the one in effect. Done on every run, also when the
# hooks are skipped below: these files are a way to run code from any
# repository that is cloned, and this script put them there.
SEEN_HOOKS_DIRS=""
while IFS= read -r candidate; do
	[[ -n "${candidate}" ]] || continue
	sgf_is_absolute "${candidate}" || candidate="${TARGET_ROOT}/${candidate}"
	candidate_p="$(physical_path "${candidate}" || true)"
	[[ -n "${candidate_p}" ]] || continue
	case "${SEEN_HOOKS_DIRS}" in
	*"|${candidate_p}|"*) continue ;;
	esac
	SEEN_HOOKS_DIRS="${SEEN_HOOKS_DIRS}|${candidate_p}|"
	hooks_dir_is_own "${candidate_p}" || remove_generated_hooks "${candidate_p}"
done < <(
	printf '%s\n' "${HOOKS_DIR}"
	git -C "${TARGET_ROOT}" config --type=path --get-all core.hooksPath 2>/dev/null || true
)

# ── Install the hooks ────
if [[ "${SOPS_FILTER_INSTALL_HOOKS:-1}" == "0" ]]; then
	echo "Skipping the permission hooks (SOPS_FILTER_INSTALL_HOOKS=0)."
elif [[ ! -x "${HARDEN_SCRIPT}" ]]; then
	echo "Skipping permission hooks: ${HARDEN_SCRIPT} is missing." >&2
elif [[ "${HOOKS_DIR_OWN}" -eq 0 ]]; then
	# Not this repository's own directory: write nothing, offer the line.
	# It runs the copy under the git directory of whatever repository the
	# hook runs in, and does nothing where install.sh never ran.
	{
		echo "⚠  Git runs the hooks of this repository from a directory that is not its own:"
		echo "     ${HOOKS_DIR}"
		echo "   (core.hooksPath, or a symlinked hooks directory). sops-git-filters does"
		echo "   not write there. Until you add the line below, SOPS-managed files are NOT"
		echo "   set back to 0600 after a checkout, merge, rebase or commit in this"
		echo "   repository (run harden-permissions.sh by hand when it matters)."
		echo "   To get that back, add this line to these hooks in that directory:"
		echo "     ${HOOK_NAMES}"
		echo "   It runs the copy that install.sh put under .git/, in every repository"
		echo "   where install.sh ran, and does nothing anywhere else:"
		# shellcheck disable=SC2016  # printed for the user to paste
		echo '     h="$(git rev-parse --git-common-dir 2>/dev/null)/sops-git-filters/harden-permissions.sh"; [ -x "$h" ] && "$h" --quiet || true'
	} >&2
else
	# A hook of this tool or of somebody else? The line for somebody
	# else's hook is the same in every repository.
	# shellcheck disable=SC2016  # printed for the user to paste
	HARDEN_HINT='"$(git rev-parse --git-common-dir)"/sops-git-filters/harden-permissions.sh'

	mkdir -p "${HOOKS_DIR}"
	installed_hooks=""
	foreign_hooks=""
	changed_hooks=""
	for hook_name in ${HOOK_NAMES}; do
		hook_path="${HOOKS_DIR}/${hook_name}"

		# Never clobber a hook this tool did not write: pre-commit, prek,
		# husky and hand-rolled hooks all live here. A symlink is never
		# written through either: its target can be a file outside this
		# repository.
		if [[ -L "${hook_path}" ]] ||
			{ [[ -e "${hook_path}" ]] && ! grep -qF "${HOOK_MARKER}" "${hook_path}" 2>/dev/null; }; then
			foreign_hooks="${foreign_hooks} ${hook_name}"
			continue
		fi
		# Nor one it wrote that was changed since. The marker line alone
		# does not make a hook replaceable: only a file that is, byte for
		# byte, a hook of this script (now or in an earlier release), the
		# same test as before a hook is taken out of a shared directory
		# (audit S8). Lines a user added stay.
		if [[ -e "${hook_path}" ]] && ! is_generated_hook "${hook_path}" "${hook_name}"; then
			changed_hooks="${changed_hooks} ${hook_name}"
			continue
		fi

		hook_text "${hook_name}" >"${hook_path}"
		chmod +x "${hook_path}"
		installed_hooks="${installed_hooks} ${hook_name}"
	done
	if [[ -n "${installed_hooks}" ]]; then
		echo "Installed the permission hooks (they set SOPS-managed files back to 0600):${installed_hooks}"
	fi
	if [[ -n "${foreign_hooks}" ]]; then
		echo "⚠  These hooks exist and are not managed by sops-git-filters:${foreign_hooks}" >&2
		echo "   Not overwriting. Add this line to each of them by hand:" >&2
		echo "     ${HARDEN_HINT} --quiet || true" >&2
	fi
	if [[ -n "${changed_hooks}" ]]; then
		echo "⚠  These hooks carry the sops-git-filters marker but were changed by hand:${changed_hooks}" >&2
		echo "   They differ from every hook install.sh wrote, so they are not overwritten." >&2
		echo "   Make sure each of them runs this line, or delete it and re-run this script:" >&2
		echo "     ${HARDEN_HINT} --quiet || true" >&2
	fi
fi

# ── Report files that need attention ────
# Last, so it is the final thing on screen, and with its own exit status
# so a setup script notices: the filters are installed, but something is
# left to do.
ATTENTION=0

if [[ -n "${OTHER_FORMAT_IN_GIT}" ]]; then
	{
		echo ""
		echo "========================================================"
		echo " STORED IN THE OTHER FORMAT"
		echo "========================================================"
		echo ""
		echo " .sops-filter.conf says ${STORE_FORMAT}, but the index holds these files"
		echo " as ${OTHER_FORMAT} (encrypted, in the other format):"
		echo ""
		printf '%s' "${OTHER_FORMAT_IN_GIT}"
		echo ""
		echo " To finish the format change, re-encrypt them and commit:"
		echo "   SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- <files>"
		echo "========================================================"
	} >&2
	ATTENTION=1
fi

# These secrets are readable by anyone who can read the repository.
if [[ -n "${PLAINTEXT_IN_GIT}" ]]; then
	{
		echo ""
		echo "========================================================"
		echo " NOT ENCRYPTED IN GIT"
		echo "========================================================"
		echo ""
		echo " These files have filter=sops in .gitattributes, but the version"
		echo " git holds is not an encrypted SOPS document (format: ${STORE_FORMAT})."
		echo " They were committed before the filter existed, or from a clone"
		echo " that never ran install.sh:"
		echo ""
		printf '%s' "${PLAINTEXT_IN_GIT}"
		echo ""
		echo " In brackets: what the check found. If that is a key sops does not"
		echo " write and your sops is newer than this tool, the file is encrypted"
		echo " and this tool is out of date: update sops-git-filters."
		echo ""
		echo " To fix:"
		echo "   1. Encrypt them:  git add --renormalize -- <file>   then commit."
		echo "   2. Rotate those secrets. The plaintext stays in the history of"
		echo "      every clone and of the remote."
		echo "========================================================"
	} >&2
	ATTENTION=1
fi

# The working copy of these files is still ciphertext.
if [[ -n "${STILL_ENCRYPTED}" ]]; then
	{
		echo ""
		echo "========================================================"
		echo " STILL ENCRYPTED IN THE WORKING TREE"
		echo "========================================================"
		echo ""
		echo " The filters and hooks are installed, but sops could not decrypt"
		echo " these files (its message for the first one is above), so their"
		echo " working copy still holds ciphertext:"
		echo ""
		printf '%s' "${STILL_ENCRYPTED}"
		echo ""
		echo " Make your keys or credentials available and re-run this script:"
		# shellcheck disable=SC2086  # one word per key type
		sgf_credential_hint "   " ${STILL_ENCRYPTED_KEY_TYPES}
		echo " Until then git sees those files as unchanged, and nothing is"
		echo " encrypted a second time, as long as each holds what the index"
		echo " holds. A command that moves only the index (git reset HEAD~1,"
		echo " git reset <commit> -- <file>, git restore --staged) ends that:"
		echo " git status, git add and git commit -a then fail on such a file"
		echo " until your keys are back. Without them, put the version git holds"
		echo " in its place with the git cat-file line that error prints."
		echo "========================================================"
	} >&2
	ATTENTION=1
fi

# The working copy of these files is still ciphertext too, on purpose.
if [[ -n "${THROUGH_A_LINK}" ]]; then
	{
		echo ""
		echo "========================================================"
		echo " NOT DECRYPTED: REACHED THROUGH A LINK"
		echo "========================================================"
		echo ""
		echo " The working copy of these files holds the ciphertext git holds,"
		echo " but it is a symbolic link, lies in a directory that is one, or"
		echo " has a second name (a hard link). The plaintext would land where"
		echo " the link leads, maybe outside this working tree, so they were"
		echo " left encrypted:"
		echo ""
		printf '%s' "${THROUGH_A_LINK}"
		echo ""
		echo " Git does not write through a symbolic link either: git status"
		echo " lists such a path as deleted or as a type change. Put the file"
		echo " itself in its place (for a hard link: a copy), or the directory"
		echo " itself instead of the link, and re-run this script."
		echo "========================================================"
	} >&2
	ATTENTION=1
fi

# Decrypted fine, but the content cannot pass through this tool.
if [[ -n "${HOLDS_NUL_BYTES}" ]]; then
	{
		echo ""
		echo "========================================================"
		echo " NUL BYTES IN THE CONTENT"
		echo "========================================================"
		echo ""
		echo " The stored version of these files decrypts to content with NUL"
		echo " bytes (binary data, or UTF-16 text). sops-git-filters handles"
		echo " text files only, so their working copy was left as ciphertext"
		echo " instead of being written damaged:"
		echo ""
		printf '%s' "${HOLDS_NUL_BYTES}"
		echo ""
		echo " Store such a secret in a text form (base64, PEM, UTF-8), or take"
		echo " filter=sops off its path and encrypt it with sops by hand."
		echo "========================================================"
	} >&2
	ATTENTION=1
fi

[[ "${ATTENTION}" -eq 0 ]] || exit 3

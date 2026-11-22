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
# ║  Four git mechanisms are used:                                   ║
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
# ║  4. merge.sops.driver    (merge / rebase / cherry-pick / stash)  ║
# ║     For paths with merge=sops in .gitattributes: merges the      ║
# ║     plaintext of the three versions (merge-driver.sh) instead    ║
# ║     of letting git merge ciphertext, which cannot work.          ║
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
# ║  every filter=sops file to 0600 (SOPS_FILE_MODE overrides; a     ║
# ║  100755 file keeps its owner execute bit, 0700), and five hooks  ║
# ║  are installed so that later git commands do the same:           ║
# ║  post-checkout, post-merge, post-rewrite, post-applypatch and    ║
# ║  post-commit. Set SOPS_FILTER_INSTALL_HOOKS=0 to skip them.      ║
# ║                                                                  ║
# ║  The hooks are written into this repository's own hooks          ║
# ║  directory only. When core.hooksPath names a directory that      ║
# ║  other repositories use too, nothing is written there (a hook    ║
# ║  in it runs for every one of them); the line to add by hand is   ║
# ║  printed instead. Hooks that an older install.sh wrote into      ║
# ║  such a directory are removed.                                   ║
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
# ║    1  nothing was installed (not a repo, sops missing or too     ║
# ║       old, bad .sops-filter.conf, conflicting git config)        ║
# ║    3  filters and hooks are in place, but files need attention:  ║
# ║       tracked in plaintext, still stored in the other storage    ║
# ║       format, not decrypted because sops could not (keys or      ║
# ║       credentials missing), or holding NUL bytes. See the lists  ║
# ║       printed at the end.                                        ║
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
HARDEN_SCRIPT="${SCRIPT_DIR}/harden-permissions.sh"

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
if git -C "${TARGET_ROOT}" config --get-regexp '^filter\.sops\.(clean|smudge)$' >/dev/null 2>&1; then
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

if ! command -v sops >/dev/null 2>&1; then
	echo "Error: sops not found on PATH. Install it first (mise/brew/apt)." >&2
	exit 1
fi

# ── Minimum sops version ────
# Older releases can store a file in clear inside a SOPS envelope (see
# SGF_MIN_SOPS_VERSION in lib.sh). clean-filter.sh would refuse such a
# result, so nothing leaks — but every `git add` would fail. Say so now.
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

# ── Compose the filter commands ────
# shell_quote <path> : <path> as one shell word. Git runs the filter and
# merge commands through sh, and the hooks below are shell scripts, so a
# space, a ';' or a '$(...)' in a directory name must reach them quoted.
# POSIX single quotes, not printf %q: under LC_ALL=C, %q writes a non-ASCII
# name as $'...', which dash (/bin/sh on Debian and Ubuntu) does not know.
# A path of only [A-Za-z0-9_./+-] is left as it is.
shell_quote() {
	case "$1" in
	'' | *[!A-Za-z0-9_./+-]*) ;;
	*)
		printf '%s' "$1"
		return
		;;
	esac
	local sq="'" esc="'\\''"
	printf "'%s'" "${1//${sq}/${esc}}"
}

# Prefer a REPO-RELATIVE path for the clean filter: git runs filters
# from the top level of the working tree, and a relative path keeps
# working when the repository directory is moved or renamed (an
# absolute path in .git/config silently breaks on the next move).
if [[ "${SCRIPT_DIR}" == "${TARGET_ROOT}"/* ]]; then
	TOOL_DIR_Q="$(shell_quote "${SCRIPT_DIR#"${TARGET_ROOT}"/}")"
else
	TOOL_DIR_Q="$(shell_quote "${SCRIPT_DIR}")"
	echo "⚠  sops-git-filters lives outside the target repo — using an absolute" >&2
	echo "   path in .git/config. It will break if either directory moves." >&2
	echo "   Consider vendoring or adding it as a submodule inside the repo." >&2
fi
# Git reads %<letter> in these commands as a placeholder: a literal % is %%.
TOOL_DIR_Q="${TOOL_DIR_Q//\%/%%}"
CLEAN_CMD="${TOOL_DIR_Q}/clean-filter.sh %f"
MERGE_CMD="${TOOL_DIR_Q}/merge-driver.sh %O %A %B %L %P"

SMUDGE_CMD="sops decrypt ${DECRYPT_ARGS} --filename-override %f /dev/stdin"
# textconv = cat is NOT a mistake. Git materializes textconv temp files
# through convert_to_working_tree(), i.e. the smudge filter runs FIRST
# and textconv already receives decrypted plaintext. Without a textconv
# driver git diffs the raw blobs instead (ciphertext gibberish) — so
# `cat` is exactly the switch that flips diffs to the smudged path.
# (A `sops decrypt` textconv double-decrypts and errors on plaintext.)
TEXTCONV_CMD="cat"

# ── Configure git (local to the target repo only) ────
git_cfg() { git -C "${TARGET_ROOT}" config --local "$@"; }
# The value git will really use: a worktree-level or included config can
# override .git/config.
git_effective() { git -C "${TARGET_ROOT}" config "$@" 2>/dev/null || true; }

# required=true: fail the operation if the filter fails — never silently
# commit plaintext because sops or the script is broken. Written FIRST
# and on EVERY run, outside the "already configured" test below: with
# the two commands in place and this flag missing, git treats a failing
# filter as no filter at all and stages the plaintext. (An existing
# setup already got it further up, before the checks that can exit.)
git_cfg filter.sops.required true

# filter.<driver>.process (a long-running filter) wins over clean/smudge.
# One left behind by another tool under the same driver name would bypass
# clean-filter.sh completely.
if git_cfg --get filter.sops.process >/dev/null 2>&1; then
	git_cfg --unset-all filter.sops.process
	echo "Removed filter.sops.process from .git/config (it overrides the clean/smudge filters)."
fi
if [[ -n "$(git_effective --get filter.sops.process)" ]]; then
	echo "Error: filter.sops.process is set outside this repository's .git/config:" >&2
	git -C "${TARGET_ROOT}" config --show-origin --get-all filter.sops.process >&2 || true
	echo "Git prefers it over the clean/smudge filters, so clean-filter.sh would never run." >&2
	echo "Remove that setting and re-run this script." >&2
	exit 1
fi

# Idempotency: compare the SMUDGE command, not just the clean path —
# the clean path is stable across storage-format migrations, so
# comparing only it would skip smudge/textconv updates on existing
# clones when the format changes.
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

# Last check: what was just written must be what git will use.
if [[ "$(git_effective --bool --get filter.sops.required)" != "true" ||
	"$(git_effective --get filter.sops.clean)" != "${CLEAN_CMD}" ||
	"$(git_effective --get filter.sops.smudge)" != "${SMUDGE_CMD}" ]]; then
	echo "Error: another git config file overrides the filter settings written to .git/config:" >&2
	git -C "${TARGET_ROOT}" config --show-origin --get-regexp '^filter\.sops\.' >&2 || true
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
# them in place — but ONLY when the working copy is byte-identical to
# the blob in the index (proof the smudge never ran and there are no
# local edits to lose).
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
while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
	[[ "${attr}" == "filter" && "${value}" == "sops" ]] || continue
	FOUND_ANY=1
	f="${TARGET_ROOT}/${path}"

	# "<mode> <object id>" of the index entry. GIT_LITERAL_PATHSPECS: the
	# path is a file name here, not a pattern.
	index_entry=$(GIT_LITERAL_PATHSPECS=1 git -C "${TARGET_ROOT}" ls-files -s -- "${path}" | awk 'NR == 1 {print $1, $2}')
	index_mode="${index_entry%% *}"
	index_sha="${index_entry#* }"
	[[ -n "${index_sha}" ]] || continue
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
	worktree_sha=$(git hash-object --no-filters -- "${f}")
	[[ "${worktree_sha}" == "${index_sha}" ]] || continue

	# Working copy == stored ciphertext → smudge never ran. Decrypt it.
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
		sops decrypt ${DECRYPT_ARGS} --filename-override "${path}" /dev/stdin 2>"${decrypt_stderr}" |
		sgf_cat_counting_nuls) && sgf_split_counted; then
		if [[ "${SGF_NUL_COUNT}" != "0" ]]; then
			HOLDS_NUL_BYTES="${HOLDS_NUL_BYTES}   - ${path}"$'\n'
			continue
		fi
		printf '%s' "${SGF_CONTENT}" >"${f}"
		# The write above bypassed git, so the index's cached stat still
		# describes the ciphertext checkout — and git flags size deltas
		# as "modified" without consulting filters. update-index re-runs
		# the clean filter (which reuses the identical blob) and records
		# fresh stat data, so `git status` is clean again.
		git -C "${TARGET_ROOT}" update-index -- "${path}" 2>/dev/null ||
			echo "⚠  Could not refresh index stat for ${path}; run: git add ${path}" >&2
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
# The hooks are deliberately NOT the place for any other logic: they call
# harden-permissions.sh from the checkout, so updating the tool updates
# the behaviour without re-running install.sh.
HOOK_MARKER="# managed by sops-git-filters (secret file permissions)"
HOOK_NAMES="post-checkout post-merge post-rewrite post-applypatch post-commit"

# hook_text <hook name> <the HARDEN=... line> : the hook this script writes
hook_text() {
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
# (now or in an earlier release) and nobody changed since. Only line 12
# may differ, the one that names harden-permissions.sh. A symlink, a file
# with one more line, or a hook of another tool that merely mentions
# sops-git-filters is not one. This is the test before a file is removed.
is_generated_hook() {
	local file="$1" name="$2" assign content
	[[ -f "${file}" && ! -L "${file}" ]] || return 1
	assign="$(sed -n '12p' "${file}" 2>/dev/null)" || return 1
	case "${assign}" in
	HARDEN=*harden-permissions.sh | HARDEN=*harden-permissions.sh\" | HARDEN=*harden-permissions.sh\') ;;
	*) return 1 ;;
	esac
	content="$(cat "${file}" 2>/dev/null && printf x)" || return 1
	[[ "${content}" == "$(hook_text "${name}" "${assign}" && printf x)" ||
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
		case "${value}" in
		/*) physical_path "${value}" || true ;;
		esac
	done
}

GIT_DIR_P="$(CDPATH='' cd -- "$(git -C "${TARGET_ROOT}" rev-parse --absolute-git-dir)" && pwd -P)"
GIT_COMMON_P="$(CDPATH='' cd -- "${TARGET_ROOT}" && CDPATH='' cd -- "$(git rev-parse --git-common-dir)" && pwd -P)"

# hooks_dir_is_own <physical path>
# True when a hooks directory belongs to this repository alone: it lies in
# the working tree or in the git directory, and it is not the directory
# that the user's or the system's git config gives to every repository.
# Everything else is shared: a hook written there would run in every
# repository that uses the directory, and the hook calls a script by its
# path inside the repository it runs in. Cloning any repository that
# ships a file at that path would then execute it.
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
# named, a shared directory included. Take those files out again, and
# only those: see is_generated_hook.
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
case "${HOOKS_DIR}" in
/*) ;;
*) HOOKS_DIR="${TARGET_ROOT}/${HOOKS_DIR}" ;;
esac
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
	case "${candidate}" in
	/*) ;;
	*) candidate="${TARGET_ROOT}/${candidate}" ;;
	esac
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
	# Not this repository's own directory: write nothing. The line offered
	# instead names this working tree by its absolute path, so in a hook
	# that every repository runs it does something in this one only.
	# (shell_quote leaves a plain path bare, which is fine in both places.)
	ROOT_Q="$(shell_quote "${TARGET_ROOT}")"
	{
		echo "⚠  Git runs the hooks of this repository from a directory that is not its own:"
		echo "     ${HOOKS_DIR}"
		echo "   (core.hooksPath, or a symlinked hooks directory). A hook written there would"
		echo "   run in every repository that uses the directory, so sops-git-filters does"
		echo "   not write there. Until you add the line below, SOPS-managed files are NOT"
		echo "   set back to 0600 after a checkout, merge, rebase or commit in this"
		echo "   repository (run harden-permissions.sh by hand when it matters)."
		echo "   To get that back, add this line to these hooks in that directory:"
		echo "     ${HOOK_NAMES}"
		echo "   It acts in this working tree only, whichever repository runs the hook:"
		# shellcheck disable=SC2016  # printed for the user to paste
		echo '     [ "$(git rev-parse --show-toplevel 2>/dev/null)" = '"${ROOT_Q}"' ] && '"$(shell_quote "${HARDEN_SCRIPT}") --root ${ROOT_Q} --quiet || true"
	} >&2
else
	# Prefer a repo-relative reference for the same reason the clean
	# filter does: an absolute path breaks silently when the repo moves.
	# The path is quoted for the shell (shell_quote): inside double quotes
	# a '$(...)' in a directory name would run at every checkout.
	if [[ "${SCRIPT_DIR}" == "${TARGET_ROOT}"/* ]]; then
		HARDEN_REL_Q="$(shell_quote "${SCRIPT_DIR#"${TARGET_ROOT}"/}/harden-permissions.sh")"
		# shellcheck disable=SC2016  # $root must reach the hook unexpanded
		HOOK_HARDEN_ASSIGN='HARDEN="$root"/'"${HARDEN_REL_Q}"
		# shellcheck disable=SC2016  # printed for the user to paste
		HARDEN_HINT='"$(git rev-parse --show-toplevel)"/'"${HARDEN_REL_Q}"
	else
		HOOK_HARDEN_ASSIGN="HARDEN=$(shell_quote "${HARDEN_SCRIPT}")"
		HARDEN_HINT="$(shell_quote "${HARDEN_SCRIPT}")"
	fi

	mkdir -p "${HOOKS_DIR}"
	installed_hooks=""
	foreign_hooks=""
	for hook_name in ${HOOK_NAMES}; do
		hook_path="${HOOKS_DIR}/${hook_name}"

		# Never clobber a hook this tool did not write — pre-commit, prek,
		# husky and hand-rolled hooks all live here. A symlink is never
		# written through either: its target can be a file outside this
		# repository.
		if [[ -L "${hook_path}" ]] ||
			{ [[ -e "${hook_path}" ]] && ! grep -qF "${HOOK_MARKER}" "${hook_path}" 2>/dev/null; }; then
			foreign_hooks="${foreign_hooks} ${hook_name}"
			continue
		fi

		hook_text "${hook_name}" "${HOOK_HARDEN_ASSIGN}" >"${hook_path}"
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
		echo " encrypted a second time."
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

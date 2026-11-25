#!/usr/bin/env bash
# Helpers for the test files. Sourced by tests/run.sh.
# shellcheck disable=SC2034  # variables here are used by the test files

# Where the tool lives inside every test repository (the submodule /
# vendored layout the README recommends).
TOOL=utilities/sops-git-filters

# ── One-time setup: throwaway keys and git identity ────
sgf_test_setup() {
	age-keygen -o "${SGF_TEST_ROOT}/keys/a.txt" 2>/dev/null
	age-keygen -o "${SGF_TEST_ROOT}/keys/b.txt" 2>/dev/null
	AGE_PUB_A="$(age-keygen -y "${SGF_TEST_ROOT}/keys/a.txt")"
	AGE_PUB_B="$(age-keygen -y "${SGF_TEST_ROOT}/keys/b.txt")"
	AGE_KEY_B="${SGF_TEST_ROOT}/keys/b.txt"
	NO_KEY="${SGF_TEST_ROOT}/keys/does-not-exist.txt"

	git config --global user.name "Test"
	git config --global user.email "test@example.invalid"
	git config --global init.defaultBranch main
	git config --global commit.gpgsign false
	git config --global advice.detachedHead false
}

# ── Assertions (a failed assertion ends the test) ────
# The output of the last `run` goes to the log too: on a CI runner it is
# all there is to see.
fail() {
	echo "ASSERTION FAILED: $*" >&2
	if [[ -n "${OUT:-}" ]]; then
		echo "output of the last command run (RC=${RC:-}):" >&2
		printf '%s\n' "${OUT}" | sed 's/^/  > /' >&2
	fi
	exit 1
}

# skip <reason> : end the test without counting it as passed or failed
skip() {
	echo "$*"
	exit 77
}

assert_eq() { # <actual> <expected> [what]
	[[ "$1" == "$2" ]] || fail "${3:-value}: expected [$2], got [$1]"
}

assert_ne() { # <actual> <unexpected> [what]
	[[ "$1" != "$2" ]] || fail "${3:-value}: must not be [$2]"
}

assert_contains() { # <text> <needle> [what]
	case "$1" in
	*"$2"*) ;;
	*) fail "${3:-text}: [$2] not found in [${1:0:600}]" ;;
	esac
}

assert_not_contains() { # <text> <needle> [what]
	case "$1" in
	*"$2"*) fail "${3:-text}: [$2] must not appear" ;;
	*) ;;
	esac
}

# run <command...> : never fails; sets OUT (stdout+stderr) and RC
run() {
	RC=0
	OUT="$("$@" 2>&1)" || RC=$?
}

# ── Repository helpers ────
vendor_tool() {
	mkdir -p "${TOOL}"
	cp "${SGF_TOOL_DIR}"/*.sh "${TOOL}/"
	chmod +x "${TOOL}"/*.sh
}

# write_sops_yaml [extra age recipient...] : catch-all rule, key A first
# shellcheck disable=SC2120  # the extra recipients are optional
write_sops_yaml() {
	{
		printf 'creation_rules:\n  - path_regex: .*\n    key_groups:\n      - age:\n'
		printf '          - %s\n' "${AGE_PUB_A}" "$@"
	} >.sops.yaml
}

# git_init <dir> : a new repository whose first branch is main. Not only
# through init.defaultBranch (sgf_test_setup): that came with git 2.28,
# and older git names the branch master.
git_init() {
	git init -q "$1"
	git -C "$1" symbolic-ref HEAD refs/heads/main
}

# git_at_least <major.minor> : true when the git on PATH is that version
# or newer. For a test of a git feature that came with that version.
git_at_least() {
	git --version | awk -v want="$1" '{
		split($3, have, ".")
		split(want, w, ".")
		exit !(have[1] + 0 > w[1] + 0 || (have[1] + 0 == w[1] + 0 && have[2] + 0 >= w[2] + 0))
	}'
}

# env_with_config <key> <value> <command...> : env <command...> with
# <key>=<value> in git's config for that run only, from the environment
# as `git -c` gives it: GIT_CONFIG_COUNT (git 2.31 and later), else
# GIT_CONFIG_PARAMETERS, which `git -c` sets and every git reads.
env_with_config() {
	local key="$1" value="$2"
	shift 2
	if git_at_least 2.31; then
		env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="${key}" GIT_CONFIG_VALUE_0="${value}" "$@"
	else
		env GIT_CONFIG_PARAMETERS="'${key}=${value}'" "$@"
	fi
}

# merge_driver_needs_ort [stash] : skip the rest of the test with a git
# that merges with its "recursive" strategy: git merge, rebase and
# cherry-pick before 2.34, git stash pop before 2.37 ("stash"). That
# strategy runs the clean filter on the file the merge driver merged and
# aborts the merge when the result is not the blob the driver handed
# back, and a secret encrypted again never is: "add_cacheinfo failed to
# refresh". The "ort" strategy, the default since, does not. README,
# Requirements.
merge_driver_needs_ort() {
	local version
	version="$(git --version | awk '{print $3}')"
	if [[ "${1:-}" == "stash" ]]; then
		git_at_least 2.37 || skip "git ${version} pops a stash with the recursive strategy, which cannot take a secret the merge driver merged (git 2.37 or later)"
	else
		git_at_least 2.34 || skip "git ${version} merges with the recursive strategy, which cannot take a secret the merge driver merged (git 2.34 or later)"
	fi
}

# new_repo <dir> [json|dotenv] : create a configured repository and cd into it
new_repo() {
	local dir="$1" format="${2:-json}"
	git_init "${dir}"
	cd "${dir}" || exit 1
	vendor_tool
	# shellcheck disable=SC2119  # no extra recipients here
	write_sops_yaml
	printf '.env filter=sops diff=sops\n*.secret filter=sops diff=sops\n' >.gitattributes
	if [[ "${format}" != "json" ]]; then
		printf 'SOPS_STORE_FORMAT=%s\n' "${format}" >.sops-filter.conf
	fi
	git add -A
	git commit -q -m scaffold
	"${TOOL}/install.sh"
}

# fresh_clone <source-dir> <new-dir> : clone WITHOUT running install.sh, cd into it
fresh_clone() {
	git clone -q "$1" "$2"
	cd "$2" || exit 1
}

# path_with_only <dir> <command...> : link the named commands into <dir>
# and print its path. As PATH it hides every other command (sops, say).
# Where ln -s makes no symlink (Git Bash on Windows) a script that runs
# the command takes its place: a copy of git.exe or bash.exe does not
# find the DLLs next to the original.
path_with_only() {
	local dir="$1" cmd links=1
	shift
	mkdir -p "${dir}"
	symlinks_work || links=0
	for cmd in "$@"; do
		if [[ "${links}" -eq 1 ]]; then
			ln -sf "$(command -v "${cmd}")" "${dir}/${cmd}"
		else
			printf '#!/bin/sh\nexec '\''%s'\'' "$@"\n' "$(command -v "${cmd}")" >"${dir}/${cmd}"
			chmod +x "${dir}/${cmd}"
		fi
	done
	(CDPATH='' cd -- "${dir}" && pwd)
}

# path_without <dir> <command...> : link every command on PATH into <dir>
# except the ones named, and print its path. As PATH it is the same PATH
# without those commands (the first of each name wins, as for PATH).
path_without() {
	local dir="$1" entry IFS=:
	shift
	mkdir -p "${dir}"
	for entry in ${PATH}; do
		[[ -d "${entry}" ]] || continue
		# One ln per directory; names that are already there fail and stay.
		ln -s "${entry}"/* "${dir}/" 2>/dev/null || true
	done
	for entry in "$@"; do
		rm -f "${dir:?}/${entry}"
	done
	(CDPATH='' cd -- "${dir}" && pwd)
}

# stored <path> : the blob git holds for <path> in the index
stored() {
	git cat-file blob "$(git ls-files -s -- "$1" | awk '{print $2}')"
}

# plain_of_stored <path> [format] : decrypt the index blob of <path>
plain_of_stored() {
	if [[ "${2:-json}" == "dotenv" ]]; then
		stored "$1" | sops decrypt --input-type dotenv --output-type dotenv
	else
		stored "$1" | sops decrypt --input-type json --output-type binary
	fi
}

# swap <old> <new>   (text on stdin) : the first <old> becomes <new>, as text
swap() {
	awk -v old="$1" -v new="$2" '!done && (i = index($0, old)) {
		$0 = substr($0, 1, i - 1) new substr($0, i + length(old))
		done = 1
	}
	{ print }'
}

blob_id() { # <path> : object id of the index entry
	git ls-files -s -- "$1" | awk '{print $2}'
}

# stub <dir> <command> : write an executable stand-in for <command> into
# <dir>; the script body comes from stdin. REAL holds the real command.
stub() {
	mkdir -p "$1"
	{
		printf '#!/usr/bin/env bash\nREAL=%q\n' "$(command -v "$2")"
		cat
	} >"$1/$2"
	chmod +x "$1/$2"
}

# installed_dir : where install.sh puts the copy of the scripts git runs
installed_dir() {
	printf '%s/sops-git-filters\n' "$(CDPATH='' cd -- "$(git rev-parse --git-common-dir)" && pwd -P)"
}

# installed_source : the checkout of the tool, as install.sh recorded it
installed_source() {
	sed -n 's/^source=//p' "$(installed_dir)/INSTALLED"
}

# The filter commands install.sh writes: the same in every repository.
# shellcheck disable=SC2016  # the command substitution belongs to git's shell
INSTALLED_CMD_PREFIX='"$(git rev-parse --git-common-dir)"/sops-git-filters'

# mode_of <file> : permission bits as octal digits (GNU and BSD stat)
mode_of() {
	stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"
}

# ── What the file system can hold ────
# Git Bash on Windows (NTFS) keeps no Unix file modes, makes no symbolic
# links (ln -s copies the target, or fails when there is none) and takes
# no file name with a colon, a backslash or a control character. A test
# of such a feature asks first and skips itself where it is missing;
# tests/run.sh lets the Windows job skip exactly those (SGF_ALLOW_SKIP).

# file_modes_work : true when chmod 600 leaves a file at mode 600
file_modes_work() {
	local f rc=0
	f="$(mktemp)"
	chmod 600 "${f}"
	[[ "$(mode_of "${f}")" == "600" ]] || rc=1
	rm -f "${f}"
	return "${rc}"
}

# needs_file_modes : skip the rest of the test where file_modes_work fails
needs_file_modes() {
	file_modes_work || skip "this file system keeps no Unix file modes (chmod 600 changes nothing)"
}

# assert_mode <file> <mode> <what> : the mode of <file>, where the file
# system keeps modes. Where it keeps none there is no mode to check: the
# tests of harden-permissions.sh skip themselves there, and a test of
# something else (a worktree, a merge) goes on.
assert_mode() {
	file_modes_work || return 0
	assert_eq "$(mode_of "$1")" "$2" "$3"
}

# symlinks_work : true when ln -s makes a symbolic link
symlinks_work() {
	local dir rc=0
	dir="$(mktemp -d)"
	{ ln -s target "${dir}/link" && [[ -L "${dir}/link" ]]; } 2>/dev/null || rc=1
	rm -f "${dir}/link"
	rmdir "${dir}"
	return "${rc}"
}

# needs_symlinks : skip the rest of the test where symlinks_work fails
needs_symlinks() {
	symlinks_work || skip "this system makes no symbolic links (ln -s)"
}

# guard_hook : encryption-guard.sh as the pre-commit hook of the
# repository at hand: a symlink, as the README says. Where ln -s makes
# none (Git Bash on Windows), a hook that runs it, as the README says
# for Windows.
guard_hook() {
	mkdir -p .git/hooks
	if symlinks_work; then
		ln -s "../../${TOOL}/encryption-guard.sh" .git/hooks/pre-commit
	else
		printf '#!/bin/sh\nexec %s/encryption-guard.sh\n' "${TOOL}" >.git/hooks/pre-commit
		chmod +x .git/hooks/pre-commit
	fi
}

# file_system_takes <name...> : sort the names into TAKEN and REFUSED:
# can a file of that name be made here, and does git list it under that
# very name? Git Bash on Windows makes a file for a name with a colon,
# but under another name (the colon becomes a private-use character).
TAKEN=()
REFUSED=()
file_system_takes() {
	local dir name
	TAKEN=()
	REFUSED=()
	dir="$(mktemp -d)"
	git init -q "${dir}"
	for name in "$@"; do
		if (cd "${dir}" && printf 'x\n' >"./${name}") 2>/dev/null &&
			[[ "$(git -C "${dir}" ls-files -o -z -- ":(literal)${name}" 2>/dev/null | tr '\0' '/')" == "${name}/" ]]; then
			TAKEN+=("${name}")
		else
			REFUSED+=("${name}")
		fi
	done
	rm -rf "${dir}"
}

# index_takes <name...> : the same for an index entry alone, with no
# file: git for Windows refuses a name NTFS cannot hold even there
# (core.protectNTFS), and a name that is not UTF-8 reaches it as another
# one (Windows passes the arguments of a program as UTF-16).
index_takes() {
	local dir name oid
	TAKEN=()
	REFUSED=()
	dir="$(mktemp -d)"
	git init -q "${dir}"
	oid="$(printf 'x\n' | git -C "${dir}" hash-object -w --stdin)"
	for name in "$@"; do
		if git -C "${dir}" update-index --add --cacheinfo "100644,${oid},${name}" 2>/dev/null &&
			[[ "$(git -C "${dir}" ls-files -z -- ":(literal)${name}" 2>/dev/null | tr '\0' '/')" == "${name}/" ]]; then
			TAKEN+=("${name}")
		else
			REFUSED+=("${name}")
		fi
	done
	rm -rf "${dir}"
}

# needs_file_name <name> : skip the rest of the test where the file
# system does not take that name (file_system_takes)
needs_file_name() {
	file_system_takes "$1"
	[[ ${#REFUSED[@]} -eq 0 ]] || skip "this file system takes no file named $(printf '%q' "$1")"
}

# skip_if_refused : at the end of a test that ran with the names the file
# system takes, skip if it refused any (the others passed)
skip_if_refused() {
	[[ ${#REFUSED[@]} -eq 0 ]] || skip "this file system takes no file named $(printf '%q ' "${REFUSED[@]}")(the other names passed)"
}

# add_index_entries <count> : put <count> more files into the index, the
# way a large repository has them: filler/dNNN/fNNNNNN.txt, spread over
# 300 directories, all with the same small blob. Only the index gets
# them, no file is written to disk: enough for what lists the index.
add_index_entries() {
	local oid
	oid="$(printf 'filler\n' | git hash-object -w --stdin)"
	awk -v n="$1" -v oid="${oid}" 'BEGIN {
		for (i = 0; i < n; i++) printf "100644 %s\tfiller/d%03d/f%06d.txt\n", oid, i % 300, i
	}' | git update-index --index-info
}

# timed <command...> : never fails; runs the command with its output
# discarded, sets RC and SECS (wall-clock seconds, e.g. 0.123)
timed() {
	local TIMEFORMAT=%R
	RC=0
	SECS="$({ time "$@" >/dev/null 2>&1; } 2>&1)" || RC=$?
}

# faster_than <seconds> <limit> : true when <seconds> < <limit>
faster_than() {
	awk -v s="$1" -v limit="$2" 'BEGIN { exit !(s + 0 < limit + 0) }'
}

# ── Hooks that earlier releases wrote ────
# old_hook <hook name> <the HARDEN line> : the hook file as install.sh
# wrote it from v1.1.0 to v2.0.0, byte for byte
old_hook() {
	cat <<EOF_HOOK
#!/usr/bin/env bash
# managed by sops-git-filters (secret file permissions)
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
EOF_HOOK
}

# hook_of_2_1 <hook name> <the HARDEN line> : the hook file as install.sh
# wrote it in v2.1.x, byte for byte
hook_of_2_1() {
	cat <<EOF_HOOK
#!/usr/bin/env bash
# managed by sops-git-filters (secret file permissions)
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
EOF_HOOK
}

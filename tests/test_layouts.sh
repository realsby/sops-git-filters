#!/usr/bin/env bash
# Permissions, hooks and the different ways a repository can be laid out.
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

test_perms_install_and_checkout_leave_0600() {
	needs_file_modes
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "v1"
	printf 'A=2\n' >.env
	git commit -q -am "v2"
	git branch older HEAD~1
	cd ..

	fresh_clone origin clone
	"${TOOL}/install.sh"
	assert_mode .env "600" "mode after install.sh"

	# A checkout rewrites the file with the umask; the hook tightens it again.
	git checkout -q older
	assert_eq "$(cat .env)" "A=1" "working copy on the other branch"
	assert_mode .env "600" "mode after git checkout"
}

# A secret tracked as 100755 keeps its execute bit, or git would show it
# as modified for ever.
test_perms_executable_secret_keeps_its_execute_bit() {
	needs_file_modes
	new_repo origin
	printf '#!/bin/sh\necho v1\n' >run.secret
	chmod 755 run.secret
	git add run.secret
	git commit -q -m "v1"
	printf '#!/bin/sh\necho v2\n' >run.secret
	git commit -q -am "v2"
	git branch older HEAD~1
	assert_eq "$(git ls-files -s run.secret | cut -c1-6)" "100755" "index mode"
	cd ..

	fresh_clone origin clone
	"${TOOL}/install.sh"
	assert_mode run.secret "700" "mode after install.sh"
	assert_eq "$(git status --porcelain)" "" "git status after install.sh"

	git checkout -q older
	assert_mode run.secret "700" "mode after git checkout"
	assert_eq "$(git status --porcelain)" "" "git status after git checkout"

	printf 'SOPS_FILE_MODE=640\n' >.sops-filter.conf
	"${TOOL}/harden-permissions.sh"
	assert_mode run.secret "740" "mode with SOPS_FILE_MODE=640"

	printf 'SOPS_FILE_MODE=0640\n' >.sops-filter.conf
	"${TOOL}/harden-permissions.sh"
	assert_mode run.secret "740" "mode with SOPS_FILE_MODE=0640"
	assert_eq "$(git status --porcelain -- run.secret)" "" "git status with SOPS_FILE_MODE=0640"

	# A zero owner digit must not be dropped: 060 becomes 160, not 070.
	# (The owner cannot read the file then, so git status is not checked.)
	local m want
	for m in 060:160 000:100; do
		want="${m#*:}"
		m="${m%%:*}"
		printf 'SOPS_FILE_MODE=%s\n' "${m}" >.sops-filter.conf
		"${TOOL}/harden-permissions.sh"
		assert_eq "$(mode_of run.secret)" "${want}" "mode with SOPS_FILE_MODE=${m}"
	done
}

test_perms_file_mode_comes_from_the_conf() {
	needs_file_modes
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	printf 'SOPS_FILE_MODE=640\n' >.sops-filter.conf
	"${TOOL}/harden-permissions.sh"
	assert_mode .env "640" "mode with SOPS_FILE_MODE=640"

	printf 'SOPS_FILE_MODE=rw-r-----\n' >.sops-filter.conf
	run "${TOOL}/harden-permissions.sh"
	assert_ne "${RC}" "0" "an invalid SOPS_FILE_MODE is refused"

	local m
	for m in 4777 2600 666; do
		printf 'SOPS_FILE_MODE=%s\n' "${m}" >.sops-filter.conf
		chmod 644 .env
		run "${TOOL}/harden-permissions.sh"
		assert_ne "${RC}" "0" "SOPS_FILE_MODE=${m} is refused"
		assert_mode .env "600" "mode after SOPS_FILE_MODE=${m} is refused"
	done
	for m in 600 0600 640; do
		printf 'SOPS_FILE_MODE=%s\n' "${m}" >.sops-filter.conf
		run "${TOOL}/harden-permissions.sh"
		assert_eq "${RC}" "0" "SOPS_FILE_MODE=${m} is accepted"
	done
}

# The hooks ignore the script's exit status, so a refused SOPS_FILE_MODE
# must still leave the secret at 0600 after a checkout, not at the umask.
test_perms_refused_mode_still_hardens_through_the_hook() {
	needs_file_modes
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "v1"
	printf 'A=2\n' >.env
	git commit -q -am "v2"
	git branch older HEAD~1
	cd ..

	fresh_clone origin clone
	"${TOOL}/install.sh"
	printf 'SOPS_FILE_MODE=2600\n' >.sops-filter.conf

	umask 022
	run git checkout -q older
	assert_eq "${RC}" "0" "git checkout exit status"
	assert_eq "$(cat .env)" "A=1" "working copy on the other branch"
	assert_contains "${OUT}" "invalid SOPS_FILE_MODE '2600'" "the hook reports the refused mode"
	assert_mode .env "600" "mode after git checkout with a refused mode"
}

# The hooks run after every checkout, merge, rebase and commit. Their
# time must follow the number of SOPS-managed files, not the number of
# tracked files (audit A-01: 1.5 s per checkout with 60,000 of them,
# 2 s with the 100,000 here). The hook needs 0.03 s on a laptop.
test_perms_hook_is_fast_with_many_tracked_files() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	add_index_entries 100000
	chmod 644 .env

	timed "${TOOL}/harden-permissions.sh"
	assert_eq "${RC}" "0" "harden-permissions.sh exit status"
	assert_mode .env "600" "mode of the secret"
	faster_than "${SECS}" 1 || fail "harden-permissions.sh took ${SECS} s for 100,000 tracked files"
}

# Every managed regular file is found, whatever its name; a symlink and
# a file without the attribute are left alone, an executable keeps its
# execute bit.
test_perms_awkward_names_symlinks_and_executables() {
	needs_file_modes
	new_repo repo
	local names=(
		'with space.secret'
		$'tab\there.secret'
		$'new\nline.secret'
		'quote"double.secret'
		'back\slash.secret'
		'glob*star[1]?.secret'
		':colon.secret'
		'!bang.secret'
		'-dash.secret'
		'2:stage.secret'
		':(literal)magic.secret'
		$'caf\303\251.secret'
	)
	local name
	for name in "${names[@]}"; do
		printf 'A=1\n' >"./${name}"
		git add -- "./${name}"
	done
	printf '#!/bin/sh\n' >run.secret
	chmod 755 run.secret
	echo docs >other.txt
	ln -s other.txt link.secret
	git add run.secret other.txt link.secret
	git commit -q -m "secrets with awkward names"
	for name in "${names[@]}"; do
		chmod 644 "./${name}"
	done
	chmod 755 run.secret
	chmod 644 other.txt

	run "${TOOL}/harden-permissions.sh"
	assert_eq "${RC}" "0" "harden-permissions.sh exit status"
	assert_contains "${OUT}" "Permissions: $((${#names[@]} + 1)) SOPS-managed file(s) set to 600." "message"
	for name in "${names[@]}"; do
		assert_mode "./${name}" "600" "mode of [${name}]"
	done
	assert_mode run.secret "700" "mode of the executable secret"
	assert_mode other.txt "644" "mode of a file without the attribute"
	assert_eq "$(git status --porcelain)" "" "git status"
}

# A pathspec setting the caller exported (GIT_LITERAL_PATHSPECS=1 also
# comes from `git --literal-pathspecs`) must not hide the secrets.
test_perms_hook_ignores_pathspec_settings_of_the_caller() {
	needs_file_modes
	needs_file_name ':(literal)b.secret'
	new_repo repo
	printf 'A=1\n' >.env
	printf 'B=1\n' >':(literal)b.secret'
	git add -- .env './:(literal)b.secret'
	local setting
	for setting in GIT_LITERAL_PATHSPECS=1 GIT_GLOB_PATHSPECS=1 GIT_NOGLOB_PATHSPECS=1 GIT_ICASE_PATHSPECS=1 \
		"GIT_GLOB_PATHSPECS=1 GIT_NOGLOB_PATHSPECS=1"; do
		chmod 644 .env ':(literal)b.secret'
		# shellcheck disable=SC2086  # one or two settings
		run env ${setting} "${TOOL}/harden-permissions.sh"
		assert_eq "${RC}" "0" "harden-permissions.sh exit status with ${setting}"
		assert_mode .env "600" "mode of .env with ${setting}"
		assert_eq "$(mode_of ':(literal)b.secret')" "600" "mode of :(literal)b.secret with ${setting}"
	done
}

test_install_keeps_hooks_it_did_not_write() {
	git_init repo
	cd repo || exit 1
	vendor_tool
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m scaffold
	mkdir -p .git/hooks
	printf '#!/bin/sh\necho "my own hook"\n' >.git/hooks/post-checkout
	chmod +x .git/hooks/post-checkout

	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_contains "${OUT}" "not managed by sops-git-filters" "install.sh says it left the hook alone"
	assert_contains "$(cat .git/hooks/post-checkout)" 'my own hook' "the foreign hook"
	assert_contains "$(cat .git/hooks/post-merge)" 'managed by sops-git-filters' "the hook it did install"
}

test_install_can_skip_the_hooks() {
	git_init repo
	cd repo || exit 1
	vendor_tool
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m scaffold

	SOPS_FILTER_INSTALL_HOOKS=0 "${TOOL}/install.sh"
	if grep -qs 'managed by sops-git-filters' .git/hooks/post-checkout .git/hooks/post-merge; then
		fail "hooks were installed although SOPS_FILTER_INSTALL_HOOKS=0"
	fi
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filters are configured all the same"
}

test_layout_git_run_from_a_subdirectory_or_elsewhere() {
	new_repo repo
	mkdir -p deep/er
	printf 'A=1\n' >deep/er/.env
	printf 'R=1\n' >.env
	(cd deep/er && git add .env ../../.env)
	assert_contains "$(stored deep/er/.env)" 'ENC[AES256_GCM,data:' "blob added from a subdirectory"
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "blob added by a relative path"

	local root="${PWD}"
	(cd / && git -C "${root}" commit -q -m "committed from another directory")
	assert_eq "$(git status --porcelain)" "" "git status"
}

# The recommended layout: the tool is a submodule, and install.sh may be
# started from inside it.
test_layout_install_from_a_submodule_configures_the_superproject() {
	local base="${PWD}"
	git_init toolrepo
	cp "${SGF_TOOL_DIR}"/*.sh toolrepo/
	(cd toolrepo && git add -A && git commit -q -m "tool")

	git_init super
	cd super || exit 1
	git -c protocol.file.allow=always submodule add -q "${base}/toolrepo" utilities/sops-git-filters
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m scaffold

	(cd utilities/sops-git-filters && ./install.sh)
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter of the superproject"
	assert_eq "$(installed_source)" "utilities/sops-git-filters" "the checkout of the tool, as recorded in the superproject"
	assert_eq "$(git -C utilities/sops-git-filters config --local --get filter.sops.clean || true)" "" "the submodule itself is not configured"

	printf 'A=1\n' >.env
	git add .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "stored blob"
}

test_layout_install_refuses_its_own_checkout() {
	git_init tool
	cp "${SGF_TOOL_DIR}"/*.sh tool/
	cd tool || exit 1
	git add -A
	git commit -q -m "tool"
	run ./install.sh
	assert_eq "${RC}" "1" "install.sh exit status"
	assert_contains "${OUT}" "inside the sops-git-filters checkout itself" "install.sh message"
}

test_layout_linked_worktree() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	git worktree add ../linked -b side >/dev/null
	cd ../linked || exit 1
	assert_eq "$(cat .env)" "A=1" "working copy in the linked worktree"
	assert_mode .env "600" "mode in the linked worktree"
	printf 'A=2\n' >.env
	git add .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "blob staged in the linked worktree"
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of that blob"
}

test_layout_sparse_checkout() {
	git_at_least 2.26 || skip "git $(git --version | awk '{print $3}') has no git sparse-checkout add (2.26)"
	new_repo origin
	mkdir app conf
	echo code >app/main.txt
	printf 'K=1\n' >conf/prod.secret
	git add app conf
	git commit -q -m "app and a secret"
	cd ..

	git clone -q --sparse origin clone
	cd clone || exit 1
	git sparse-checkout set app utilities
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh with the secret outside the sparse checkout"
	assert_eq "$(git status --porcelain)" "" "git status"

	git sparse-checkout add conf
	assert_eq "$(cat conf/prod.secret)" "K=1" "the secret once it is checked out"
}

# ── Paths that need quoting, and symlinked paths (audit L5) ────
# A directory name with a space, a single quote, shell syntax and a %
# (git's placeholder sign). Since v3.0.0 the path of the tool is in no
# command at all: git config and the hooks name the copy under .git/.
# install.sh still has to copy from such a directory, and nothing in its
# name may run.
# shellcheck disable=SC2016  # the $(...) and backticks are the test
ODD_NAME='sgf '\''tools;$(touch PWNED)`touch PWNED`%f'

# odd_round_trip <base> : in the current repository (tool installed, .env
# with merge=sops), check that git add, a merge through the merge driver
# and the permission hook all work, and that nothing under <base> ran.
odd_round_trip() {
	local base="$1"
	printf 'A=1\nB=2\nC=3\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add exit status"
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "stored blob"
	git commit -q -m "base"

	git checkout -q -b theirs
	printf 'A=1\nB=2\nC=theirs\n' >.env
	git commit -q -am "theirs: C"
	git checkout -q main
	printf 'A=ours\nB=2\nC=3\n' >.env
	git commit -q -am "ours: A"

	umask 022
	git checkout -q theirs
	assert_eq "$(cat .env)" $'A=1\nB=2\nC=theirs' "working copy on the other branch"
	assert_mode .env "600" "mode after git checkout (the hook ran)"
	git checkout -q main
	assert_eq "$(find "${base}" -name 'PWNED*')" "" "files created by the directory name"

	merge_driver_needs_ort
	run git merge --no-edit theirs
	assert_eq "${RC}" "0" "git merge exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs' "merged working copy"
	assert_eq "$(plain_of_stored .env)" $'A=ours\nB=2\nC=theirs' "merged blob"
	assert_eq "$(find "${base}" -name 'PWNED*')" "" "files created by the directory name"
}

# odd_repo : a repository with merge=sops on .env, no tool yet; cd into it
odd_repo() {
	git_init repo
	cd repo || exit 1
	# shellcheck disable=SC2119  # no extra recipients here
	write_sops_yaml
	printf '.env filter=sops diff=sops merge=sops\n' >.gitattributes
}

test_layout_tool_path_that_needs_quoting_inside_the_repo() {
	local base="${PWD}"
	odd_repo
	mkdir -p "utilities/${ODD_NAME}"
	cp "${SGF_TOOL_DIR}"/*.sh "utilities/${ODD_NAME}/"
	git add -A
	git commit -q -m scaffold

	run "utilities/${ODD_NAME}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	assert_not_contains "$(cat .git/hooks/post-checkout)" "tools;" "the hook does not name the tool's directory"
	assert_eq "$(installed_source)" "utilities/${ODD_NAME}" "the checkout of the tool, as recorded"
	odd_round_trip "${base}"
}

test_layout_tool_path_that_needs_quoting_outside_the_repo() {
	local base="${PWD}"
	mkdir "${ODD_NAME}"
	cp "${SGF_TOOL_DIR}"/*.sh "${ODD_NAME}/"
	odd_repo
	git add -A
	git commit -q -m scaffold

	run "${base}/${ODD_NAME}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	assert_eq "$(installed_source)" "${base}/${ODD_NAME}" "the checkout of the tool, as recorded"
	odd_round_trip "${base}"
}

# A non-ASCII directory name, such as a localized "Masaüstü" (Desktop).
# Git runs the filter and merge commands with /bin/sh, which is dash on
# Debian and Ubuntu, and dash does not know bash's $'...' quoting. The
# commands hold a "$(git rev-parse ...)" that sh and dash must run.
NON_ASCII_NAME='Masaüstü'

# check_posix_commands : the stored clean and merge commands hold no
# $'...', and the clean command works under sh and, when there, dash.
check_posix_commands() {
	local clean merge sh_name out
	clean="$(git config --local --get filter.sops.clean)"
	merge="$(git config --local --get merge.sops.driver)"
	assert_not_contains "${clean}" "\$'" "clean filter command"
	assert_not_contains "${merge}" "\$'" "merge driver command"
	printf 'A=1\n' >probe.env
	for sh_name in sh dash; do
		command -v "${sh_name}" >/dev/null 2>&1 || continue
		out="$("${sh_name}" -c "${clean%' %f'} probe.env" <probe.env 2>&1)" ||
			fail "clean filter command under ${sh_name}: ${out}"
		assert_contains "${out}" 'ENC[AES256_GCM,data:' "clean filter output under ${sh_name}"
	done
	rm -f probe.env
}

test_layout_non_ascii_tool_path_inside_the_repo() {
	local base="${PWD}"
	odd_repo
	mkdir -p "utilities/${NON_ASCII_NAME}/sgf"
	cp "${SGF_TOOL_DIR}"/*.sh "utilities/${NON_ASCII_NAME}/sgf/"
	git add -A
	git commit -q -m scaffold

	run "utilities/${NON_ASCII_NAME}/sgf/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	assert_eq "$(installed_source)" "utilities/${NON_ASCII_NAME}/sgf" "the checkout of the tool, as recorded"
	check_posix_commands
	odd_round_trip "${base}"
}

test_layout_non_ascii_tool_path_outside_the_repo() {
	local base="${PWD}"
	mkdir -p "${NON_ASCII_NAME}/sgf"
	cp "${SGF_TOOL_DIR}"/*.sh "${NON_ASCII_NAME}/sgf/"
	odd_repo
	git add -A
	git commit -q -m scaffold

	run "${base}/${NON_ASCII_NAME}/sgf/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_eq "$(git config --local --get merge.sops.driver)" \
		"${INSTALLED_CMD_PREFIX}/merge-driver.sh %O %A %B %L %P" "merge driver command"
	assert_eq "$(installed_source)" "${base}/${NON_ASCII_NAME}/sgf" "the checkout of the tool, as recorded"
	check_posix_commands
	odd_round_trip "${base}"
}

# Reached through a symlink, the tool inside the repository is still
# inside it: its path is recorded relative to the repository, not as an
# absolute one.
test_layout_install_through_a_symlinked_path() {
	needs_symlinks
	mkdir real
	ln -s real link
	cd real || exit 1
	git_init repo
	cd repo || exit 1
	vendor_tool
	# shellcheck disable=SC2119  # no extra recipients here
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m scaffold

	cd ../../link/repo || exit 1
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_eq "$(installed_source)" "${TOOL}" "the checkout of the tool, as recorded"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	assert_eq "$(git config --local --get merge.sops.driver)" "${INSTALLED_CMD_PREFIX}/merge-driver.sh %O %A %B %L %P" "merge driver command"
	assert_contains "$(cat .git/hooks/post-checkout)" 'git rev-parse --git-common-dir' "hook"

	printf 'A=1\n' >.env
	git add .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "stored blob"
}

test_layout_install_refuses_its_own_checkout_through_a_symlink() {
	needs_symlinks
	mkdir real
	ln -s real link
	git_init real/tool
	cp "${SGF_TOOL_DIR}"/*.sh real/tool/
	(cd real/tool && git add -A && git commit -q -m "tool")

	cd link/tool || exit 1
	run ./install.sh
	assert_eq "${RC}" "1" "install.sh exit status"
	assert_contains "${OUT}" "inside the sops-git-filters checkout itself" "install.sh message"
	assert_eq "$(git config --local --get filter.sops.clean || true)" "" "the tool's checkout is not configured"
}

# A file system that keeps no Unix modes (NTFS through Git Bash on
# Windows): chmod succeeds and changes nothing. The message must not say
# the files were set to 600. A chmod that does nothing stands in for it.
test_perms_says_when_the_file_system_keeps_no_modes() {
	umask 022
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	chmod 644 .env
	stub "${PWD}/../bin" chmod <<'STUB'
exit 0
STUB
	run env PATH="${PWD}/../bin:${PATH}" "${TOOL}/harden-permissions.sh"
	assert_eq "${RC}" "0" "harden-permissions.sh exit status"
	assert_contains "${OUT}" "this file system keeps no Unix file modes" "message"
	assert_not_contains "${OUT}" "set to 600" "message"

	needs_file_modes
	run "${TOOL}/harden-permissions.sh"
	assert_contains "${OUT}" "Permissions: 1 SOPS-managed file(s) set to 600." "message with a chmod that works"
}

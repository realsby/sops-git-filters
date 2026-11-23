#!/usr/bin/env bash
# The copy of the scripts under .git/ that git runs (audit F12), and the
# smudge filter in it (audit F7).
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

# ── A branch cannot swap the code (audit F12) ────
# Before, git config and the hooks named the scripts in the working tree.
# Checking out a branch ran that branch's harden-permissions.sh through
# the post-checkout hook, and the next `git status` ran its
# clean-filter.sh with the plaintext on stdin.
test_copy_a_branch_cannot_swap_the_code_git_runs() {
	umask 022
	new_repo repo
	printf '.env filter=sops diff=sops merge=sops\n' >.gitattributes
	printf 'A=1\nB=2\nC=3\n' >.env
	git add .gitattributes .env
	git commit -q -m "add .env"

	# A branch from somebody else: every script of the tool is replaced.
	local marker="${PWD}/../PWNED" script
	git checkout -q -b theirs
	for script in "${TOOL}"/*.sh; do
		printf '#!/bin/sh\ntouch %s\nexit 0\n' "${marker}" >"${script}"
	done
	printf 'A=1\nB=2\nC=theirs\n' >.env
	git commit -q -am "theirs: C, and other scripts"
	git checkout -q main
	printf 'A=ours\nB=2\nC=3\n' >.env
	git commit -q -am "ours: A"

	# Look at their branch, edit a secret there, come back and merge it.
	chmod 644 .env
	git checkout -q theirs
	assert_eq "$(mode_of .env)" "600" "mode after the checkout (the installed hook ran)"
	git status >/dev/null
	git diff >/dev/null
	printf 'A=1\nB=2\nC=theirs\nD=4\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add on their branch"
	assert_eq "$(plain_of_stored .env)" $'A=1\nB=2\nC=theirs\nD=4' "the installed clean filter encrypted it"
	git commit -q -m "theirs: D"
	git checkout -q main
	run git merge --no-edit theirs
	assert_eq "${RC}" "0" "git merge exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs\nD=4' "merged working copy (the installed merge driver ran)"

	[[ ! -e "${marker}" ]] || fail "a script of the branch was executed"
}

# ── Linked worktrees ────
# The filter and hook commands ask for the common git directory when they
# run. A linked worktree needs nothing of its own: not even the tool,
# which with the submodule layout is missing there until
# `git submodule update --init`.
test_copy_works_in_a_linked_worktree_without_the_tool() {
	umask 022
	git init -q repo
	cd repo || exit 1
	vendor_tool
	# shellcheck disable=SC2119  # no extra recipients here
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	# Not tracked: a new worktree will not have it.
	printf '/utilities/\n' >.gitignore
	git add .sops.yaml .gitattributes .gitignore
	git commit -q -m scaffold
	"${TOOL}/install.sh"
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	git worktree add -q ../linked -b side
	cd ../linked || exit 1
	[[ ! -e utilities ]] || fail "the tool is in the linked worktree, the test would prove nothing"
	assert_eq "$(cat .env)" "A=1" "working copy in the linked worktree"
	assert_eq "$(mode_of .env)" "600" "mode in the linked worktree (the hook ran at worktree add)"

	printf 'A=2\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add in the linked worktree"
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
	git commit -q -m "change .env in the linked worktree"
	chmod 644 .env
	git checkout -q HEAD~1
	assert_eq "$(cat .env)" "A=1" "working copy after a checkout in the linked worktree"
	assert_eq "$(mode_of .env)" "600" "mode after a checkout in the linked worktree"
}

test_copy_survives_a_move_of_the_repository() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "v1"
	printf 'A=2\n' >.env
	git commit -q -am "v2"
	cd ..
	mv repo "moved repo"
	cd "moved repo" || exit 1

	git checkout -q HEAD~1
	assert_eq "$(cat .env)" "A=1" "working copy after the move"
	printf 'A=3\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add after the move"
	assert_eq "$(plain_of_stored .env)" "A=3" "plaintext of the staged blob"
}

# ── What is installed, and when it is refreshed ────
test_copy_holds_what_git_needs_and_follows_install() {
	new_repo repo
	local dir file
	dir="$(installed_dir)"
	for file in lib.sh clean-filter.sh smudge-filter.sh merge-driver.sh harden-permissions.sh; do
		cmp "${TOOL}/${file}" "${dir}/${file}" || fail "${file} of the installed copy differs from the checkout"
	done
	assert_contains "$(cat "${dir}/INSTALLED")" "source=${TOOL}" "INSTALLED names the checkout by its path in the repository"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	assert_eq "$(git config --local --get filter.sops.smudge)" "${INSTALLED_CMD_PREFIX}/smudge-filter.sh json %f" "smudge filter command"
	assert_eq "$(git config --local --get merge.sops.driver)" \
		"${INSTALLED_CMD_PREFIX}/merge-driver.sh %O %A %B %L %P" "merge driver command"

	# A second run changes nothing.
	run "${TOOL}/install.sh"
	assert_not_contains "${OUT}" "Installed the scripts git runs" "install.sh output of a second run"

	# The checkout changes: the copy does not, until install.sh runs.
	printf '\n# a later version\n' >>"${TOOL}/clean-filter.sh"
	if cmp -s "${TOOL}/clean-filter.sh" "${dir}/clean-filter.sh"; then
		fail "the installed copy changed with the checkout"
	fi
	run "${TOOL}/install.sh"
	assert_contains "${OUT}" "Installed the scripts git runs" "install.sh output after the checkout changed"
	cmp "${TOOL}/clean-filter.sh" "${dir}/clean-filter.sh" || fail "install.sh did not refresh the copy"
}

# A setup of before v3.0.0 named the scripts of the checkout in git config
# and in the hooks. install.sh replaces both.
test_copy_replaces_a_setup_from_before_v3() {
	new_repo repo
	git config --local filter.sops.clean "${TOOL}/clean-filter.sh %f"
	git config --local filter.sops.smudge "sops decrypt --input-type json --output-type binary --filename-override %f /dev/stdin"
	git config --local merge.sops.driver "${TOOL}/merge-driver.sh %O %A %B %L %P"
	local hook
	hook="$(git rev-parse --git-path hooks)/post-checkout"
	{
		printf '#!/usr/bin/env bash\n# managed by sops-git-filters (secret file permissions)\n'
		# shellcheck disable=SC2016  # $root belongs to the hook
		printf 'root="$(git rev-parse --show-toplevel)"\n"$root"/%s/harden-permissions.sh --quiet\n' "${TOOL}"
	} >"${hook}"

	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_contains "$(git config --local --get filter.sops.clean)" "git rev-parse --git-common-dir" "clean filter command"
	assert_contains "$(git config --local --get filter.sops.smudge)" "smudge-filter.sh json %f" "smudge filter command"
	assert_contains "$(git config --local --get merge.sops.driver)" "git rev-parse --git-common-dir" "merge driver command"
	assert_contains "$(cat "${hook}")" "git rev-parse --git-common-dir" "the hook"
	assert_not_contains "$(cat "${hook}")" "${TOOL}" "the hook names nothing in the working tree"
}

# ── An update that was not installed yet ────
# After an update of the checkout, git still runs the old copy. That is
# the price of the copy, so it must not go unnoticed.
test_copy_says_when_the_checkout_is_newer() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	printf 'A=2\n' >.env
	run git add .env
	assert_not_contains "${OUT}" "install.sh" "git add while the copy is current"

	# set_version <text> : rewrite the version line of the checkout
	set_version() {
		awk -v v="$1" '/^SGF_VERSION=/ { print "SGF_VERSION=" v; next } { print }' "${TOOL}/lib.sh" >../lib.new
		cat ../lib.new >"${TOOL}/lib.sh"
	}

	# A newer release in the checkout, install.sh not run again.
	set_version '"99.0.0"'
	printf 'A=3\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add exit status"
	assert_contains "${OUT}" "holds 99.0.0" "the clean filter says the checkout is newer"
	assert_contains "${OUT}" "${TOOL}/install.sh" "and what to run"
	git commit -q -m "change .env"
	run git checkout -q -b other
	assert_contains "${OUT}" "holds 99.0.0" "the hook says it too"

	# An older checkout (a branch from before the update) is no reason to warn.
	set_version '"1.0.0"'
	printf 'A=4\n' >.env
	run git add .env
	assert_not_contains "${OUT}" "install.sh" "git add with an older checkout"

	# The line is read as text. Anything but a version number is ignored,
	# and nothing in it runs.
	# shellcheck disable=SC2016  # must stay unexpanded
	set_version '"$(touch PWNED)"'
	printf 'A=5\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add exit status"
	assert_not_contains "${OUT}" "install.sh" "git add with a version line that is no version"
	[[ ! -e PWNED ]] || fail "the version line of the checkout was executed"

	# install.sh brings the copy up to date and the notice goes away.
	set_version '"99.0.0"'
	"${TOOL}/install.sh"
	assert_contains "$(cat "$(installed_dir)/INSTALLED")" "version=99.0.0" "INSTALLED after install.sh"
	printf 'A=6\n' >.env
	run git add .env
	assert_not_contains "${OUT}" "install.sh" "git add after install.sh"
}

# ── An incomplete copy fails closed ────
test_copy_incomplete_copy_fails_closed() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	local before
	before="$(blob_id .env)"

	mv "$(installed_dir)/lib.sh" ../lib.sh.off
	printf 'A=PLAINTEXT\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add without lib.sh in the installed copy"
	assert_eq "$(blob_id .env)" "${before}" "the index keeps the earlier blob"

	# install.sh repairs it.
	git checkout -q -- .env 2>/dev/null || true
	run "${TOOL}/install.sh"
	printf 'A=2\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add after install.sh"
	assert_not_contains "$(stored .env)" 'A=2' "index blob"
}

# ── The smudge filter (audit F7) ────
# sops cannot decrypt: the checkout stops, nothing but the error is
# written, and the lines under the error say what to check.
test_smudge_fails_closed_and_says_what_to_check() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "v1"
	printf 'A=2\n' >.env
	git commit -q -am "v2"
	local head
	head="$(git rev-parse HEAD)"
	sleep 1
	git status >/dev/null

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" git checkout -q HEAD~1
	assert_ne "${RC}" "0" "git checkout without the key"
	assert_contains "${OUT}" "data key" "sops' own error is shown"
	assert_contains "${OUT}" "sops smudge filter: cannot decrypt .env" "the filter names the file"
	assert_contains "${OUT}" "age: the private key must be where sops looks" "the hint fits the kind of key"
	assert_not_contains "${OUT}" "aws sso login" "no hint for a key service the file does not use"
	assert_contains "${OUT}" "do NOT commit or stash" "the filter says what not to do"
	assert_eq "$(git rev-parse HEAD)" "${head}" "HEAD has not moved"
	# Fail closed: no ciphertext and no empty file in place of the secret.
	[[ ! -e .env ]] || fail "something was written in place of the secret: $(head -c 80 .env)"

	# The way back.
	git checkout -q -- .env
	assert_eq "$(cat .env)" "A=2" "working copy after the way back"
	assert_eq "$(git status --porcelain)" "" "git status"
	run git checkout -q HEAD~1
	assert_eq "${RC}" "0" "git checkout with the key"
	assert_eq "$(cat .env)" "A=1" "working copy"
}

# The plaintext goes from sops to git without passing through a shell
# variable, so content this tool cannot stage is still checked out intact.
test_smudge_writes_the_plaintext_byte_for_byte() {
	new_repo repo
	printf 'a\0b\n\n\n' >../expected
	sops encrypt --input-type binary --output-type json \
		--filename-override bin.secret ../expected >../bin.enc
	git update-index --add --cacheinfo "100644,$(git hash-object -w ../bin.enc),bin.secret"
	git commit -q -m "a binary secret stored without the filter"

	git checkout -q -- bin.secret
	cmp bin.secret ../expected || fail "the checked-out file differs from what was encrypted"
}

# The storage format is part of the smudge command that install.sh writes.
# The filter must not read it from .sops-filter.conf: git checks files out
# in the order of their names, and in a new working tree ".env" is written
# before ".sops-filter.conf" exists. (A release candidate read the file,
# and `git worktree add` failed in every repository that stores dotenv.)
test_smudge_knows_the_storage_format_before_the_conf_is_checked_out() {
	umask 022
	new_repo repo dotenv
	printf 'A=1\n' >.env
	mkdir stacks
	printf 'B=2\n' >stacks/.env
	printf '**/.env filter=sops diff=sops\n.env filter=sops diff=sops\n' >.gitattributes
	git add .gitattributes .env stacks/.env
	git commit -q -m "two dotenv secrets"
	assert_eq "$(git config --local --get filter.sops.smudge)" "${INSTALLED_CMD_PREFIX}/smudge-filter.sh dotenv %f" "smudge filter command"

	run git worktree add -q ../linked -b side
	assert_eq "${RC}" "0" "git worktree add in a repository that stores dotenv"
	assert_eq "$(cat ../linked/.env)" "A=1" "working copy in the linked worktree"
	assert_eq "$(cat ../linked/stacks/.env)" "B=2" "working copy in the linked worktree"
	assert_eq "$(mode_of ../linked/.env)" "600" "mode in the linked worktree"
	assert_eq "$(git -C ../linked status --porcelain)" "" "git status in the linked worktree"

	printf 'A=2\n' >../linked/.env
	run git -C ../linked add .env
	assert_eq "${RC}" "0" "git add in the linked worktree"
	assert_eq "$(cd ../linked && plain_of_stored .env dotenv)" "A=2" "plaintext of the staged blob"
}

# A changed .sops-filter.conf reaches the smudge filter through install.sh,
# and a blob in the other format is named as such.
test_smudge_format_follows_install() {
	new_repo repo dotenv
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "v1 (dotenv)"
	printf 'A=2\n' >.env
	git commit -q -am "v2 (dotenv)"

	# The conf says json now, install.sh has not run: checkouts go on as before.
	printf 'SOPS_STORE_FORMAT=json\n' >.sops-filter.conf
	rm .env
	run git checkout -- .env
	assert_eq "${RC}" "0" "git checkout before install.sh ran again"
	assert_eq "$(cat .env)" "A=2" "working copy"

	# install.sh takes the new format over (and reports the files still in
	# the old one, exit status 3).
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status with an unfinished format change"
	assert_eq "$(git config --local --get filter.sops.smudge)" "${INSTALLED_CMD_PREFIX}/smudge-filter.sh json %f" "smudge filter command"
	rm .env
	run git checkout -- .env
	assert_ne "${RC}" "0" "git checkout of a blob in the other format"
	assert_contains "${OUT}" "in the dotenv format, but this clone is set up for json" "the filter names the format mismatch"
	[[ ! -e .env ]] || fail "something was written in place of the secret"
}

# A blob that was committed in plaintext cannot be checked out silently.
test_smudge_names_a_blob_that_is_not_encrypted() {
	new_repo repo
	printf 'A=plaintext\n' >../plain
	git update-index --add --cacheinfo "100644,$(git hash-object -w ../plain),.env"
	git commit -q -m "a secret committed without the filter"

	run git checkout -q -- .env
	assert_ne "${RC}" "0" "git checkout of a plaintext blob"
	assert_contains "${OUT}" "not an encrypted SOPS document" "the filter says what the blob is"
	[[ ! -e .env ]] || fail "the plaintext blob was written to the working tree"
}

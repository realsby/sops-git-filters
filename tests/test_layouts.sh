#!/usr/bin/env bash
# Permissions, hooks and the different ways a repository can be laid out.
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

test_perms_install_and_checkout_leave_0600() {
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
	assert_eq "$(mode_of .env)" "600" "mode after install.sh"

	# A checkout rewrites the file with the umask; the hook tightens it again.
	git checkout -q older
	assert_eq "$(cat .env)" "A=1" "working copy on the other branch"
	assert_eq "$(mode_of .env)" "600" "mode after git checkout"
}

test_perms_file_mode_comes_from_the_conf() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	printf 'SOPS_FILE_MODE=640\n' >.sops-filter.conf
	"${TOOL}/harden-permissions.sh"
	assert_eq "$(mode_of .env)" "640" "mode with SOPS_FILE_MODE=640"

	printf 'SOPS_FILE_MODE=rw-r-----\n' >.sops-filter.conf
	run "${TOOL}/harden-permissions.sh"
	assert_ne "${RC}" "0" "an invalid SOPS_FILE_MODE is refused"
}

test_install_keeps_hooks_it_did_not_write() {
	git init -q repo
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
	git init -q repo
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
	git init -q toolrepo
	cp "${SGF_TOOL_DIR}"/*.sh toolrepo/
	(cd toolrepo && git add -A && git commit -q -m "tool")

	git init -q super
	cd super || exit 1
	git -c protocol.file.allow=always submodule add -q "${base}/toolrepo" utilities/sops-git-filters
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m scaffold

	(cd utilities/sops-git-filters && ./install.sh)
	assert_eq "$(git config --local --get filter.sops.clean)" "utilities/sops-git-filters/clean-filter.sh %f" "clean filter of the superproject"
	assert_eq "$(git -C utilities/sops-git-filters config --local --get filter.sops.clean || true)" "" "the submodule itself is not configured"

	printf 'A=1\n' >.env
	git add .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "stored blob"
}

test_layout_install_refuses_its_own_checkout() {
	git init -q tool
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

	git worktree add -q ../linked -b side
	cd ../linked || exit 1
	assert_eq "$(cat .env)" "A=1" "working copy in the linked worktree"
	assert_eq "$(mode_of .env)" "600" "mode in the linked worktree"
	printf 'A=2\n' >.env
	git add .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "blob staged in the linked worktree"
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of that blob"
}

test_layout_sparse_checkout() {
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

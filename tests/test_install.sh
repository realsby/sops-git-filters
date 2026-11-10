#!/usr/bin/env bash
# install.sh
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

# The "already configured" shortcut must not skip filter.sops.required:
# without it git stages the plaintext when the clean filter fails.
test_install_restores_required_flag() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	git config --local --unset filter.sops.required
	"${TOOL}/install.sh"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filter.sops.required after re-install"

	# The consequence: a failing clean filter aborts instead of staging plaintext.
	mv .sops.yaml sops.yaml.off
	printf 'A=PLAINTEXT\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_not_contains "$(stored .env)" 'PLAINTEXT' "index blob"
}

# filter.<driver>.process takes precedence over clean/smudge.
test_install_removes_local_process_filter() {
	new_repo repo
	git config --local filter.sops.process "some-other-tool"
	"${TOOL}/install.sh"
	run git config --local --get filter.sops.process
	assert_ne "${RC}" "0" "filter.sops.process is gone from .git/config"
}

test_install_refuses_inherited_process_filter() {
	new_repo repo
	git config --global filter.sops.process "some-other-tool"
	run "${TOOL}/install.sh"
	git config --global --unset filter.sops.process
	assert_ne "${RC}" "0" "install.sh exit status"
	assert_contains "${OUT}" "filter.sops.process" "install.sh message"
}

# A .sops-filter.conf may set SOPS_FILE_MODE only and keep the default format.
test_install_accepts_conf_without_store_format() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	printf '# widen for a deploy daemon\nSOPS_FILE_MODE=640\n' >.sops-filter.conf
	git add .sops-filter.conf
	git commit -q -m "add .env and a conf without SOPS_STORE_FORMAT"
	cd ..

	fresh_clone origin clone
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_ne "$(git config --local --get filter.sops.clean || true)" "" "filter.sops.clean"
	assert_eq "$(cat .env)" "A=1" "working copy after install.sh"
}

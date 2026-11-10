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

# The same repair when install.sh cannot finish. Here sops is not on PATH
# (setup run outside the dev shell): install.sh stops, and the clean
# filter fails for the same reason.
test_install_restores_required_flag_when_it_stops_early() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	git config --local --unset filter.sops.required
	no_sops="$(path_with_only ../nosops git bash dirname)"
	run env PATH="${no_sops}" "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status without sops"
	assert_contains "${OUT}" "sops not found" "install.sh message"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filter.sops.required after a failed install"

	printf 'A=PLAINTEXT\n' >.env
	run env PATH="${no_sops}" git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_not_contains "$(stored .env)" 'PLAINTEXT' "index blob"
}

# ... but only there. required=true without the two commands makes git
# fail on every SOPS-managed file, so a clone that never had the filters
# gets no setting at all from an install that stops.
test_install_that_stops_early_leaves_a_new_clone_unconfigured() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	run env PATH="$(path_with_only ../nosops git bash dirname)" "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status without sops"
	assert_eq "$(git config --local --get-regexp '^filter\.sops\.' || true)" "" "filter settings after a failed first install"
	assert_eq "$(git status --porcelain)" "" "git status still works"
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

# Up to 3.10.2 sops can store a whole file in clear (see lib.sh).
test_install_refuses_old_sops() {
	new_repo repo
	stub ../fakebin sops <<'STUB'
case " $* " in
*" --version "*) echo "sops 3.10.2"; exit 0 ;;
esac
exec "${REAL}" "$@"
STUB
	git config --local --unset filter.sops.required
	run env PATH="${PWD}/../fakebin:${PATH}" "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status"
	assert_contains "${OUT}" "3.10.2 is too old" "install.sh message"
	assert_contains "${OUT}" "3.11.0" "install.sh message"
	# Refused, but an existing setup is fail-closed again.
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filter.sops.required after a refused install"
}

# An incomplete copy of the tool (lib.sh was not copied along): install.sh
# stops at once, and the clean filter cannot work either. The flag is
# restored before that.
test_install_restores_required_flag_with_an_incomplete_copy() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	git config --local --unset filter.sops.required
	mv "${TOOL}/lib.sh" "${TOOL}/lib.sh.off"
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status without lib.sh"
	assert_contains "${OUT}" "lib.sh is missing" "install.sh message"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filter.sops.required after a failed install"

	printf 'A=PLAINTEXT\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_not_contains "$(stored .env)" 'PLAINTEXT' "index blob"
}

# A secret that was committed before the filter existed stays plaintext
# in git. install.sh must say so, not blame the keys.
test_install_reports_plaintext_tracked_before_adoption() {
	git init -q repo
	cd repo || exit 1
	printf 'P=legacy\n' >.env
	git add .env
	git commit -q -m "plaintext secret, before the filter"
	vendor_tool
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m "adopt sops-git-filters"

	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status"
	assert_contains "${OUT}" "NOT ENCRYPTED IN GIT" "install.sh report"
	assert_contains "${OUT}" ".env  (index and HEAD)" "install.sh report"
	assert_not_contains "${OUT}" "Could not decrypt .env" "the misleading key warning"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filters are installed all the same"

	# The fix the report prints.
	git add --renormalize -- .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "blob after --renormalize"
	assert_not_contains "$(stored .env)" 'legacy' "blob after --renormalize"
	git commit -q -m "encrypt .env"
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status once the file is encrypted"
}

# A storage-format change that is not finished: the blobs are encrypted,
# in the old format. Not plaintext, but still something to do.
test_install_reports_unfinished_format_change() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env (json)"

	printf 'SOPS_STORE_FORMAT=dotenv\n' >.sops-filter.conf
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status"
	assert_contains "${OUT}" "STORED IN THE OTHER FORMAT" "install.sh report"
	assert_not_contains "${OUT}" "NOT ENCRYPTED IN GIT" "install.sh report"
}

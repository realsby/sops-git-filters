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

# A filter.sops.process that outranks .git/config (GIT_CONFIG_COUNT,
# `git -c`, a worktree's config) stops install.sh with exit 1. A clone
# that never had the filters must come out of that unchanged: with
# filter.sops.required=true and no filter command, the first edit of a
# secret made `git status` and `git add` fail with exit 128 (audit A-03).
test_install_stopped_by_an_overriding_process_filter_leaves_a_new_clone_working() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	run env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=filter.sops.process GIT_CONFIG_VALUE_0=cat "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status"
	assert_contains "${OUT}" "filter.sops.process is set outside" "install.sh message"
	assert_eq "$(git config --local --get-regexp '^filter\.sops\.' || true)" "" "filter settings after exit 1"
	[[ ! -e "$(git rev-parse --git-common-dir)/sops-git-filters" ]] || fail "exit 1 left the scripts under .git/"

	printf 'A=2\n' >>.env
	run git status --short
	assert_eq "${RC}" "0" "git status after an edit of the secret"
	assert_eq "${OUT}" " M .env" "git status after an edit of the secret"

	# The same with a clean or smudge command that is there for this one
	# run only: it is no setup to keep fail-closed.
	git checkout -q -- .env
	run env PATH="$(path_with_only ../nosops git bash dirname)" \
		GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=filter.sops.smudge GIT_CONFIG_VALUE_0=cat "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status without sops"
	assert_eq "$(git config --local --get-regexp '^filter\.sops\.' || true)" "" "filter settings after exit 1"
}

# The one exit 1 that comes after the settings are written: a filter
# command in a config file that outranks .git/config. The settings are in
# .git/config and work; the message says what was left undone.
test_install_stopped_by_an_overriding_smudge_filter_says_what_it_left() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	run env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=filter.sops.smudge GIT_CONFIG_VALUE_0=cat "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status"
	assert_contains "${OUT}" "another git config file overrides" "install.sh message"
	assert_contains "${OUT}" "no hooks were installed and no file was decrypted" "install.sh message"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filter.sops.required"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	[[ ! -e "$(git rev-parse --git-path hooks)/post-checkout" ]] || fail "a hook was installed"

	printf 'A=2\n' >.env
	run git status --short
	assert_eq "${RC}" "0" "git status after an edit of the secret"
	git add .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "index blob"
	assert_not_contains "$(stored .env)" 'A=2' "index blob"

	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status without the override"
	assert_contains "$(cat "$(git rev-parse --git-path hooks)/post-checkout")" 'managed by sops-git-filters' "the hook"
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
# stops at once. The flag is restored before that, and the copy under
# .git/ that an earlier run installed keeps working.
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
	assert_eq "${RC}" "0" "git add with the installed copy"
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "index blob"
	assert_not_contains "$(stored .env)" 'PLAINTEXT' "index blob"

	# The same with one of the other scripts git needs.
	mv "${TOOL}/lib.sh.off" "${TOOL}/lib.sh"
	mv "${TOOL}/smudge-filter.sh" "${TOOL}/smudge-filter.sh.off"
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "1" "install.sh exit status without smudge-filter.sh"
	assert_contains "${OUT}" "smudge-filter.sh is missing" "install.sh message"
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

# The commit holds plaintext, the index already holds ciphertext, and
# then the storage format is changed. The report on the format must not
# hide that the committed version is readable.
test_install_reports_a_plaintext_commit_behind_the_other_format() {
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
	git add --renormalize -- .env
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "index blob after --renormalize"

	printf 'SOPS_STORE_FORMAT=dotenv\n' >.sops-filter.conf
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status"
	assert_contains "${OUT}" "STORED IN THE OTHER FORMAT" "install.sh report"
	assert_contains "${OUT}" "NOT ENCRYPTED IN GIT" "install.sh report"
	assert_contains "${OUT}" ".env  (HEAD)" "install.sh report"
	assert_not_contains "${OUT}" "nothing leaked" "install.sh report"
	assert_not_contains "${OUT}" "legacy" "install.sh output"
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

# No key, no decryption: the caller must be able to tell from the exit status.
test_install_exits_3_when_it_cannot_decrypt() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status without the key"
	assert_contains "${OUT}" "STILL ENCRYPTED IN THE WORKING TREE" "install.sh report"
	assert_contains "${OUT}" "- .env" "install.sh report"
	assert_contains "${OUT}" "data key" "sops' own error is shown"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filters are installed all the same"
	assert_eq "$(git status --porcelain)" "" "git status with ciphertext in the working copy"

	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status with the key"
	assert_eq "$(cat .env)" "A=1" "working copy"
}

# dotenv, several files: while one is decrypted git re-checks the others,
# which still hold ciphertext. That must not fail.
test_install_decrypts_several_dotenv_files() {
	new_repo origin dotenv
	printf 'A=1\n' >.env
	printf 'B=2\n' >b.secret
	printf 'C=3\n' >c.secret
	git add .env b.secret c.secret
	git commit -q -m "three secrets"
	cd ..

	fresh_clone origin clone
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_not_contains "${OUT}" "Could not refresh index stat" "install.sh output"
	assert_eq "$(git status --porcelain)" "" "git status"
	assert_eq "$(cat .env b.secret c.secret)" "$(printf 'A=1\nB=2\nC=3')" "working copies"
}

# A pathspec setting the caller exported (GIT_LITERAL_PATHSPECS=1 also
# comes from `git --literal-pathspecs`) must not hide the secrets from
# install.sh's decrypt pass or from preflight.sh.
test_install_and_preflight_ignore_pathspec_settings_of_the_caller() {
	new_repo origin
	printf 'A=1\n' >.env
	printf 'B=2\n' >':(literal)b.secret'
	git add -- .env './:(literal)b.secret'
	git commit -q -m "two secrets"
	cd ..

	fresh_clone origin clone
	run env GIT_LITERAL_PATHSPECS=1 "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	assert_eq "$(cat .env ':(literal)b.secret')" "$(printf 'A=1\nB=2')" "working copies"
	assert_eq "$(git status --porcelain)" "" "git status"

	local setting
	for setting in GIT_LITERAL_PATHSPECS=1 "GIT_GLOB_PATHSPECS=1 GIT_NOGLOB_PATHSPECS=1"; do
		# shellcheck disable=SC2086  # one or two settings
		run env ${setting} "${TOOL}/preflight.sh"
		assert_eq "${RC}" "0" "preflight.sh exit status with ${setting}"
		assert_contains "${OUT}" "decryption works (1 set(s) of keys checked)" "preflight.sh with ${setting}"
	done
}

# The permission hook chmods a secret right after git wrote it. That
# changes the file's inode change time, and git took the secret for
# locally modified: a rebase stopped with "Your local changes to the
# following files would be overwritten by merge" whenever the chmod
# landed in a later second than the checkout. Here the hook is slowed
# down, so that it always does.
test_install_makes_rebase_survive_the_permission_hook() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "base"
	git checkout -q -b feature
	printf 'A=2\n' >.env
	git add .env
	git commit -q -m "feature: change the secret"
	git checkout -q main
	printf 'x\n' >other.txt
	git add other.txt
	git commit -q -m "main: something else"
	git checkout -q feature

	hook="$(git rev-parse --git-path hooks)/post-checkout"
	mv "${hook}" "${hook}.real"
	# shellcheck disable=SC2016  # $0 and $@ belong to the hook
	printf '#!/bin/sh\nsleep 1\nexec "$0.real" "$@"\n' >"${hook}"
	chmod +x "${hook}"

	run git rebase main
	assert_eq "${RC}" "0" "git rebase exit status"
	assert_eq "$(cat .env)" "A=2" "working copy after the rebase"
	assert_eq "$(git status --porcelain)" "" "git status"
}

# core.trustctime is written once. A value that is already there stays.
test_install_sets_trustctime_unless_it_is_set() {
	new_repo repo
	assert_eq "$(git config --local --get core.trustctime)" "false" "core.trustctime after install.sh"

	git config --local core.trustctime true
	"${TOOL}/install.sh"
	assert_eq "$(git config --local --get core.trustctime)" "true" "a core.trustctime that was set by hand"
}

# An exported CDPATH must not change where the scripts find themselves.
# With it, `cd utilities/sops-git-filters` can land in another directory
# of that name, and bash prints the path, so `$(cd ... && pwd)` returns
# two lines. The scripts run here through the relative path ${TOOL}.
test_install_ignores_cdpath() {
	mkdir -p "decoy/${TOOL}"
	decoy="$(CDPATH='' cd -- decoy && pwd)"
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	run env CDPATH="${decoy}" "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status with CDPATH set"
	assert_eq "$(git config --local --get filter.sops.clean)" "${INSTALLED_CMD_PREFIX}/clean-filter.sh %f" "clean filter command"
	assert_not_contains "$(git config --local --list)" "decoy" "git config"
	assert_eq "$(installed_source)" "${TOOL}" "the checkout of the tool, as recorded"
	cmp "${TOOL}/clean-filter.sh" "$(installed_dir)/clean-filter.sh" || fail "the installed copy does not come from the checkout"
	assert_eq "$(cat .env)" "A=1" "working copy"

	printf 'A=PLAINTEXT\n' >.env
	run env CDPATH="${decoy}" git add .env
	assert_eq "${RC}" "0" "git add exit status with CDPATH set"
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "index blob"
	assert_not_contains "$(stored .env)" 'PLAINTEXT' "index blob"
	run env CDPATH="${decoy}" git commit -q -m "change .env"
	assert_eq "${RC}" "0" "git commit exit status with CDPATH set"

	run env CDPATH="${decoy}" "${TOOL}/rekey.sh" --help
	assert_not_contains "${OUT}" "lib.sh is missing" "rekey.sh output"
}

# The re-smudge pass holds the plaintext in a shell variable too. A stored
# version with NUL bytes (written without the clean filter) must not be
# written to the working tree without them (audit F9).
test_install_does_not_write_a_file_with_nul_bytes_damaged() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	printf 'a\0b\n' | sops encrypt --input-type binary --output-type json \
		--filename-override bin.secret /dev/stdin >../bin.enc
	git update-index --add --cacheinfo "100644,$(git hash-object -w ../bin.enc),bin.secret"
	git commit -q -m "a text secret and a binary one"
	cd ..

	fresh_clone origin clone
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status"
	assert_contains "${OUT}" "NUL BYTES IN THE CONTENT" "install.sh report"
	assert_contains "${OUT}" "- bin.secret" "install.sh report"
	assert_eq "$(cat .env)" "A=1" "the text secret is decrypted"
	assert_eq "$(git hash-object --no-filters bin.secret)" "$(blob_id bin.secret)" "the binary one is left as ciphertext"
	assert_eq "$(git status --porcelain)" "" "git status"
}

# The re-smudge pass writes the plaintext where the working copy is. A
# working copy that is a symlink, that lies in a directory reached
# through one, or that has a second name (a hard link) leads out of the
# working tree: there it is left as ciphertext and reported (audit A-06,
# A-14). Git does not follow such a path either. The permission pass
# does not chmod through a symlinked directory.
test_install_does_not_write_through_a_link() {
	new_repo origin
	mkdir secrets
	printf 'A=1\n' >.env
	printf 'B=2\n' >secrets/app.secret
	printf 'C=3\n' >hard.secret
	printf 'D=4\n' >plain.secret
	git add .env secrets/app.secret hard.secret plain.secret
	git commit -q -m "four secrets"
	cd ..

	fresh_clone origin clone
	mkdir ../outside
	# The working copy itself is a symlink to a copy of the ciphertext.
	cp .env ../outside/target.txt
	rm .env
	ln -s ../outside/target.txt .env
	# A directory on the path is a symlink.
	mv secrets/app.secret ../outside/app.secret
	rmdir secrets
	ln -s ../outside secrets
	# A second name, outside the working tree.
	ln hard.secret ../outside/hard.txt
	chmod 644 ../outside/target.txt ../outside/app.secret

	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status"
	assert_contains "${OUT}" "REACHED THROUGH A LINK" "install.sh report"
	local name
	for name in .env secrets/app.secret hard.secret; do
		assert_contains "${OUT}" "   - ${name}" "install.sh report"
		assert_not_contains "${OUT}" "Re-smudged ${name}" "install.sh output"
	done
	assert_eq "$(git hash-object --no-filters ../outside/target.txt)" "$(blob_id .env)" "the target of the symlink"
	assert_eq "$(git hash-object --no-filters ../outside/app.secret)" "$(blob_id secrets/app.secret)" "the file in the symlinked directory"
	assert_eq "$(git hash-object --no-filters ../outside/hard.txt)" "$(blob_id hard.secret)" "the other name of the hard link"
	assert_eq "$(mode_of ../outside/target.txt)" "644" "mode of the target of the symlink"
	assert_eq "$(mode_of ../outside/app.secret)" "644" "mode of the file in the symlinked directory"
	[[ -L .env && -L secrets ]] || fail "a symlink was replaced"
	# The secret without a link is decrypted as before.
	assert_contains "${OUT}" "Re-smudged plain.secret" "install.sh output"
	assert_eq "$(cat plain.secret)" "D=4" "working copy of the secret without a link"
	assert_eq "$(mode_of plain.secret)" "600" "mode of the secret without a link"
}

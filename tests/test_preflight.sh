#!/usr/bin/env bash
# preflight.sh: can sops decrypt, asked before git needs it (audit F7).
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

test_preflight_passes_with_the_key_and_fails_without() {
	new_repo repo
	printf 'TOKEN=hunter2\n' >.env
	git add .env
	git commit -q -m "add .env"

	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status with the key"
	assert_contains "${OUT}" "decryption works (1 set(s) of keys checked)" "preflight.sh output"
	assert_not_contains "${OUT}" "hunter2" "preflight.sh output"

	run "${TOOL}/preflight.sh" --quiet
	assert_eq "${RC}" "0" "preflight.sh --quiet exit status"
	assert_eq "${OUT}" "" "preflight.sh --quiet output"

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/preflight.sh" --quiet
	assert_eq "${RC}" "1" "preflight.sh exit status without the key"
	assert_contains "${OUT}" "sops cannot decrypt .env" "preflight.sh names the file"
	assert_contains "${OUT}" "data key" "sops' own error is shown"
	# The hint fits the kind of key the file names, and only that kind.
	assert_contains "${OUT}" "age: the private key must be where sops looks" "the hint for an age key"
	assert_not_contains "${OUT}" "aws sso login" "no hint for a key service the file does not use"
	assert_contains "${OUT}" "do NOT pull" "preflight.sh says what not to do"

	# Nothing was changed by asking.
	assert_eq "$(cat .env)" "TOKEN=hunter2" "working copy"
	assert_eq "$(git status --porcelain)" "" "git status"
}

test_preflight_dotenv_format() {
	new_repo repo dotenv
	printf 'TOKEN=hunter2\n' >.env
	git add .env
	git commit -q -m "add .env"

	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status with the key"
	assert_not_contains "${OUT}" "hunter2" "preflight.sh output"

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/preflight.sh"
	assert_eq "${RC}" "1" "preflight.sh exit status without the key"
	assert_contains "${OUT}" "age: the private key must be where sops looks" "the hint for an age key"
}

# Files encrypted for different keys: one that works is not enough.
test_preflight_checks_every_set_of_keys() {
	new_repo repo
	{
		printf 'creation_rules:\n'
		printf '  - path_regex: only-b\\.secret$\n    key_groups:\n      - age:\n          - %s\n' "${AGE_PUB_B}"
		printf '  - path_regex: .*\n    key_groups:\n      - age:\n          - %s\n' "${AGE_PUB_A}"
	} >.sops.yaml
	printf 'A=1\n' >.env
	printf 'A=1\n' >same-keys.secret
	printf 'B=2\n' >only-b.secret
	# Committed by someone who holds both keys.
	cat "${SGF_TEST_ROOT}/keys/a.txt" "${AGE_KEY_B}" >../both-keys.txt
	local both="${PWD}/../both-keys.txt"
	SOPS_AGE_KEY_FILE="${both}" git add .sops.yaml .env same-keys.secret only-b.secret
	SOPS_AGE_KEY_FILE="${both}" git commit -q -m "secrets for two sets of keys"

	# Key A alone opens two of the three files.
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "1" "preflight.sh exit status with one of the two keys"
	assert_contains "${OUT}" "sops cannot decrypt only-b.secret" "preflight.sh names the file it cannot open"
	assert_not_contains "${OUT}" "cannot decrypt .env" "preflight.sh output"

	run env SOPS_AGE_KEY_FILE="${both}" "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status with both keys"
	assert_contains "${OUT}" "2 set(s) of keys checked" "one decryption per set of keys, not per file"
}

test_preflight_without_secrets_or_outside_a_repository() {
	new_repo repo
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status without any secret"
	assert_contains "${OUT}" "nothing to check" "preflight.sh output"

	run "${TOOL}/preflight.sh" --no-such-option
	assert_eq "${RC}" "2" "preflight.sh exit status for an unknown option"

	local preflight="${PWD}/${TOOL}/preflight.sh"
	mkdir ../not-a-repo
	cd ../not-a-repo || exit 1
	run env GIT_CEILING_DIRECTORIES="$(dirname "${PWD}")" "${preflight}"
	assert_eq "${RC}" "2" "preflight.sh exit status outside a repository"
}

# The same wording reaches the other places that report a failed
# decryption: the clean filter and install.sh.
test_preflight_hint_is_shared_with_the_clean_filter_and_install() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	printf 'A=2\n' >.env
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" git add .env
	assert_ne "${RC}" "0" "git add without the key"
	assert_contains "${OUT}" "age: the private key must be where sops looks" "clean filter hint"
	git checkout -q -- .env
	cd ..

	fresh_clone origin clone
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status without the key"
	assert_contains "${OUT}" "age: the private key must be where sops looks" "install.sh hint"
	assert_not_contains "${OUT}" "aws sso login" "install.sh hint"
}

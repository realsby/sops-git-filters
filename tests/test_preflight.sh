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

# Recipients A and B in one key group (either key decrypts) and in two
# groups with a threshold of 2 (both are needed) are not the same access,
# although the files name the same two keys. One must not answer for the
# other.
preflight_key_groups() { # <format>
	new_repo repo "$1"
	{
		printf 'creation_rules:\n'
		printf '  - path_regex: needs-both\\.secret$\n    shamir_threshold: 2\n    key_groups:\n'
		printf '      - age:\n          - %s\n      - age:\n          - %s\n' "${AGE_PUB_A}" "${AGE_PUB_B}"
		printf '  - path_regex: .*\n    key_groups:\n      - age:\n          - %s\n          - %s\n' "${AGE_PUB_A}" "${AGE_PUB_B}"
	} >.sops.yaml
	printf 'A=1\n' >.env
	printf 'B=2\n' >needs-both.secret
	cat "${SGF_TEST_ROOT}/keys/a.txt" "${AGE_KEY_B}" >../both-keys.txt
	local both="${PWD}/../both-keys.txt"
	SOPS_AGE_KEY_FILE="${both}" git add .sops.yaml .env needs-both.secret
	SOPS_AGE_KEY_FILE="${both}" git commit -q -m "either key for one file, both keys for the other"

	# Key A alone opens .env, which is looked at first.
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "1" "preflight.sh exit status with one of the two keys ($1)"
	assert_contains "${OUT}" "sops cannot decrypt needs-both.secret" "preflight.sh names the file that needs both keys"
	assert_not_contains "${OUT}" "cannot decrypt .env" "preflight.sh output"

	run env SOPS_AGE_KEY_FILE="${both}" "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status with both keys ($1)"
	assert_contains "${OUT}" "2 set(s) of keys checked" "the two files count as two sets"
}

test_preflight_tells_key_groups_apart() {
	preflight_key_groups json
}

test_preflight_tells_key_groups_apart_in_the_dotenv_format() {
	preflight_key_groups dotenv
}

# A check that could not look at everything is not a success: a script
# that goes by the exit status must be able to tell.
test_preflight_incomplete_check_is_not_success() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"

	# A stored version that cannot be read.
	local id object
	id="$(blob_id .env)"
	object=".git/objects/${id:0:2}/${id:2}"
	[[ -f "${object}" ]] || fail "the blob of .env is not a loose object, the test cannot hide it"
	mv "${object}" ../blob.off
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "2" "preflight.sh exit status with an unreadable blob"
	assert_contains "${OUT}" "cannot read the stored version of .env" "preflight.sh names the file"
	assert_not_contains "${OUT}" "decryption works" "preflight.sh output"
	mv ../blob.off "${object}"
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status once the blob is back"

	# An index that cannot be read: no list of files, so nothing was checked.
	cp .git/index ../index.good
	printf 'this is not an index' >.git/index
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "2" "preflight.sh exit status with an unreadable index"
	assert_contains "${OUT}" "cannot list the tracked files" "preflight.sh says why"
	assert_not_contains "${OUT}" "nothing to check" "preflight.sh output"
	cp ../index.good .git/index
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status once the index is back"
}

# Files that are not encrypted in git are not checked, and that is said.
test_preflight_mentions_files_it_did_not_check() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	printf 'B=plaintext\n' >../plain
	git update-index --add --cacheinfo "100644,$(git hash-object -w ../plain),old.secret"
	git commit -q -m "one encrypted secret, one committed without the filter"

	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status"
	assert_contains "${OUT}" "decryption works (1 set(s) of keys checked)" "preflight.sh output"
	assert_contains "${OUT}" "1 SOPS-managed file(s) are not encrypted SOPS documents" "preflight.sh output"

	# --quiet leaves out the success line, not the note: it is a warning
	# (audit S4). The exit status stays 0, decryption works.
	run "${TOOL}/preflight.sh" --quiet
	assert_eq "${RC}" "0" "preflight.sh --quiet exit status"
	assert_not_contains "${OUT}" "decryption works" "preflight.sh --quiet output"
	assert_contains "${OUT}" "1 SOPS-managed file(s) are not encrypted SOPS documents" "preflight.sh --quiet output"
	local err
	err="$("${TOOL}/preflight.sh" --quiet 2>&1 >/dev/null)"
	assert_contains "${err}" "not encrypted SOPS documents" "the note goes to stderr"
}

# Files that differ only in the version of sops that wrote them are opened
# by the same keys: one decryption answers for all of them. (A repository
# with 21 secrets written by four sops releases cost four calls to the key
# service instead of one.)
preflight_sops_versions() { # <format>
	new_repo repo "$1"
	printf 'A=1\n' >.env
	printf 'B=2\n' >b.secret
	git add .env b.secret
	git commit -q -m "two secrets"
	run "${TOOL}/preflight.sh"
	assert_contains "${OUT}" "1 set(s) of keys checked" "two files with the same keys ($1)"

	# The same blob, as an older sops would have stamped it.
	stored b.secret | sed -e 's/^sops_version=.*/sops_version=3.9.0/' \
		-e 's/^\([[:space:]]*"version": \)"[0-9.]*"/\1"3.9.0"/' >../b.older
	if cmp -s ../b.older <(stored b.secret); then
		fail "the test did not change the version field of the stored blob"
	fi
	git update-index --cacheinfo "100644,$(git hash-object -w ../b.older),b.secret"
	run "${TOOL}/preflight.sh"
	assert_eq "${RC}" "0" "preflight.sh exit status ($1)"
	assert_contains "${OUT}" "1 set(s) of keys checked" "the version of sops is not part of the set ($1)"
}

test_preflight_ignores_the_sops_version() {
	preflight_sops_versions json
}

test_preflight_ignores_the_sops_version_in_the_dotenv_format() {
	preflight_sops_versions dotenv
}

#!/usr/bin/env bash
# rekey.sh
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

decrypt_as_b() { # stdin: a json-format blob; decrypt with key B only
	SOPS_AGE_KEY_FILE="${AGE_KEY_B}" sops decrypt --input-type json --output-type binary /dev/stdin
}

test_rekey_adds_a_recipient() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "add recipient B"

	# Touching and re-adding changes nothing: the plaintext is the same,
	# so the clean filter reuses the stored blob.
	touch .env
	git add .env
	assert_not_contains "$(stored .env)" "${AGE_PUB_B}" "blob after touch + add"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_eq "$(stored .env | decrypt_as_b)" "A=1" "key B decrypts the staged blob"
	assert_eq "$(cat .env)" "A=1" "working copy is untouched"
	assert_eq "$(git status --porcelain)" "M  .env" "staged, nothing else"

	git commit -q -m "re-key for B"
	local id
	id="$(blob_id .env)"
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "second run"
	assert_contains "${OUT}" "0 file(s) re-keyed" "second run output"
	assert_eq "$(blob_id .env)" "${id}" "blob after a second run"
}

test_rekey_removes_a_recipient() {
	new_repo repo
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "recipients A and B"
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	assert_eq "$(stored .env | decrypt_as_b)" "A=1" "key B decrypts before"

	# shellcheck disable=SC2119  # back to key A only
	write_sops_yaml
	git add .sops.yaml
	git commit -q -m "remove recipient B"
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_not_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	run decrypt_as_b <<<"$(stored .env)"
	assert_ne "${RC}" "0" "key B must not decrypt the re-keyed blob"
	assert_eq "$(plain_of_stored .env)" "A=1" "key A still decrypts"
}

test_rekey_dotenv_nested_file() {
	new_repo repo dotenv
	mkdir -p stacks/app
	printf 'A=1\n' >stacks/app/.env
	git add stacks/app/.env
	git commit -q -m "add a nested .env"
	write_sops_yaml "${AGE_PUB_B}"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "$(stored stacks/app/.env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_eq "$(plain_of_stored stacks/app/.env dotenv)" "A=1" "plaintext"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard after the re-key"
}

# sops picks the creation rule by the file's path relative to .sops.yaml.
# The copies rekey.sh works on must sit at the same relative paths.
test_rekey_follows_path_rules() {
	new_repo repo
	mkdir -p team
	printf 'X=1\n' >team/shared.secret
	printf 'Y=1\n' >private.secret
	git add team/shared.secret private.secret
	git commit -q -m "two secrets, key A only"

	cat >.sops.yaml <<YAML
creation_rules:
  - path_regex: ^team/
    key_groups:
      - age:
          - ${AGE_PUB_A}
          - ${AGE_PUB_B}
  - path_regex: .*
    key_groups:
      - age:
          - ${AGE_PUB_A}
YAML
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "$(stored team/shared.secret)" "${AGE_PUB_B}" "team/ file gets recipient B"
	assert_not_contains "$(stored private.secret)" "${AGE_PUB_B}" "the other file does not"
}

test_rekey_dry_run_and_path_limit() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'B=1\n' >other.secret
	git add .env other.secret
	git commit -q -m "two secrets"
	write_sops_yaml "${AGE_PUB_B}"
	local env_id other_id
	env_id="$(blob_id .env)"
	other_id="$(blob_id other.secret)"

	run "${TOOL}/rekey.sh" --dry-run
	assert_eq "${RC}" "0" "dry run exit status"
	assert_contains "${OUT}" "would re-key  .env" "dry run output"
	assert_eq "$(blob_id .env)" "${env_id}" "dry run stages nothing"

	run "${TOOL}/rekey.sh" other.secret
	assert_eq "${RC}" "0" "limited run exit status"
	assert_ne "$(blob_id other.secret)" "${other_id}" "the named file is re-keyed"
	assert_eq "$(blob_id .env)" "${env_id}" "the other file is left alone"
}

test_rekey_reports_a_plaintext_blob() {
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

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "1" "rekey.sh exit status"
	assert_contains "${OUT}" "FAILED  .env" "rekey.sh output"
	assert_eq "$(stored .env)" "P=legacy" "the blob is left alone"
}

test_rekey_without_keys_fails_and_stages_nothing() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	write_sops_yaml "${AGE_PUB_B}"
	local id
	id="$(blob_id .env)"

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/rekey.sh"
	assert_eq "${RC}" "1" "rekey.sh exit status"
	assert_eq "$(blob_id .env)" "${id}" "nothing staged"
	assert_eq "$(ls -d .git/sops-rekey.* 2>/dev/null || true)" "" "work directory removed"
}

# git could not write the index (another git process holds the lock, or
# the lock file of a crashed one is still there). Then nothing was
# re-keyed, and rekey.sh must say so and fail.
test_rekey_fails_when_the_index_cannot_be_written() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "add recipient B"
	local before
	before="$(blob_id .env)"

	: >.git/index.lock
	run "${TOOL}/rekey.sh"
	rm -f .git/index.lock
	assert_ne "${RC}" "0" "rekey.sh exit status while the index is locked"
	assert_contains "${OUT}" "FAILED  .env" "rekey.sh output"
	assert_not_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	assert_contains "${OUT}" "0 file(s) re-keyed and staged, 0 already match .sops.yaml, 1 failed" "rekey.sh summary"
	assert_eq "$(blob_id .env)" "${before}" "index entry after the failed run"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status without the lock"
	assert_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
}

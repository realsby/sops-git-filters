#!/usr/bin/env bash
# clean-filter.sh
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

# A .sops-filter.conf may set SOPS_FILE_MODE only and keep the default format.
test_clean_accepts_conf_without_store_format() {
	new_repo repo
	printf '# widen for a deploy daemon\nSOPS_FILE_MODE=640\n' >.sops-filter.conf
	printf 'A=1\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add exit status"
	assert_contains "$(stored .env)" 'ENC[AES256_GCM,data:' "stored blob"
}

# .sops.yaml decides who can decrypt, not variables left in the shell.
test_clean_ignores_recipient_variables() {
	new_repo repo
	printf 'A=1\n' >.env
	SOPS_AGE_RECIPIENTS="${AGE_PUB_B}" git add .env

	local blob
	blob="$(stored .env)"
	assert_contains "${blob}" "${AGE_PUB_A}" "recipient from .sops.yaml"
	assert_not_contains "${blob}" "${AGE_PUB_B}" "recipient from the environment"

	# A KMS key named in the environment must not be contacted either.
	printf 'B=2\n' >other.secret
	run env SOPS_KMS_ARN="arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000" git add other.secret
	assert_eq "${RC}" "0" "git add with SOPS_KMS_ARN set"
	assert_not_contains "$(stored other.secret)" '"kms": [' "kms entry in the stored blob"
}

# The filter must check what sops returns. This stand-in behaves like
# sops <= 3.10.2 under a creation rule with encrypted_regex: a proper
# envelope around content left in clear.
test_clean_refuses_envelope_with_plaintext_data() {
	new_repo repo
	stub ../fakebin sops <<'STUB'
if [[ "$1" == "encrypt" ]]; then
	plain="$(cat)"
	printf '{\n\t"data": "%s",\n\t"sops": {\n\t\t"mac": "ENC[AES256_GCM,data:AAAA,iv:AAAA,tag:AAAA,type:str]",\n\t\t"version": "3.10.2"\n\t}\n}\n' "${plain}"
	exit 0
fi
exec "${REAL}" "$@"
STUB
	printf 'TOP-SECRET\n' >deploy.secret
	run env PATH="${PWD}/../fakebin:${PATH}" git add deploy.secret
	assert_ne "${RC}" "0" "git add exit status"
	assert_contains "${OUT}" "did not encrypt deploy.secret completely" "filter message"
	assert_eq "$(git ls-files -s -- deploy.secret)" "" "nothing staged"
}

# With a real sops and a rule that does not select the "data" key: either
# the file is encrypted in full or the add fails. Never plaintext.
test_clean_json_partial_rule_never_stores_plaintext() {
	new_repo repo
	cat >.sops.yaml <<YAML
creation_rules:
  - path_regex: .*
    encrypted_regex: '^(password|apiKey)\$'
    key_groups:
      - age:
          - ${AGE_PUB_A}
YAML
	printf 'TOP-SECRET\n' >deploy.secret
	run git add deploy.secret
	if [[ "${RC}" -eq 0 ]]; then
		assert_contains "$(stored deploy.secret)" '"data": "ENC[AES256_GCM,data:' "stored blob"
		assert_not_contains "$(stored deploy.secret)" 'TOP-SECRET' "stored blob"
	else
		assert_eq "$(git ls-files -s -- deploy.secret)" "" "nothing staged"
	fi
}

# dotenv: sops honours encrypted_regex there, so a value could stay in clear.
test_clean_dotenv_refuses_partial_encryption_rule() {
	new_repo repo dotenv
	cat >.sops.yaml <<YAML
creation_rules:
  - path_regex: .*
    encrypted_regex: '^(PASSWORD|TOKEN)\$'
    key_groups:
      - age:
          - ${AGE_PUB_A}
YAML
	printf 'PASSWORD=p1\nDATABASE_URL=postgres://user:hunter2@db/prod\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_eq "$(git ls-files -s -- .env)" "" "nothing staged"
}

# dotenv: sops keeps keys ending in _unencrypted in clear by default.
test_clean_dotenv_refuses_unencrypted_suffix_key() {
	new_repo repo dotenv
	printf 'A=1\nDEBUG_unencrypted=true\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_eq "$(git ls-files -s -- .env)" "" "nothing staged"
}

# dotenv: the continuation lines of a quoted multi-line value would become
# plaintext KEYS (everything left of "=" is a key to sops).
test_clean_dotenv_refuses_multiline_value() {
	new_repo repo dotenv
	printf 'DB=x\nKEYS="c2VjcmV0LTE=\nc2VjcmV0LTI=="\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_contains "${OUT}" "line 2" "message names the line"
	assert_not_contains "${OUT}" "c2VjcmV0" "message must not print the content"
	assert_eq "$(git ls-files -s -- .env)" "" "nothing staged"
}

# dotenv: a line without "=" made sops print that line in its error.
test_clean_dotenv_error_does_not_print_the_line() {
	new_repo repo dotenv
	printf 'A=1\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_contains "${OUT}" "line 2" "message names the line"
	assert_not_contains "${OUT}" "MIIEvQIBADANBg" "message must not print the content"
}

test_clean_dotenv_accepts_common_forms() {
	new_repo repo dotenv
	cat >.env <<'ENV'
# a comment
#
PLAIN=value
export EXPORTED=yes
QUOTED="two words"
SINGLE='it is'
WITH_NOTE="quoted" # trailing note
EMPTY=
dotted.key-name=1
URL=postgres://user:pw@host/db?sslmode=require
ENV
	run git add .env
	assert_eq "${RC}" "0" "git add exit status"
	assert_eq "$(plain_of_stored .env dotenv)" "$(cat .env)" "round trip"
	assert_not_contains "$(stored .env)" 'two words' "stored blob"
}

# A file of a megabyte or more must not take minutes. The checks on the
# document run in awk for that reason (see lib.sh).
test_clean_large_file_is_fast() {
	new_repo repo
	awk 'BEGIN { for (i = 0; i < 40000; i++) print "line " i " of a large secret file" }' >large.secret
	assert_eq "$(($(wc -c <large.secret) > 1000000))" "1" "the test file is over 1 MB"

	SECONDS=0
	git add large.secret
	git commit -q -m "add a large secret"
	touch large.secret
	assert_eq "$(git status --porcelain)" "" "git status"
	cp large.secret ../expected
	mv large.secret ../moved
	git checkout -- large.secret
	cmp large.secret ../expected
	[[ "${SECONDS}" -lt 60 ]] || fail "add, status and checkout of a 1 MB file took ${SECONDS}s"
}

# install.sh ran while the key was unavailable: the filters are on and the
# working copy still holds ciphertext. Nothing may encrypt it a second time.
test_clean_stores_ciphertext_input_unchanged() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
	assert_contains "$(cat .env)" 'ENC[AES256_GCM' "working copy still holds ciphertext"
	local id
	id="$(blob_id .env)"

	# The key is back, and the user just keeps working.
	touch .env
	assert_eq "$(git status --porcelain)" "" "git status"
	echo note >note.txt
	git add -A
	git commit -q -m "unrelated work"
	assert_eq "$(blob_id .env)" "${id}" "blob of .env after git add -A"
	assert_eq "$(plain_of_stored .env)" "A=1" "one layer of encryption"

	# install.sh can still decrypt the working copy afterwards.
	"${TOOL}/install.sh"
	assert_eq "$(cat .env)" "A=1" "working copy after install.sh"
	assert_eq "$(git status --porcelain)" "" "git status"
}

# "Stored unchanged" is only for a document sops wrote. An envelope with a
# secret in clear added to it is content like any other: it is encrypted.
# The first input is the example from the review of that shortcut.
test_clean_encrypts_an_envelope_with_plaintext_added() {
	new_repo repo
	printf '{"data":"","sops":{},"credentials":{"password":"hunter2"}}\n' >one.secret
	git add one.secret
	assert_not_contains "$(stored one.secret)" "hunter2" "index blob"
	assert_eq "$(plain_of_stored one.secret)" '{"data":"","sops":{},"credentials":{"password":"hunter2"}}' "decrypted blob"

	# a real ciphertext working copy, edited by hand
	printf 'A=1\n' >two.secret
	git add two.secret
	git commit -q -m "two secrets"
	local envelope
	envelope="$(stored two.secret)"
	printf '%s\n' "${envelope}" | sed '$d' >two.secret
	printf ',\n\t"credentials": {"password": "hunter2"}\n}\n' >>two.secret
	assert_contains "$(cat two.secret)" '"data": "ENC[AES256_GCM' "test fixture: a real envelope"
	git add two.secret
	assert_not_contains "$(stored two.secret)" "hunter2" "index blob of the edited envelope"
	assert_contains "$(plain_of_stored two.secret)" '"password": "hunter2"' "decrypted blob of the edited envelope"
}

# Plaintext in the working copy, but the stored version cannot be decrypted
# (key missing). The filter must stop, not re-encrypt an unchanged file.
test_clean_stops_when_stored_version_cannot_be_decrypted() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	local id
	id="$(blob_id .env)"

	touch .env
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" git add .env
	assert_ne "${RC}" "0" "git add without the decryption key"
	assert_contains "${OUT}" "cannot decrypt the version of .env that git holds" "filter message"
	assert_contains "${OUT}" "data key" "sops' own error is shown"
	assert_eq "$(blob_id .env)" "${id}" "index blob"

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" git commit -q -am "no real change"
	assert_ne "${RC}" "0" "git commit -a without the decryption key"

	# With the key the file is simply unchanged.
	assert_eq "$(git status --porcelain)" "" "git status with the key"
}

test_clean_force_reencrypt_gives_a_new_blob() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	local id
	id="$(blob_id .env)"

	SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- .env
	assert_ne "$(blob_id .env)" "${id}" "blob after a forced re-encryption"
	assert_eq "$(plain_of_stored .env)" "A=1" "plaintext"
}

# A storage-format change re-encrypts every file. That needs an explicit step.
test_clean_format_change_needs_the_override() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env (json)"

	printf 'SOPS_STORE_FORMAT=dotenv\n' >.sops-filter.conf
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "3" "install.sh exit status during the change"

	touch .env
	run git add .env
	assert_ne "${RC}" "0" "plain git add during the change"
	assert_contains "${OUT}" "SOPS_FILTER_FORCE_REENCRYPT=1" "filter message"

	SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- .env
	assert_contains "$(stored .env)" 'A=ENC[AES256_GCM,data:' "blob in the dotenv format"
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status after the change"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard after the change"
}

test_clean_refuses_ciphertext_in_the_other_format() {
	new_repo repo
	printf 'A=1\n' | sops encrypt --input-type dotenv --output-type dotenv --filename-override any.env /dev/stdin >x.secret
	run git add x.secret
	assert_ne "${RC}" "0" "git add exit status"
	assert_contains "${OUT}" "in the dotenv format" "filter message"
}

# An empty file decrypts to nothing. That is still "unchanged".
test_clean_empty_file_keeps_its_blob() {
	new_repo repo
	: >empty.secret
	git add empty.secret
	git commit -q -m "add an empty secret"
	local id
	id="$(blob_id empty.secret)"

	touch empty.secret
	git add empty.secret
	assert_eq "$(blob_id empty.secret)" "${id}" "blob id after touch + add"
	assert_eq "$(git status --porcelain)" "" "git status"
}

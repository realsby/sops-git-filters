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

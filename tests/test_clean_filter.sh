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

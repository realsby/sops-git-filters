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

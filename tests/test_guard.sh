#!/usr/bin/env bash
# encryption-guard.sh
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

# A repository where install.sh never ran: no filter, the guard is the
# only control. Leaves the caller inside it.
unfiltered_repo() { # [json|dotenv]
	git init -q repo
	cd repo || exit 1
	vendor_tool
	write_sops_yaml
	printf '.env filter=sops diff=sops\n*.secret filter=sops diff=sops\n' >.gitattributes
	if [[ "${1:-json}" != "json" ]]; then
		printf 'SOPS_STORE_FORMAT=%s\n' "$1" >.sops-filter.conf
	fi
	git add -A
	git commit -q -m scaffold
}

test_guard_passes_encrypted_files() {
	new_repo repo
	printf 'A=1\n' >.env
	: >empty.secret
	git add .env empty.secret
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status (json)"
	cd ..

	new_repo repo2 dotenv
	printf '# note\nA=1\nEMPTY=\n' >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status (dotenv)"
}

test_guard_blocks_plaintext_that_mentions_the_marker() {
	unfiltered_repo
	printf 'PW=hunter2\n# old value was ENC[AES256_GCM,data:xxxx]\n' >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "- .env" "guard names the file"
}

test_guard_blocks_partly_encrypted_dotenv() {
	unfiltered_repo dotenv
	{
		printf 'A=1\n' | sops encrypt --input-type dotenv --output-type dotenv --filename-override any.env /dev/stdin
		printf 'API_TOKEN=this-value-is-not-encrypted\n'
	} >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
}

# A SOPS envelope whose content is in clear. Its MAC is ENC[...] all the same.
test_guard_blocks_envelope_with_plaintext_data() {
	unfiltered_repo
	printf 'x\n' | sops encrypt --input-type binary --output-type json --filename-override any.secret /dev/stdin |
		sed 's/"data": "ENC[^"]*"/"data": "key material in clear"/' >key.secret
	assert_contains "$(cat key.secret)" '"data": "key material in clear"' "test fixture"
	assert_contains "$(cat key.secret)" 'ENC[AES256_GCM' "test fixture keeps an encrypted MAC"
	git add key.secret
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
}

# ":2:prod.secret" is git syntax for "index stage 2 of prod.secret".
test_guard_checks_files_named_like_an_index_stage() {
	unfiltered_repo
	printf 'TOKEN=plaintext\n' >'2:prod.secret'
	git add './2:prod.secret'
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "2:prod.secret" "guard names the file"
}

# Git never filters a symlink, so there is nothing to encrypt.
test_guard_ignores_symlinks() {
	unfiltered_repo
	ln -s ../shared/.env .env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status"
}

# A secret committed in plaintext earlier is not part of the next commit's
# diff. The guard must still see it.
test_guard_blocks_plaintext_tracked_earlier() {
	unfiltered_repo
	printf 'PW=hunter2\n' >.env
	git add .env
	git commit -q -m "plaintext slipped in"
	echo docs >README.txt
	git add README.txt
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status on an unrelated commit"
	assert_contains "${OUT}" "- .env" "guard names the file"
}

# If the guard cannot read the attributes it must not wave the commit through.
test_guard_fails_closed_when_check_attr_fails() {
	unfiltered_repo
	printf 'PW=hunter2\n' >.env
	git add .env
	stub ../fakebin git <<'STUB'
if [[ "$1" == "check-attr" ]]; then
	echo "fatal: simulated check-attr failure" >&2
	exit 128
fi
exec "${REAL}" "$@"
STUB
	run env PATH="${PWD}/../fakebin:${PATH}" "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "COMMIT BLOCKED" "guard message"
}

test_guard_blocks_when_sops_yaml_is_missing() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	git rm -q --cached .sops.yaml
	mv .sops.yaml sops.yaml.off
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "SOPS not configured" "guard message"
}

# README: ln -s ../../utilities/sops-git-filters/encryption-guard.sh .git/hooks/pre-commit
test_guard_works_as_a_symlinked_hook() {
	unfiltered_repo
	mkdir -p .git/hooks
	ln -s "../../${TOOL}/encryption-guard.sh" .git/hooks/pre-commit

	echo docs >README.txt
	git add README.txt
	run git commit -q -m "no secrets involved"
	assert_eq "${RC}" "0" "commit without managed files"

	printf 'PW=hunter2\n' >.env
	git add .env
	run git commit -q -m "plaintext secret"
	assert_ne "${RC}" "0" "commit with a plaintext secret"
	assert_contains "${OUT}" "COMMIT BLOCKED" "guard message"
}

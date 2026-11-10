#!/usr/bin/env bash
# The behaviour the README promises. These must pass on every version.
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

test_basics_json_add_encrypts_and_reuses_blob() {
	new_repo repo
	printf 'DB_PASSWORD=hunter2\nAPI_KEY=abc123\n' >.env
	git add .env

	local blob
	blob="$(stored .env)"
	assert_contains "${blob}" 'ENC[AES256_GCM,data:' "stored blob"
	assert_not_contains "${blob}" 'hunter2' "stored blob"
	assert_eq "$(plain_of_stored .env)" "$(cat .env)" "decrypted blob"
	git commit -q -m "add .env"

	# Same plaintext → the very same blob, so no false diff.
	local id
	id="$(blob_id .env)"
	touch .env
	git add .env
	assert_eq "$(blob_id .env)" "${id}" "blob id after touch + add"
	assert_eq "$(git status --porcelain)" "" "git status"
}

test_basics_dotenv_add_encrypts_values_only() {
	new_repo repo dotenv
	printf '# database\nDB_PASSWORD=hunter2\nAPI_KEY=abc123\n' >.env
	git add .env

	local blob
	blob="$(stored .env)"
	assert_contains "${blob}" 'DB_PASSWORD=ENC[AES256_GCM,data:' "stored blob"
	assert_not_contains "${blob}" 'hunter2' "stored blob"
	assert_not_contains "${blob}" '# database' "comments are encrypted too"
	assert_eq "$(plain_of_stored .env dotenv)" "$(cat .env)" "decrypted blob"
	git commit -q -m "add .env"

	local id
	id="$(blob_id .env)"
	touch .env
	git add .env
	assert_eq "$(blob_id .env)" "${id}" "blob id after touch + add"
	assert_eq "$(git status --porcelain)" "" "git status"
}

test_basics_fresh_clone_is_decrypted_by_install() {
	new_repo origin
	printf 'DB_PASSWORD=hunter2\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..

	fresh_clone origin clone
	assert_contains "$(cat .env)" 'ENC[AES256_GCM' "fresh clone holds ciphertext"

	"${TOOL}/install.sh"
	assert_eq "$(cat .env)" "DB_PASSWORD=hunter2" "working copy after install.sh"
	assert_eq "$(git status --porcelain)" "" "git status"
	assert_eq "$(git config --local --get filter.sops.required)" "true" "filter.sops.required"
}

test_basics_install_twice_changes_nothing() {
	new_repo repo
	printf 'DB_PASSWORD=hunter2\n' >.env
	git add .env
	git commit -q -m "add .env"

	local before
	before="$(git config --local --list)"
	"${TOOL}/install.sh"
	assert_eq "$(git config --local --list)" "${before}" "local git config"
	assert_eq "$(git status --porcelain)" "" "git status"
	assert_eq "$(cat .env)" "DB_PASSWORD=hunter2" "working copy"
}

test_basics_failing_clean_filter_aborts_git_add() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	local id
	id="$(blob_id .env)"

	mv .sops.yaml sops.yaml.off
	printf 'A=changed\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add exit status"
	assert_eq "$(blob_id .env)" "${id}" "index keeps the previous ciphertext"
}

test_basics_guard_blocks_plaintext_and_passes_ciphertext() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard on an encrypted blob"
	git commit -q -m "add .env"
	cd ..

	# A clone where install.sh never ran: no filter, the guard is all there is.
	fresh_clone origin clone
	printf 'A=plaintext\n' >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard on a plaintext blob"
	assert_contains "${OUT}" "COMMIT BLOCKED" "guard message"
}

test_basics_stash_holds_ciphertext_only() {
	new_repo repo
	printf 'TOKEN=base\n' >.env
	git add .env
	git commit -q -m "add .env"

	printf 'TOKEN=SEKRIT-unstaged\n' >.env
	printf 'TOKEN=SEKRIT-untracked\n' >new.secret
	git stash push -q -u -m wip

	local id leaked=""
	for id in $(git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)' | awk '$2 == "blob" {print $1}'); do
		if git cat-file blob "${id}" | grep -q 'SEKRIT'; then
			leaked="${leaked} ${id}"
		fi
	done
	assert_eq "${leaked}" "" "blobs containing plaintext"

	git stash pop -q
	assert_eq "$(cat .env)" "TOKEN=SEKRIT-unstaged" "working copy after stash pop"
	assert_eq "$(cat new.secret)" "TOKEN=SEKRIT-untracked" "untracked file after stash pop"
}

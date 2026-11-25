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

# A complete SOPS document with a secret in clear next to it: after the
# metadata, or in a line named like metadata. These are the examples
# from the review of the document check.
test_guard_blocks_plaintext_next_to_the_envelope() {
	unfiltered_repo
	printf '{"data":"","sops":{},"credentials":{"password":"hunter2"}}\n' >one.secret
	printf 'x\n' | sops encrypt --input-type binary --output-type json --filename-override any.secret /dev/stdin |
		sed '$d' >two.secret
	printf ',\n\t"credentials": {"password": "hunter2"}\n}\n' >>two.secret
	assert_contains "$(cat two.secret)" '"data": "ENC[AES256_GCM' "test fixture: a real envelope"
	git add one.secret two.secret
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "- one.secret" "guard names the file"
	assert_contains "${OUT}" "- two.secret" "guard names the file"
	assert_not_contains "${OUT}" "hunter2" "guard output"
}

test_guard_blocks_plaintext_in_a_sops_prefixed_line() {
	unfiltered_repo dotenv
	{
		printf 'A=1\n' | sops encrypt --input-type dotenv --output-type dotenv --filename-override any.env /dev/stdin
		printf 'sops_API_TOKEN=hunter2\n'
	} >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "- .env" "guard names the file"
	assert_not_contains "${OUT}" "hunter2" "guard output"
}

# The guard checks the whole index. Started in a subdirectory (by hand,
# or by a CI step that changed directory), it must still see a secret
# that is not below that directory.
test_guard_checks_the_whole_repository_from_a_subdirectory() {
	unfiltered_repo
	mkdir -p docs sub
	echo text >docs/readme.txt
	printf 'PW=hunter2\n' >.env
	printf 'TOKEN=abc\n' >sub/deploy.secret
	git add docs/readme.txt .env sub/deploy.secret
	cd docs || exit 1
	run "../${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status from a subdirectory"
	assert_contains "${OUT}" "- .env" "guard names the file at the top"
	assert_contains "${OUT}" "- sub/deploy.secret" "guard names the file in another directory"
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

# stage_raw <path> <file> : put the bytes of <file> into the index as
# <path>, the way a clone without the filters stages a file. No filter
# runs, and the content is stored byte for byte.
stage_raw() {
	local oid
	oid="$(git hash-object -w --no-filters -- "$2")"
	git update-index --add --cacheinfo "100644,${oid},$1"
}

# The awk of macOS ends a line at a NUL byte and never sees the rest of
# it. A complete SOPS document with plaintext hidden behind a NUL byte
# must still be refused (audit A-12).
test_guard_blocks_plaintext_after_a_nul_byte() {
	unfiltered_repo dotenv
	{
		printf 'A=1\n' | sops encrypt --input-type dotenv --output-type dotenv --filename-override any.env /dev/stdin
		printf '\000DB_PASSWORD=hunter2\n'
	} >../dotenv.blob
	stage_raw .env ../dotenv.blob
	assert_eq "$(stored .env | tr -cd '\000' | wc -c | tr -d ' ')" "1" "test fixture: one NUL byte in the index"
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status (dotenv)"
	assert_contains "${OUT}" "- .env  (it holds NUL bytes (1)" "guard names the file and the cause"
	assert_not_contains "${OUT}" "hunter2" "guard output"
	cd ..

	# json: the NUL byte follows a valid line of the document.
	git init -q repo2
	cd repo2 || exit 1
	vendor_tool
	write_sops_yaml
	printf '*.secret filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m scaffold
	printf 'x\n' | sops encrypt --input-type binary --output-type json --filename-override any.secret /dev/stdin >../doc.json
	assert_contains "$(sed -n 2p ../doc.json)" '"data": "ENC[AES256_GCM' "test fixture: line 2 holds the data"
	{
		sed -n 1p ../doc.json
		sed -n 2p ../doc.json | tr -d '\n'
		printf '\000 DB_PASSWORD=hunter2\n'
		sed -n '3,$p' ../doc.json
	} >../json.blob
	stage_raw key.secret ../json.blob
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status (json)"
	assert_contains "${OUT}" "- key.secret  (it holds NUL bytes (1)" "guard names the file and the cause"
	assert_not_contains "${OUT}" "hunter2" "guard output"

	# The same document without the NUL byte and the plaintext passes.
	stage_raw key.secret ../doc.json
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status for the plain document"
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

# The commit carries the .gitattributes of the index. A local edit that
# takes filter=sops off a path, and is not staged, also keeps `git add`
# from running the filter: the guard must not take its cue from that
# same unstaged file (audit A-11).
test_guard_reads_the_attributes_of_the_index() {
	new_repo repo
	echo '.env -filter' >>.gitattributes
	printf 'PW=hunter2\n' >.env
	git add .env
	assert_contains "$(stored .env)" "hunter2" "test fixture: plaintext in the index"
	assert_contains "$(git show :.gitattributes)" ".env filter=sops" "test fixture: the index marks .env"
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "- .env" "guard names the file"
	assert_not_contains "${OUT}" "hunter2" "guard output"
}

# If the guard cannot read the attributes it must not wave the commit through.
test_guard_fails_closed_when_check_attr_fails() {
	unfiltered_repo
	printf 'PW=hunter2\n' >.env
	git add .env
	stub ../fakebin git <<'STUB'
case " $* " in
*" check-attr "*)
	echo "fatal: simulated check-attr failure" >&2
	exit 128
	;;
esac
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

# After SOPS_STORE_FORMAT changes, the blobs are still encrypted, in the
# old format. That is not plaintext, and the message must say so.
test_guard_names_an_unfinished_format_change() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env (json)"

	# Not staged on purpose: the guard reads the format from the working
	# tree, and during a format change any git command that re-checks
	# .env is refused by the clean filter.
	printf 'SOPS_STORE_FORMAT=dotenv\n' >.sops-filter.conf
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "stored in the other format" "guard message"
	assert_contains "${OUT}" "SOPS_FILTER_FORCE_REENCRYPT=1" "guard names the command"
	assert_not_contains "${OUT}" "are not encrypted" "guard message"
}

# `git add -N <file>` (intent to add) puts the path in the index with the
# empty blob, which is no SOPS document. Such an entry never reaches a
# commit as it is: a plain `git commit` leaves it out, and `git commit -a`
# or `git commit -- <file>` stage the content, through the filter, before
# the hook runs. So it must not block a commit (audit A-05).
test_guard_passes_while_a_secret_is_intent_to_add() {
	new_repo repo
	mkdir -p .git/hooks
	ln -s "../../${TOOL}/encryption-guard.sh" .git/hooks/pre-commit
	printf 'PW=hunter2\n' >a.secret
	printf 'TOKEN=abc\n' >b.secret
	git add -N a.secret b.secret

	echo docs >README.txt
	git add README.txt
	run git commit -q -m "readme only"
	assert_eq "${RC}" "0" "commit of another file"
	assert_eq "$(git diff-tree --no-commit-id --name-only -r HEAD)" "README.txt" "files in the commit"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard started by hand"

	run git commit -q -m "a.secret" -- a.secret
	assert_eq "${RC}" "0" "git commit -- a.secret"
	assert_contains "$(git show HEAD:a.secret)" '"data": "ENC[AES256_GCM' "a.secret in the commit"
	assert_eq "$(plain_of_stored a.secret)" "PW=hunter2" "a.secret decrypts"

	run git commit -q -a -m "everything"
	assert_eq "${RC}" "0" "git commit -a"
	assert_contains "$(git show HEAD:b.secret)" '"data": "ENC[AES256_GCM' "b.secret in the commit"
	assert_not_contains "$(git show HEAD:b.secret)" "abc" "b.secret in the commit"
}

# Only an intent-to-add entry is let through. An empty blob that is
# really staged, and plaintext next to an intent-to-add entry, still
# block the commit.
test_guard_blocks_plaintext_next_to_an_intent_to_add_entry() {
	unfiltered_repo
	printf 'PW=hunter2\n' >new.secret
	git add -N new.secret
	printf 'TOKEN=abc\n' >.env
	git add .env
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "- .env" "guard names the plaintext file"
	assert_not_contains "${OUT}" "- new.secret" "guard output"

	git rm -q --cached .env
	: >empty.secret
	git add empty.secret
	assert_eq "$(blob_id empty.secret)" "$(blob_id new.secret)" "test fixture: both hold the empty blob"
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status for an empty blob that is staged"
	assert_contains "${OUT}" "- empty.secret" "guard names the empty file"
	assert_not_contains "${OUT}" "- new.secret" "guard output"
}

# When the guard cannot tell that an entry is left out of the commit, it
# checks the entry as before: an empty blob blocks the commit.
test_guard_fails_closed_when_it_cannot_classify_an_intent_to_add_entry() {
	unfiltered_repo
	printf 'PW=hunter2\n' >new.secret
	git add -N new.secret
	stub ../fakebin git <<'STUB'
case " $* " in
*" write-tree "*)
	echo "fatal: simulated write-tree failure" >&2
	exit 128
	;;
esac
exec "${REAL}" "$@"
STUB
	run env PATH="${PWD}/../fakebin:${PATH}" "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "- new.secret" "guard names the entry"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status with a working git"
}

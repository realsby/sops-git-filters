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
	printf '{\n\t"data": "%s",\n\t"sops": {\n\t\t"mac": "ENC[AES256_GCM,data:AAAA,iv:aK0NDUmGF5rgQKERiDsl8ZmCs+7aY6DdOPGhvm21fiw=,tag:jZYZLFyNneDOtZnXYZjGaQ==,type:str]",\n\t\t"version": "3.10.2"\n\t}\n}\n' "${plain}"
	exit 0
fi
exec "${REAL}" "$@"
STUB
	printf 'TOP-SECRET\n' >deploy.secret
	run env PATH="${PWD}/../fakebin:${PATH}" git add deploy.secret
	assert_ne "${RC}" "0" "git add exit status"
	assert_contains "${OUT}" "did not encrypt deploy.secret completely" "filter message"
	assert_contains "${OUT}" 'Found: "data" is not encrypted.' "what the check found"
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

# ── A SOPS document that is not the version git holds (audit A-13) ────
# Only the ciphertext git already holds (index or HEAD) is stored as it is.
# Before, any SOPS document was: one copied from another project, or a
# forged one, was committed with exit status 0, and the next checkout of
# every teammate stopped half-way.

# encrypt_for <json|dotenv> <age recipient>[,<recipient>...]   (plaintext on
# stdin) : a SOPS document for exactly those keys, whatever .sops.yaml says
encrypt_for() {
	local type=binary out=json
	if [[ "$1" == "dotenv" ]]; then
		type=dotenv
		out=dotenv
	fi
	sops encrypt --age "$2" --input-type "${type}" --output-type "${out}" --filename-override any.secret /dev/stdin
}

# A file copied from another project, encrypted for that project's key
# only (key B stands in for it). .sops.yaml names key A; the user holds A.
test_clean_refuses_a_sops_document_for_other_keys() {
	local format id
	for format in json dotenv; do
		new_repo "${format}" "${format}"
		printf 'A=1\n' >.env
		git add .env
		git commit -q -m "add .env"
		id="$(blob_id .env)"

		printf 'A=from-another-project\n' | encrypt_for "${format}" "${AGE_PUB_B}" >../foreign
		cp ../foreign .env
		run git add .env
		assert_ne "${RC}" "0" "git add exit status (${format})"
		assert_contains "${OUT}" "does not decrypt with your keys" "filter message (${format})"
		assert_contains "${OUT}" "another project" "filter message names the likely causes (${format})"
		assert_eq "$(blob_id .env)" "${id}" "index blob (${format})"
		run git commit -q -am "commit the copy"
		assert_ne "${RC}" "0" "git commit -a exit status (${format})"
		assert_eq "$(git rev-parse HEAD:.env)" "${id}" "committed blob (${format})"

		# A new file: nothing to compare with, the same refusal.
		cp ../foreign new.secret
		run git add new.secret
		assert_ne "${RC}" "0" "git add of a new file (${format})"
		assert_eq "$(git ls-files -s -- new.secret)" "" "nothing staged (${format})"
		cd ..
	done
}

# A real document with its ciphertext replaced by hand: the structure is
# right, the MAC no longer matches. Only a decrypt notices.
# TXlQYXNzd29yZDEy is "MyPassword12" in base64.
test_clean_refuses_a_forged_sops_document() {
	local format id blob data
	for format in json dotenv; do
		new_repo "${format}" "${format}"
		printf 'A=1\n' >.env
		git add .env
		git commit -q -m "add .env"
		id="$(blob_id .env)"

		blob="$(stored .env)"
		data="$(printf '%s\n' "${blob}" | grep -o 'ENC\[AES256_GCM,data:[^,]*' | head -1)"
		data="${data#ENC[AES256_GCM,data:}"
		printf '%s\n' "${blob}" | swap "data:${data}," "data:TXlQYXNzd29yZDEy," >.env
		assert_contains "$(cat .env)" "data:TXlQYXNzd29yZDEy," "test fixture (${format})"
		run git add .env
		assert_ne "${RC}" "0" "git add exit status (${format})"
		assert_contains "${OUT}" "forged" "filter message names the likely causes (${format})"
		assert_not_contains "${OUT}" "MyPassword" "filter message (${format})"
		assert_eq "$(blob_id .env)" "${id}" "index blob (${format})"
		cd ..
	done
}

# Without the keys, a working copy that holds ciphertext git no longer
# holds (a git reset in a clone where install.sh could not decrypt) stops
# git status. "rm f && git checkout -- f" needs the keys (the checkout
# decrypts); the refusal must also print a way back that works without
# them, ready to paste, from any directory, for a path with a space and
# a quote in it.
test_clean_refusal_prints_a_way_back_without_the_keys() {
	local file="a b'c.secret" line rc
	new_repo origin
	printf 'A=1\n' >"${file}"
	git add "${file}"
	git commit -q -m "A=1"
	printf 'A=2\n' >"${file}"
	git add "${file}"
	git commit -q -m "A=2"
	cd ..
	fresh_clone origin clone
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
	export SOPS_AGE_KEY_FILE="${NO_KEY}"
	git reset -q HEAD~1 2>/dev/null || true

	touch "${file}"
	run git status --porcelain
	assert_ne "${RC}" "0" "git status without the keys"
	assert_contains "${OUT}" "does not decrypt with your keys" "filter message"
	assert_contains "${OUT}" "needs your keys" "the checkout line says it needs the keys"
	line="$(printf '%s\n' "${OUT}" | grep 'git cat-file blob' | head -1)"
	assert_ne "${line}" "" "a git cat-file line"
	line="git cat-file blob${line#*git cat-file blob}"

	mkdir -p sub
	(cd sub && eval "${line}")
	rc=0
	git status --porcelain >/dev/null 2>&1 || rc=$?
	assert_eq "${rc}" "0" "git status after the printed command"
	assert_eq "$(git hash-object --no-filters -- "${file}")" "$(blob_id "${file}")" "the working copy is the blob git holds"
}

# The case the shortcut is for: install.sh ran without the key, and the
# working copy still holds the ciphertext git holds. It is stored as it
# is, without the key and without a call to sops (with a KMS key, every
# call is a request to the key service). The dotenv files are refreshed
# by git while install.sh works on the others: that must work too.
test_clean_stores_the_held_ciphertext_without_a_key() {
	local format id out
	stub fakebin sops <<'STUB'
printf '%s\n' "$*" >>"${SOPS_CALLS}"
exec "${REAL}" "$@"
STUB
	for format in json dotenv; do
		new_repo "origin-${format}" "${format}"
		printf 'A=1\n' >.env
		printf 'B=2\n' >b.secret
		git add .env b.secret
		git commit -q -m "two secrets"
		cd ..
		fresh_clone "origin-${format}" "clone-${format}"
		run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
		assert_eq "${RC}" "3" "install.sh without the key (${format})"
		id="$(blob_id .env)"

		: >../calls
		touch .env b.secret
		out="$(env SOPS_AGE_KEY_FILE="${NO_KEY}" SOPS_CALLS="${PWD}/../calls" PATH="${PWD}/../fakebin:${PATH}" \
			git status --porcelain 2>/dev/null)"
		assert_eq "${out}" "" "git status without the key (${format})"
		echo note >note.txt
		touch .env b.secret
		run env SOPS_AGE_KEY_FILE="${NO_KEY}" SOPS_CALLS="${PWD}/../calls" PATH="${PWD}/../fakebin:${PATH}" \
			git add -A
		assert_eq "${RC}" "0" "git add -A without the key (${format})"
		assert_contains "${OUT}" "holds the ciphertext git holds" "the filter saw the ciphertext (${format})"
		assert_eq "$(blob_id .env)" "${id}" "blob of .env (${format})"
		assert_contains "$(cat .env)" "ENC[AES256_GCM,data:" "working copy (${format})"
		assert_not_contains "$(cat ../calls)" "decrypt" "calls to sops (${format})"
		cd ..
	done
}

# has_cr <file> : true when the file holds a carriage return
has_cr() {
	[[ "$(tr -d '\r' <"$1" | wc -c)" -ne "$(wc -c <"$1")" ]]
}

# The same with core.autocrlf=true and no -text on the path: the working
# copy is the stored blob with CRLF line endings, not byte for byte the
# blob git holds. It must still be taken for it, without the key and
# without a call to sops (before, json failed without the key and dotenv
# even with it: sops cannot parse a dotenv document with CRLF).
test_clean_stores_the_held_ciphertext_with_crlf_line_endings() {
	local format id out rc
	stub fakebin sops <<'STUB'
printf '%s\n' "$*" >>"${SOPS_CALLS}"
exec "${REAL}" "$@"
STUB
	for format in json dotenv; do
		new_repo "origin-${format}" "${format}"
		printf 'A=1\n' >.env
		git add .env
		git commit -q -m "add .env"
		cd ..
		fresh_clone "origin-${format}" "clone-${format}"
		git config core.autocrlf true
		rm .env
		git checkout -- .env
		has_cr .env || fail "test fixture: the working copy has no CR (${format})"
		run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
		id="$(blob_id .env)"

		: >../calls
		touch .env
		rc=0
		out="$(env SOPS_AGE_KEY_FILE="${NO_KEY}" SOPS_CALLS="${PWD}/../calls" PATH="${PWD}/../fakebin:${PATH}" \
			git status --porcelain 2>/dev/null)" || rc=$?
		assert_eq "${rc}" "0" "git status without the key (${format})"
		assert_eq "${out}" "" "git status --porcelain without the key (${format})"
		touch .env
		run env SOPS_AGE_KEY_FILE="${NO_KEY}" SOPS_CALLS="${PWD}/../calls" PATH="${PWD}/../fakebin:${PATH}" \
			git add -A
		assert_eq "${RC}" "0" "git add -A without the key (${format})"
		assert_eq "$(blob_id .env)" "${id}" "blob of .env (${format})"
		assert_not_contains "$(cat ../calls)" "decrypt" "calls to sops (${format})"

		# With the key too.
		touch .env
		rc=0
		out="$(git status --porcelain 2>/dev/null)" || rc=$?
		assert_eq "${rc}" "0" "git status with the key (${format})"
		assert_eq "${out}" "" "git status --porcelain with the key (${format})"

		# A copy of a foreign document with CRLF line endings is still refused.
		printf 'A=from-another-project\n' | encrypt_for "${format}" "${AGE_PUB_B}" |
			awk '{ printf "%s\r\n", $0 }' >.env
		run git add .env
		assert_ne "${RC}" "0" "git add of a foreign document with CRLF (${format})"
		assert_contains "${OUT}" "does not decrypt with your keys" "filter message (${format})"
		assert_eq "$(blob_id .env)" "${id}" "index blob after the foreign copy (${format})"
		cd ..
	done
}

# A SOPS document that is not the version git holds, but that decrypts
# with the user's keys, is content like any other: its plaintext is
# compared with the stored version and, when it differs, encrypted for
# the recipients of .sops.yaml (audit A-13). Here: copies encrypted for
# keys A and B while .sops.yaml names A only, and an old version taken
# from history as ciphertext.
test_clean_reencrypts_a_sops_document_it_can_decrypt() {
	local format id
	for format in json dotenv; do
		new_repo "${format}" "${format}"
		printf 'A=1\n' >.env
		git add .env
		git commit -q -m "add .env"
		id="$(blob_id .env)"

		# The same plaintext for other keys: the stored blob is kept, and the
		# note says how recipients do change.
		printf 'A=1\n' | encrypt_for "${format}" "${AGE_PUB_A},${AGE_PUB_B}" >.env
		run git add .env
		assert_eq "${RC}" "0" "git add of the same content for other keys (${format})"
		assert_eq "$(blob_id .env)" "${id}" "the stored blob is reused (${format})"
		assert_contains "${OUT}" "rekey.sh" "the note names rekey.sh (${format})"
		assert_eq "$(git status --porcelain 2>/dev/null)" "" "git status (${format})"

		# Other content: encrypted for the recipients of .sops.yaml only.
		printf 'A=2\n' | encrypt_for "${format}" "${AGE_PUB_A},${AGE_PUB_B}" >.env
		run git add .env
		assert_eq "${RC}" "0" "git add of new content for other keys (${format})"
		assert_eq "$(plain_of_stored .env "${format}")" "A=2" "plaintext of the staged blob (${format})"
		assert_contains "$(stored .env)" "${AGE_PUB_A}" "the recipient .sops.yaml names (${format})"
		assert_not_contains "$(stored .env)" "${AGE_PUB_B}" "a recipient .sops.yaml does not name (${format})"
		git commit -q -m "A=2"

		# An old version, taken from history as ciphertext.
		git cat-file blob HEAD~1:.env >.env
		run git add .env
		assert_eq "${RC}" "0" "git add of an old version (${format})"
		assert_eq "$(plain_of_stored .env "${format}")" "A=1" "plaintext of the staged blob (${format})"
		run "${TOOL}/encryption-guard.sh"
		assert_eq "${RC}" "0" "guard (${format})"
		cd ..
	done
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

# ── Content with NUL bytes (audit F9) ────
# File content passes through shell variables, and a shell variable cannot
# hold a NUL byte. Before, `git add` exited 0 and stored the file without
# them: a keystore or a UTF-16 file was committed damaged.
test_clean_refuses_content_with_nul_bytes() {
	new_repo repo
	printf 'a\0b\n' >bin.secret
	run git add bin.secret
	assert_ne "${RC}" "0" "git add of a file with a NUL byte"
	assert_contains "${OUT}" "bin.secret holds NUL bytes (1)" "clean filter message"
	assert_eq "$(git ls-files -s -- bin.secret)" "" "nothing is staged"

	# UTF-16 text is full of them.
	printf '\377\376A\0=\0001\0\n\0' >utf16.secret
	run git add utf16.secret
	assert_ne "${RC}" "0" "git add of a UTF-16 file"
	assert_contains "${OUT}" "utf16.secret holds NUL bytes (4)" "clean filter message"
	assert_eq "$(git ls-files -s -- utf16.secret)" "" "nothing is staged"
	rm bin.secret utf16.secret

	# A tracked text secret that turns binary keeps its good blob in git.
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	local before
	before="$(blob_id .env)"
	printf 'A=1\0\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add after a NUL byte was added"
	assert_eq "$(blob_id .env)" "${before}" "the index keeps the earlier blob"
	run git commit -q -am "would store a damaged file"
	assert_ne "${RC}" "0" "git commit -a with a NUL byte in the secret"
	assert_eq "$(git rev-parse HEAD:.env)" "${before}" "HEAD keeps the earlier blob"

	# Without the NUL byte the file is taken again.
	printf 'A=2\n' >.env
	run git add .env
	assert_eq "${RC}" "0" "git add of the text file"
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
}

test_clean_dotenv_refuses_content_with_nul_bytes() {
	new_repo repo dotenv
	printf 'A=1\0\nB=2\n' >.env
	run git add .env
	assert_ne "${RC}" "0" "git add of a dotenv file with a NUL byte"
	assert_contains "${OUT}" ".env holds NUL bytes (1)" "clean filter message"
	assert_eq "$(git ls-files -s -- .env)" "" "nothing is staged"
}

# A stored version with NUL bytes (written without this filter) is never
# taken for "unchanged" because the shell dropped them on the way.
test_clean_does_not_reuse_a_stored_blob_with_nul_bytes() {
	new_repo repo
	printf 'a\0b\n' | sops encrypt --input-type binary --output-type json \
		--filename-override bin.secret /dev/stdin >../bin.enc
	git update-index --add --cacheinfo "100644,$(git hash-object -w ../bin.enc),bin.secret"
	git commit -q -m "a binary secret stored without the filter"
	local before
	before="$(blob_id bin.secret)"

	# The same bytes without the NUL: a different file.
	printf 'ab\n' >bin.secret
	run git add bin.secret
	assert_eq "${RC}" "0" "git add exit status"
	assert_ne "$(blob_id bin.secret)" "${before}" "the staged blob is a new one"
	assert_eq "$(plain_of_stored bin.secret)" "ab" "plaintext of the staged blob"
}

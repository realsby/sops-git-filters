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

# A change to .sops.yaml decides who can read every secret edited after
# it, and the re-encryption that puts it into effect used to say nothing
# but "re-encrypting". The filter names the keys it adds and removes
# (audit A-15), and says nothing about keys when they stay the same.
test_clean_names_the_keys_a_reencryption_adds_or_removes() {
	local format
	for format in json dotenv; do
		new_repo "${format}" "${format}"
		printf 'A=1\n' >.env
		git add .env
		git commit -q -m "add .env"

		printf 'A=2\n' >.env
		run git add .env
		assert_eq "${RC}" "0" "git add with the same keys (${format})"
		assert_contains "${OUT}" "re-encrypting .env" "the file was re-encrypted (${format})"
		assert_not_contains "${OUT}" "keys of .env change" "the same keys (${format})"

		write_sops_yaml "${AGE_PUB_B}"
		git add .sops.yaml .env
		git commit -q -m "add recipient B"
		printf 'A=3\n' >.env
		run git add .env
		assert_eq "${RC}" "0" "git add after recipient B was added (${format})"
		assert_contains "${OUT}" "added: age ${AGE_PUB_B}" "the added key is named (${format})"
		assert_not_contains "${OUT}" "removed:" "nothing removed (${format})"
		git commit -q -m "A=3"

		# shellcheck disable=SC2119  # key A only
		write_sops_yaml
		printf 'A=4\n' >.env
		run git add .env
		assert_eq "${RC}" "0" "git add after recipient B was removed (${format})"
		assert_contains "${OUT}" "removed: age ${AGE_PUB_B}" "the removed key is named (${format})"
		assert_not_contains "${OUT}" "added:" "nothing added (${format})"
		git commit -q -am "A=4, B removed"

		# Key groups: key B in a second group.
		printf 'creation_rules:\n  - path_regex: .*\n    shamir_threshold: 2\n    key_groups:\n      - age:\n          - %s\n      - age:\n          - %s\n' \
			"${AGE_PUB_A}" "${AGE_PUB_B}" >.sops.yaml
		printf 'A=5\n' >.env
		run git add .env
		assert_eq "${RC}" "0" "git add after a key group was added (${format})"
		assert_contains "${OUT}" "added: age ${AGE_PUB_B} (key group 2)" "the key and its group are named (${format})"
		assert_not_contains "${OUT}" "removed:" "nothing removed by the change to key groups (${format})"
		cd ..
	done
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

# Git takes a path in a command as a pattern: "[ab].secret" matches
# a.secret too, and `git checkout -- '<top>/[ab].secret'` threw away the
# edits in a.secret. The commands the filter prints for one file must
# reach that file only.
test_clean_printed_commands_take_the_path_literally() {
	local file='[ab].secret' line
	new_repo repo
	printf 'A=1\n' >a.secret
	printf 'B=1\n' >"${file}"
	git add -- a.secret ":(literal)${file}"
	git commit -q -m "two secrets"
	printf 'A=edited\n' >a.secret
	mkdir -p sub

	# A SOPS document that decrypts with your keys is stored like an edit;
	# the note says how to get its plaintext into the working tree.
	printf 'B=2\n' | encrypt_for json "${AGE_PUB_A}" >"${file}"
	run git add -- ":(literal)${file}"
	assert_eq "${RC}" "0" "git add of a SOPS document"
	line="$(printf '%s\n' "${OUT}" | grep 'For the plaintext there: ' | head -1)"
	line="${line#*For the plaintext there: }"
	assert_contains "${line}" "git checkout -- " "test fixture: the printed line"
	(cd sub && eval "${line}")
	assert_eq "$(cat "${file}")" "B=2" "the file, decrypted"
	assert_eq "$(cat a.secret)" "A=edited" "a.secret keeps its edits"

	# Without the key: the stored version cannot be decrypted, and the
	# error prints how to re-encrypt regardless.
	printf 'B=3\n' >"${file}"
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" git add -- ":(literal)${file}"
	assert_ne "${RC}" "0" "git add without the key"
	line="$(printf '%s\n' "${OUT}" | grep 'To re-encrypt regardless: ' | head -1)"
	line="${line#*To re-encrypt regardless: }"
	assert_contains "${line}" "git add " "test fixture: the printed line"
	(export SOPS_AGE_KEY_FILE="${NO_KEY}" && cd sub && eval "${line}")
	assert_eq "$(git diff --cached --name-only)" "${file}" "what the printed line staged"
	assert_eq "$(git cat-file blob ":${file}" | sops decrypt --input-type json --output-type binary /dev/stdin)" "B=3" "the staged blob"
}

# A newline at the end of a name is part of it. The quoted path in the
# commands the filter prints lost it once: for "b.secret<newline>",
# `rm '<top>/b.secret' && git checkout -- '<top>/b.secret'` threw away
# the edits in b.secret.
test_clean_printed_commands_keep_a_trailing_newline() {
	local file=$'b.secret\n' line
	new_repo repo
	# *.secret does not match a name that ends in a newline.
	printf 'b.secret? filter=sops diff=sops\n' >>.gitattributes
	git add .gitattributes
	printf 'B=1\n' >b.secret
	printf 'N=1\n' >"${file}"
	git add -- b.secret "${file}"
	git commit -q -m "two secrets"
	assert_eq "$(git ls-files -z -- "${file}" | tr '\0' '|')" "${file}|" "test fixture: the name is tracked with its newline"
	printf 'B=edited\n' >b.secret
	mkdir -p sub

	printf 'N=2\n' | encrypt_for json "${AGE_PUB_A}" >"${file}"
	run git add -- "${file}"
	assert_eq "${RC}" "0" "git add of a SOPS document"
	# The printed command holds the newline of each of the two paths: it
	# spans three lines. Their shape is checked before the eval, which
	# must not run a line of some other message.
	line="${OUT#*For the plaintext there: }"
	line="$(printf '%s\n' "${line}" | head -3)"
	[[ "${line}" == "rm '"*$'\n'"' && git checkout -- '"*$'\n'"'" ]] ||
		fail "the printed command does not keep the newline of the name: [${line}]"
	(cd sub && eval "${line}")
	assert_eq "$(cat "${file}")" "N=2" "the file, decrypted"
	assert_eq "$(cat b.secret)" "B=edited" "b.secret keeps its edits"
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

# A rule you can encrypt for but not decrypt (audit A-04): the prod/ rule
# lists key B only, the user holds key A. git add encrypts (public keys
# are enough); git commit checks the file again and cannot decrypt what
# was staged. The keys are fine: the message must name the rule, and the
# way it gives to commit must work.
test_clean_names_a_rule_that_does_not_list_your_key() {
	new_repo repo
	printf 'creation_rules:\n  - path_regex: ^prod/\n    age: %s\n  - path_regex: .*\n    age: %s\n' \
		"${AGE_PUB_B}" "${AGE_PUB_A}" >.sops.yaml
	printf 'prod/*.env filter=sops diff=sops\n' >>.gitattributes
	git add .sops.yaml .gitattributes
	git commit -q -m "a rule for prod/"
	mkdir prod
	printf 'TOKEN=1\n' >prod/deploy.env
	run git add prod/deploy.env
	assert_eq "${RC}" "0" "git add for a rule without your key"

	# git commit checks the file again when its timestamp leaves it in
	# doubt; touch makes that certain.
	touch prod/deploy.env
	run git commit -q -m "add the deploy key"
	assert_ne "${RC}" "0" "git commit"
	assert_contains "${OUT}" "cannot decrypt the version of prod/deploy.env that git holds" "filter message"
	assert_contains "${OUT}" "rule for it in .sops.yaml may not list your key" "the message names the rule"
	assert_contains "${OUT}" "SOPS_FILTER_FORCE_REENCRYPT=1 git commit" "the message gives a way to commit"

	run env SOPS_FILTER_FORCE_REENCRYPT=1 git commit -q -m "add the deploy key"
	assert_eq "${RC}" "0" "git commit as the message says"
	assert_eq "$(git cat-file blob HEAD:prod/deploy.env |
		SOPS_AGE_KEY_FILE="${AGE_KEY_B}" sops decrypt --input-type json --output-type binary /dev/stdin)" \
		"TOKEN=1" "key B decrypts the committed blob"

	# The README's way to stop the checks that fail while the plaintext is
	# in the working tree: the ciphertext git holds in its place.
	git cat-file blob :0:prod/deploy.env >prod/deploy.env
	run git add prod/deploy.env
	assert_eq "${RC}" "0" "git add of the ciphertext git holds"
	touch prod/deploy.env
	run git status --porcelain
	assert_eq "${RC}" "0" "git status with the ciphertext in the working tree"
	assert_eq "$(git status --porcelain 2>/dev/null)" "" "git status"
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

# SOPS_FILTER_FORCE_REENCRYPT reaches every run of the filter in the
# command, not only the file meant (audit S9). What the README says:
# on git add <file> and on a plain git commit only what is meant is
# stored; on git commit -a every managed file git checks again is.
test_clean_force_reencrypt_reaches_every_file_git_checks() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'B=1\n' >b.secret
	git add .env b.secret
	git commit -q -m "two secrets"
	local b_id
	b_id="$(blob_id b.secret)"

	printf 'A=2\n' >.env
	touch b.secret
	run env SOPS_FILTER_FORCE_REENCRYPT=1 git add .env
	assert_eq "${RC}" "0" "forced git add of one file"
	assert_eq "$(blob_id b.secret)" "${b_id}" "the other file after the forced git add"
	touch b.secret
	run env SOPS_FILTER_FORCE_REENCRYPT=1 git commit -q -m "A=2"
	assert_eq "${RC}" "0" "forced plain git commit"
	assert_eq "$(git rev-parse HEAD:b.secret)" "${b_id}" "the other file after a forced plain git commit"
	assert_eq "$(git status --porcelain 2>/dev/null)" "" "git status after the commit"

	printf 'A=3\n' >.env
	touch b.secret
	run env SOPS_FILTER_FORCE_REENCRYPT=1 git commit -q -am "A=3"
	assert_eq "${RC}" "0" "forced git commit -a"
	assert_ne "$(git rev-parse HEAD:b.secret)" "${b_id}" "git commit -a re-encrypted the other file"
	assert_eq "$(plain_of_stored b.secret)" "B=1" "its plaintext is the same"
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

# ":2:prod.secret" is stage 2 of prod.secret to git, not the index entry
# of a file named "2:prod.secret". The filter must find the version git
# holds of the file it was given: else a staged new file looks new at
# every git status, and a staged edit is compared with HEAD's version and
# re-encrypted, so the file never stops showing as modified.
test_clean_path_that_looks_like_an_index_stage() {
	local file id
	new_repo repo
	printf '1:x filter=sops diff=sops\n' >>.gitattributes
	git add .gitattributes
	git commit -q -m "1:x is a secret"
	for file in '2:prod.secret' '1:x'; do
		printf 'A=1\n' >"${file}"
		git add -- "${file}"
		id="$(blob_id "${file}")"
		touch "${file}"
		git add -- "${file}"
		assert_eq "$(blob_id "${file}")" "${id}" "blob of the new file after touch + add (${file})"
		assert_eq "$(git status --porcelain -- "${file}" 2>/dev/null)" "A  ${file}" "git status of the new file (${file})"
		git commit -q -m "add ${file}"

		printf 'A=2\n' >"${file}"
		git add -- "${file}"
		id="$(blob_id "${file}")"
		assert_eq "$(plain_of_stored "${file}")" "A=2" "plaintext of the staged blob (${file})"
		touch "${file}"
		git add -- "${file}"
		assert_eq "$(blob_id "${file}")" "${id}" "blob of the staged edit after touch + add (${file})"
		assert_eq "$(git status --porcelain -- "${file}" 2>/dev/null)" "M  ${file}" "git status of the staged edit (${file})"
		git commit -q -m "edit ${file}"
	done
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

# ── What a run remembers for the next one (issue #21) ────
# Git runs the clean filter each time it looks at a secret with
# uncommitted changes. Each run decrypted the stored version and
# encrypted the edit again: two requests to a key service, and a new
# ciphertext every time. A run now remembers its answer for some minutes.

# counting_sops : a sops in fakebin (call it before new_repo) that writes
# its subcommand to the file CALL_LOG names, then runs the real one. Not
# a SOPS_* variable: those are part of what the cache remembers.
counting_sops() {
	stub fakebin sops <<'STUB'
printf '%s\n' "$1" >>"${CALL_LOG}"
exec "${REAL}" "$@"
STUB
}

# calls <command...> : run it with the counting sops; never fails. Sets
# OUT (stdout), ERR (stderr), RC, and CALLS: "<decrypts> <encrypts>".
calls() {
	: >../calls
	RC=0
	OUT="$(env CALL_LOG="${PWD}/../calls" PATH="${PWD}/../fakebin:${PATH}" "$@" 2>../stderr)" || RC=$?
	ERR="$(cat ../stderr)"
	CALLS="$(awk '$1 == "decrypt" { d++ } $1 == "encrypt" { e++ } END { print d + 0, e + 0 }' ../calls)"
}

# cache_dir : where the clean filter keeps what it remembers
cache_dir() {
	printf '%s/sops-git-filters/cache\n' "$(git rev-parse --git-common-dir)"
}

# edit_same_size <content> <touch time> : write .env, and give it a time
# that is neither the one git recorded nor recent: git then reads the
# file at every git status, and never takes it for racily clean.
edit_same_size() {
	printf '%s' "$1" >.env
	touch -t "$2" .env
}

# The calls per command for one secret with an edit that keeps its size,
# with the cache and without (SOPS_FILTER_CACHE=0: the counts of before).
# The edit is encrypted once, and every later command gets that blob:
# git status, git diff and git add see the same ciphertext, and git add
# stores it.
test_clean_cache_counts_sops_calls() {
	local format mode id
	counting_sops
	for format in json dotenv; do
		for mode in 1 0; do
			new_repo "${format}-${mode}" "${format}"
			export SOPS_FILTER_CACHE="${mode}"
			printf 'A=1\nB=2\n' >.env
			git add .env
			git commit -q -m "add .env"
			edit_same_size $'A=1\nB=3\n' 200001010000

			calls git status --porcelain
			assert_eq "${OUT}" " M .env" "git status (${format}, cache ${mode})"
			assert_eq "${CALLS}" "1 1" "first git status (${format}, cache ${mode})"
			calls git status --porcelain
			if [[ "${mode}" == "1" ]]; then
				assert_eq "${CALLS}" "0 0" "second git status (${format}, cache ${mode})"
				assert_contains "${ERR}" "reusing its encryption of" "message of a remembered run (${format})"
				id="$(git hash-object .env 2>/dev/null)"
				assert_eq "$(git hash-object .env 2>/dev/null)" "${id}" "the same blob each time (${format})"
			else
				assert_eq "${CALLS}" "1 1" "second git status (${format}, cache ${mode})"
			fi
			# git diff: the clean filter twice, and once the smudge filter
			# for the stored version (the text the diff shows).
			calls git diff
			assert_contains "${OUT}" "+B=3" "git diff (${format}, cache ${mode})"
			[[ "${mode}" == "1" ]] && assert_eq "${CALLS}" "1 0" "git diff (${format}, cache ${mode})"
			[[ "${mode}" == "0" ]] && assert_eq "${CALLS}" "3 2" "git diff (${format}, cache ${mode})"
			calls git diff --stat
			[[ "${mode}" == "1" ]] && assert_eq "${CALLS}" "0 0" "git diff --stat (${format}, cache ${mode})"
			[[ "${mode}" == "0" ]] && assert_eq "${CALLS}" "2 2" "git diff --stat (${format}, cache ${mode})"
			calls git add .env
			[[ "${mode}" == "1" ]] && assert_eq "${CALLS}" "0 0" "git add (${format}, cache ${mode})"
			[[ "${mode}" == "0" ]] && assert_eq "${CALLS}" "1 1" "git add (${format}, cache ${mode})"
			[[ "${mode}" == "0" ]] || assert_eq "$(blob_id .env)" "${id}" "git add stores the blob git status saw (${format})"
			assert_eq "$(plain_of_stored .env "${format}")" $'A=1\nB=3' "plaintext of the staged blob (${format}, cache ${mode})"
			calls git commit -q -m "B=3"
			assert_eq "${CALLS}" "0 0" "git commit (${format}, cache ${mode})"

			edit_same_size $'A=1\nB=4\n' 200001020000
			calls git status --porcelain
			assert_eq "${CALLS}" "1 1" "git status after the next edit (${format}, cache ${mode})"
			calls git commit -q -a -m "B=4"
			[[ "${mode}" == "1" ]] && assert_eq "${CALLS}" "0 0" "git commit -a (${format}, cache ${mode})"
			[[ "${mode}" == "0" ]] && assert_eq "${CALLS}" "1 1" "git commit -a (${format}, cache ${mode})"
			assert_eq "$(git cat-file blob HEAD:.env | plain_of_stored_blob "${format}")" $'A=1\nB=4' "committed plaintext (${format}, cache ${mode})"
			calls git status --porcelain
			assert_eq "${OUT}" "" "git status after the commit (${format}, cache ${mode})"
			if [[ "${mode}" == "0" ]]; then
				[[ ! -e "$(cache_dir)" ]] || fail "SOPS_FILTER_CACHE=0 made $(cache_dir) (${format})"
			fi
			unset SOPS_FILTER_CACHE
			cd ..
		done
	done
}

# plain_of_stored_blob [format]   (blob on stdin) : decrypt it
plain_of_stored_blob() {
	if [[ "${1:-json}" == "dotenv" ]]; then
		sops decrypt --input-type dotenv --output-type dotenv /dev/stdin
	else
		sops decrypt --input-type json --output-type binary /dev/stdin
	fi
}

# What is on disk: MACs and object ids, in a directory of mode 0700 with
# files of mode 0600. Not the plaintext, not a plain hash of it.
test_clean_cache_holds_no_plaintext() {
	local dir file secret='hunter2-S3cr3t' sum
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	printf 'PW=%s\n' "${secret}" >.env
	touch -t 200001010000 .env
	git status --porcelain >/dev/null 2>&1
	git add .env
	dir="$(cache_dir)"
	[[ -f "${dir}/key" ]] || fail "test fixture: no key in ${dir}"
	assert_eq "$(mode_of "${dir}")" "700" "mode of the cache directory"
	for file in "${dir}"/*; do
		assert_eq "$(mode_of "${file}")" "600" "mode of ${file##*/}"
	done
	assert_eq "$(grep -rl "${secret}" "${dir}" || true)" "" "files that hold the plaintext"
	# Not a plain SHA-256 of it either, in any form a tool prints.
	for sum in "$(printf 'PW=%s\n' "${secret}" | sha256sum 2>/dev/null || true)" \
		"$(printf 'PW=%s\n' "${secret}" | shasum -a 256 2>/dev/null || true)"; do
		sum="${sum%% *}"
		[[ -z "${sum}" ]] || assert_eq "$(grep -rl "${sum:0:32}" "${dir}" || true)" "" "files that hold its SHA-256"
	done
	# The entries: "sgf-cache 1 <check> <time> <object id>", nothing else.
	for file in "${dir}"/e-*; do
		[[ "$(cat "${file}")" =~ ^sgf-cache\ 1\ [0-9a-f]{32}\ [0-9]+\ [0-9a-f]{40}$ ]] ||
			fail "an entry that is not as expected: $(cat "${file}")"
	done
}

# SOPS_FILTER_FORCE_REENCRYPT=1 asks for a new encryption: the remembered
# one is not given, and the forced one is not remembered.
test_clean_cache_is_bypassed_by_force_reencrypt() {
	local id entries
	counting_sops
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	edit_same_size $'A=2\n' 200001010000
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status"
	id="$(git hash-object .env 2>/dev/null)"
	entries="$(ls "$(cache_dir)")"

	calls env SOPS_FILTER_FORCE_REENCRYPT=1 git add .env
	assert_eq "${RC}" "0" "forced git add"
	assert_eq "${CALLS}" "0 1" "forced git add"
	assert_ne "$(blob_id .env)" "${id}" "the forced git add encrypted anew"
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
	assert_eq "$(ls "$(cache_dir)")" "${entries}" "entries after the forced git add"
}

# A change to .sops.yaml is a new question: the next run encrypts for the
# recipients it names, and says which keys that adds (audit A-15); the
# run after it gives that encryption again, with the same line.
test_clean_cache_follows_a_change_of_sops_yaml() {
	counting_sops
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	edit_same_size $'A=2\n' 200001010000
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status"
	assert_not_contains "${ERR}" "added:" "git status before the change"

	write_sops_yaml "${AGE_PUB_B}"
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status after recipient B was added"
	assert_contains "${ERR}" "added: age ${AGE_PUB_B}" "the added key is named"
	calls git add .env
	assert_eq "${CALLS}" "0 0" "git add after that git status"
	assert_contains "${ERR}" "added: age ${AGE_PUB_B}" "the added key is named again"
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_eq "$(stored .env | SOPS_AGE_KEY_FILE="${AGE_KEY_B}" plain_of_stored_blob)" "A=2" "key B decrypts the staged blob"
}

# rewriting_sops : counting_sops, and on encrypt it first copies the file
# NEW_RULES names (when set) over .sops.yaml: an editor or a checkout
# that changes the rules while sops waits for a key service.
rewriting_sops() {
	stub fakebin sops <<'STUB'
printf '%s\n' "$1" >>"${CALL_LOG}"
if [[ "$1" == "encrypt" && -n "${NEW_RULES:-}" ]]; then
	cp "${NEW_RULES}" .sops.yaml
fi
exec "${REAL}" "$@"
STUB
}

# .sops.yaml changed while sops encrypted: sops read the new rules, the
# question holds the old ones. That encryption is not remembered, so a
# run with the old rules (in another linked worktree, say) does not get
# a blob for the recipients of the new ones.
test_clean_cache_keeps_no_encryption_for_rules_changed_while_sops_ran() {
	local entries
	rewriting_sops
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	edit_same_size $'A=2\n' 200001010000
	cp .sops.yaml ../old-rules.yaml
	write_sops_yaml "${AGE_PUB_B}"
	cp .sops.yaml ../new-rules.yaml
	cp ../old-rules.yaml .sops.yaml
	entries="$(ls "$(cache_dir)")"

	calls env NEW_RULES="${PWD}/../new-rules.yaml" git status --porcelain -- .env
	assert_eq "${OUT}" " M .env" "git status"
	assert_eq "${CALLS}" "1 1" "git status"
	assert_eq "$(cat .sops.yaml)" "$(cat ../new-rules.yaml)" "test fixture: the rules changed during the encryption"
	assert_contains "${ERR}" "added: age ${AGE_PUB_B}" "test fixture: sops encrypted for the new rules"
	assert_eq "$(ls "$(cache_dir)")" "${entries}" "entries after that git status"

	# The old rules again: a new encryption, for them, remembered as usual.
	cp ../old-rules.yaml .sops.yaml
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with the old rules"
	assert_not_contains "${ERR}" "reusing its encryption" "git status with the old rules"
	calls git add .env
	assert_eq "${CALLS}" "0 0" "git add after that git status"
	assert_not_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_contains "$(stored .env)" "${AGE_PUB_A}" "recipient A in the staged blob"
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
}

# count_files <path...> : how many of the paths exist (for a glob that
# may match nothing)
count_files() {
	local n=0 path
	for path in "$@"; do
		[[ ! -e "${path}" && ! -L "${path}" ]] || n=$((n + 1))
	done
	echo "${n}"
}

# rewrite_entries <awk program> : apply it to the line of every entry
rewrite_entries() {
	local file
	for file in "$(cache_dir)"/e-*; do
		awk "$1" "${file}" >"${file}.new" && mv -f "${file}.new" "${file}"
	done
}

# What the cache holds is not trusted: an entry that is too old, does
# not read as one, or names a blob that is gone or is not a complete SOPS
# document is not used. The filter then works as without it.
test_clean_cache_ignores_entries_it_cannot_trust() {
	local plain_id now
	counting_sops
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	edit_same_size $'A=2\n' 200001010000
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "first git status"
	calls git status --porcelain
	assert_eq "${CALLS}" "0 0" "test fixture: the answer is remembered"

	# Ten minutes and more.
	now="$(date +%s)"
	rewrite_entries "{ \$4 = ${now} - 600; print }"
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with an entry of ten minutes ago"
	calls git status --porcelain
	assert_eq "${CALLS}" "0 0" "git status after that: remembered again"

	# Garbage, and a line cut short.
	# shellcheck disable=SC2016  # the fields belong to awk
	rewrite_entries '{ print "garbage" }'
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with entries that do not read"
	# shellcheck disable=SC2016  # the fields belong to awk
	rewrite_entries '{ print $1, $2, $3, $4 }'
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with entries cut short"

	# A blob that is not a SOPS document (the plaintext itself, say), and
	# one that is not in the object store.
	plain_id="$(printf 'A=2\n' | git hash-object -w --stdin)"
	rewrite_entries "{ \$5 = \"${plain_id}\"; print }"
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with an entry that names a plaintext blob"
	assert_eq "${OUT}" " M .env" "git status output"
	# shellcheck disable=SC2016  # the fields belong to awk
	rewrite_entries '{ $5 = "0123456789012345678901234567890123456789"; print }'
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with an entry that names a missing blob"

	# The entry of another question under this name (its check differs).
	# shellcheck disable=SC2016  # the fields belong to awk
	rewrite_entries '{ $3 = "00000000000000000000000000000000"; print }'
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with an entry of another question"

	git add .env
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
}

# The directory and the key must be the user's own and closed to others,
# and not reached through a symlink. Otherwise the cache is not used (and
# nothing is written there); the filter still works.
test_clean_cache_is_not_used_when_its_directory_is_open_or_a_symlink() {
	local dir what
	counting_sops
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	edit_same_size $'A=2\n' 200001010000
	calls git status --porcelain
	dir="$(cache_dir)"
	for what in dir key; do
		if [[ "${what}" == "dir" ]]; then chmod 750 "${dir}"; else chmod 640 "${dir}/key"; fi
		calls git status --porcelain
		assert_eq "${CALLS}" "1 1" "git status with the ${what} open to the group"
		calls git status --porcelain
		assert_eq "${CALLS}" "1 1" "git status again with the ${what} open to the group"
		assert_eq "${OUT}" " M .env" "git status output"
		chmod 700 "${dir}"
		chmod 600 "${dir}/key"
	done

	mv "${dir}" "${dir}.real"
	ln -s "$(basename "${dir}").real" "${dir}"
	rm -f "${dir}.real"/e-*
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status with the directory a symlink"
	calls git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status again with the directory a symlink"
	assert_eq "$(count_files "${dir}.real"/e-*)" "0" "entries written through the symlink"
	git add .env
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
}

# Two git commands at once: neither fails, both see the change, and what
# they leave behind is a cache the next run can use.
test_clean_cache_two_commands_at_once() {
	local round status1 status2 pid1 pid2
	counting_sops
	new_repo repo
	printf 'A=00\n' >.env
	printf 'B=00\n' >b.secret
	git add .env b.secret
	git commit -q -m "two secrets"
	# The edits keep the size: git has to run the filter to see them.
	for round in 1 2 3; do
		edit_same_size "A=${round}x"$'\n' "20000101000${round}"
		printf 'B=%sx\n' "${round}" >b.secret
		touch -t "20000101000${round}" b.secret
		status1=0
		status2=0
		git status --porcelain >../out1 2>/dev/null &
		pid1=$!
		git status --porcelain >../out2 2>/dev/null &
		pid2=$!
		wait "${pid1}" || status1=$?
		wait "${pid2}" || status2=$?
		assert_eq "${status1} ${status2}" "0 0" "exit status of the two git status (round ${round})"
		assert_eq "$(cat ../out1)" $' M .env\n M b.secret' "first git status (round ${round})"
		assert_eq "$(cat ../out2)" $' M .env\n M b.secret' "second git status (round ${round})"
		calls git status --porcelain
		assert_eq "${CALLS}" "0 0" "git status after the two (round ${round})"
	done
	assert_eq "$(count_files "$(cache_dir)"/tmp.*)" "0" "temporary files left behind"
	git add .env b.secret
	assert_eq "$(plain_of_stored .env)" "A=3x" "plaintext of the staged .env"
	assert_eq "$(plain_of_stored b.secret)" "B=3x" "plaintext of the staged b.secret"
}

# Without a tool for SHA-256 (sha256sum, openssl, shasum) there is no
# cache: the filter works as before, and remembers nothing.
test_clean_cache_without_a_sha256_tool() {
	local bin entries
	counting_sops
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	edit_same_size $'A=2\n' 200001010000
	bin="$(path_without ../nosha sha256sum openssl shasum)"
	! PATH="${bin}" command -v sha256sum openssl shasum >/dev/null || fail "test fixture: a SHA-256 tool is still on PATH"
	entries="$(ls "$(cache_dir)")"
	calls env PATH="${PWD}/../fakebin:${bin}" git status --porcelain
	assert_eq "${OUT}" " M .env" "git status"
	assert_eq "${CALLS}" "1 1" "git status"
	calls env PATH="${PWD}/../fakebin:${bin}" git status --porcelain
	assert_eq "${CALLS}" "1 1" "git status again"
	assert_eq "$(ls "$(cache_dir)")" "${entries}" "what the cache holds"
	PATH="${bin}" git add .env
	assert_eq "$(plain_of_stored .env)" "A=2" "plaintext of the staged blob"
}

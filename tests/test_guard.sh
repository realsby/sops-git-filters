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

# swap <old> <new>   (text on stdin) : the first <old> becomes <new>, as text
swap() {
	awk -v old="$1" -v new="$2" '!done && (i = index($0, old)) {
		$0 = substr($0, 1, i - 1) new substr($0, i + length(old))
		done = 1
	}
	{ print }'
}

# A hand-made ENC[...] value in a real document (audit A-16): a password
# in the place of the ciphertext, or after a real value. Every value the
# check reads is tried: "data" and "mac" (json); a value, a comment and
# sops_mac (dotenv). The documents sops wrote, unchanged, pass.
test_guard_blocks_hand_made_encrypted_values() {
	local fake_short='ENC[AES256_GCM,data:MyPassword123,iv:x,tag:y,type:str]'
	local doc token name

	unfiltered_repo
	doc="$(printf 'x\n' | sops encrypt --input-type binary --output-type json --filename-override any.secret /dev/stdin)"
	printf '%s\n' "${doc}" >real.secret
	for name in data mac; do
		token="$(printf '%s\n' "${doc}" | sed -n 's/^[[:space:]]*"'"${name}"'": "\(ENC\[[^"]*\]\)".*/\1/p')"
		assert_contains "${token}" "ENC[AES256_GCM,data:" "test fixture: the ${name} value"
		printf '%s\n' "${doc}" | swap "${token}" "${fake_short}" >"${name}-short.secret"
		printf '%s\n' "${doc}" | swap "${token}" "${token}hunter2]" >"${name}-after.secret"
	done
	git add ./*.secret
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status (json)"
	for name in data-short data-after mac-short mac-after; do
		assert_contains "${OUT}" "- ${name}.secret" "guard names the file (json)"
	done
	assert_not_contains "${OUT}" "- real.secret" "guard output (json)"
	assert_not_contains "${OUT}" "hunter2" "guard output (json)"
	assert_not_contains "${OUT}" "MyPassword" "guard output (json)"
	cd ..

	mkdir dotenv && cd dotenv || exit 1
	unfiltered_repo dotenv
	doc="$(printf '# note\nA=1\n' | sops encrypt --input-type dotenv --output-type dotenv --filename-override any.env /dev/stdin)"
	printf '%s\n' "${doc}" >real.secret
	for name in comment value sops_mac; do
		case "${name}" in
		comment) token="$(printf '%s\n' "${doc}" | sed -n 's/^#\(ENC\[.*\]\)$/\1/p')" ;;
		value) token="$(printf '%s\n' "${doc}" | sed -n 's/^A=\(ENC\[.*\]\)$/\1/p')" ;;
		sops_mac) token="$(printf '%s\n' "${doc}" | sed -n 's/^sops_mac=\(ENC\[.*\]\)$/\1/p')" ;;
		esac
		assert_contains "${token}" "ENC[AES256_GCM,data:" "test fixture: the ${name} value"
		printf '%s\n' "${doc}" | swap "${token}" "${fake_short}" >"${name}-short.secret"
		printf '%s\n' "${doc}" | swap "${token}" "${token}hunter2]" >"${name}-after.secret"
	done
	git add ./*.secret
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status (dotenv)"
	for name in comment-short comment-after value-short value-after sops_mac-short sops_mac-after; do
		assert_contains "${OUT}" "- ${name}.secret" "guard names the file (dotenv)"
	done
	assert_not_contains "${OUT}" "- real.secret" "guard output (dotenv)"
	assert_not_contains "${OUT}" "hunter2" "guard output (dotenv)"
	assert_not_contains "${OUT}" "MyPassword" "guard output (dotenv)"
}

# What sops writes for empty content passes the stricter check of the
# encrypted values (audit A-16): an empty file in either format, an empty
# value and an empty comment. sops writes no ENC[...] for those.
test_guard_passes_what_sops_writes_for_empty_content() {
	new_repo repo
	: >empty.secret
	git add empty.secret
	assert_contains "$(stored empty.secret)" '"data": ""' "test fixture: an empty file (json)"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status (json)"
	cd ..

	new_repo repo2 dotenv
	: >empty.secret
	printf '#\nEMPTY=\nA=1\n' >.env
	git add empty.secret .env
	assert_contains "$(stored .env)" $'#\nEMPTY=\n' "test fixture: an empty comment and an empty value"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status (dotenv)"
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

# The guard runs on every commit. Its time must follow the number of
# SOPS-managed files, not the number of tracked files: a bash loop over
# every tracked path took 8.5 seconds with 60,000 of them (audit A-01),
# 19 seconds with the 100,000 here. The guard needs 0.4 seconds on a
# laptop: the limit leaves a slow CI runner seven times that.
test_guard_is_fast_with_many_tracked_files() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'TOKEN=abc\n' >deploy.secret
	git add .env deploy.secret
	local before
	before="$(git ls-files | wc -l)"
	add_index_entries 100000
	assert_eq "$(git ls-files | wc -l | tr -d " ")" "$((before + 100000))" "test fixture: tracked files"

	timed "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status"
	faster_than "${SECS}" 3 || fail "the guard took ${SECS} s for 100,000 tracked files"

	# Among them, a plaintext secret is still found.
	stage_raw plain.secret .env
	timed "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "1" "guard exit status with a plaintext secret"
	faster_than "${SECS}" 3 || fail "the guard took ${SECS} s for 100,000 tracked files"
	run "${TOOL}/encryption-guard.sh"
	assert_contains "${OUT}" "- plain.secret" "guard names the file"
	assert_not_contains "${OUT}" "- .env" "guard output"
}

# Names that need quoting in git's text output, or that look like
# pathspec magic or an index stage. Each one must be found and named
# byte for byte, and nothing else. Staged straight into the index, so
# names a file system refuses can be tested too.
test_guard_names_plaintext_files_with_awkward_names() {
	unfiltered_repo
	local names=(
		'with space.secret'
		$'tab\there.secret'
		$'new\nline.secret'
		'quote"double.secret'
		"quote'single.secret"
		'back\slash.secret'
		'back\\two\"slashes.secret'
		$'ctrl\001char.secret'
		$'esc\033[31mred.secret'
		$'del\177char.secret'
		$'cr\rchar.secret'
		$'caf\303\251.secret'
		$'latin\351.secret'
		'glob*star[1]?.secret'
		':colon.secret'
		'!bang.secret'
		'-dash.secret'
		'2:stage.secret'
		':(literal)magic.secret'
		'"starts with a quote.secret'
		'sub dir/"quoted" dir/x.secret'
	)
	local name oid i=0
	for name in "${names[@]}"; do
		i=$((i + 1))
		oid="$(printf 'PW=hunter%s\n' "${i}" | git hash-object -w --stdin)"
		git update-index --add --cacheinfo "100644,${oid},${name}"
	done
	oid="$(printf 'not a secret\n' | git hash-object -w --stdin)"
	git update-index --add --cacheinfo "100644,${oid},plain.txt"
	git update-index --add --cacheinfo "100644,${oid},"$'tab\tplain.txt'
	git update-index --add --cacheinfo "100644,${oid},"$'caf\303\251.txt'

	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	for name in "${names[@]}"; do
		assert_contains "${OUT}" $'\n'"   - ${name}  (" "guard names [${name}]"
	done
	assert_not_contains "${OUT}" "plain.txt" "guard output"
	assert_not_contains "${OUT}" $'caf\303\251.txt' "guard output"
	assert_not_contains "${OUT}" "hunter" "guard output"
	assert_eq "$(printf '%s\n' "${OUT}" | grep -c '^   - ')" "${#names[@]}" "lines that name a file"
}

# sops_blob <text> : write an encrypted SOPS document (json) of <text>
# to the object store and print its object id
sops_blob() {
	printf '%s\n' "$1" |
		sops encrypt --input-type binary --output-type json --filename-override any.secret /dev/stdin |
		git hash-object -w --stdin
}

# set_stage <path> <stage> <object id> : put one stage of a conflict
# into the index (or replace it)
set_stage() {
	printf '100644 %s %s\t%s\n' "$3" "$2" "$1" | git update-index --index-info
}

# All three stages of an unmerged path are checked, also under a name
# git quotes.
test_guard_checks_every_stage_of_an_unmerged_path() {
	unfiltered_repo
	local name stage plain
	for name in c.secret $'tab\t"q".secret'; do
		for stage in 1 2 3; do
			set_stage "${name}" "${stage}" "$(sops_blob "stage ${stage}")"
		done
	done
	assert_eq "$(git ls-files -u | wc -l | tr -d ' ')" "6" "test fixture: unmerged entries"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status when every stage is encrypted"

	plain="$(printf 'PW=hunter2\n' | git hash-object -w --stdin)"
	for name in c.secret $'tab\t"q".secret'; do
		for stage in 1 2 3; do
			set_stage "${name}" "${stage}" "${plain}"
			assert_eq "$(git ls-files -u | wc -l | tr -d ' ')" "6" "test fixture: unmerged entries"
			run "${TOOL}/encryption-guard.sh"
			assert_ne "${RC}" "0" "guard exit status with plaintext in stage ${stage} of [${name}]"
			assert_contains "${OUT}" $'\n'"   - ${name}  (" "guard names [${name}] (stage ${stage})"
			set_stage "${name}" "${stage}" "$(sops_blob "stage ${stage}")"
		done
	done
}

# Intent to add is told from a staged empty file under names git quotes:
# a wrong name would look like "left out of the commit" and let the
# staged empty file through.
test_guard_tells_intent_to_add_from_staged_under_awkward_names() {
	unfiltered_repo
	local ita=$'ita\t"q" back\\slash \303\251.secret'
	local staged=$'staged\t"q" back\\slash \303\251.secret'
	printf 'PW=hunter2\n' >"${ita}"
	git add -N -- "${ita}"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status with an intent-to-add entry"

	: >"${staged}"
	git add -- "${staged}"
	run "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status with a staged empty file"
	assert_contains "${OUT}" "- ${staged}" "guard names the staged file"
	assert_not_contains "${OUT}" "- ${ita}" "guard output"
}

# If the guard cannot list the index it must not wave the commit through.
test_guard_fails_closed_when_ls_files_fails() {
	unfiltered_repo
	printf 'PW=hunter2\n' >.env
	git add .env
	stub ../fakebin git <<'STUB'
case " $* " in
*" ls-files "*)
	echo "fatal: simulated ls-files failure" >&2
	exit 128
	;;
esac
exec "${REAL}" "$@"
STUB
	run env PATH="${PWD}/../fakebin:${PATH}" "${TOOL}/encryption-guard.sh"
	assert_ne "${RC}" "0" "guard exit status"
	assert_contains "${OUT}" "COMMIT BLOCKED" "guard message"
}

# An answer of git check-attr that does not fit the listing (cut short,
# or in another order) is not an answer: the commit is blocked.
test_guard_fails_closed_when_check_attr_answers_wrong() {
	unfiltered_repo
	printf 'PW=hunter2\n' >.env
	printf 'TOKEN=abc\n' >b.secret
	echo docs >c.txt
	git add .env b.secret c.txt
	stub ../fakebin git <<'STUB'
case " $* " in
*" check-attr "*)
	case "${SGF_STUB_MODE}" in
	short) "${REAL}" "$@" </dev/null ;;
	reversed)
		case " $* " in
		*" -z "*) tr '\0\n' '\n\0' | sort -r | tr '\0\n' '\n\0' | "${REAL}" "$@" ;;
		*) sort -r | "${REAL}" "$@" ;;
		esac
		;;
	esac
	exit $?
	;;
esac
exec "${REAL}" "$@"
STUB
	local mode
	for mode in short reversed; do
		run env SGF_STUB_MODE="${mode}" PATH="${PWD}/../fakebin:${PATH}" "${TOOL}/encryption-guard.sh"
		assert_ne "${RC}" "0" "guard exit status (${mode})"
		assert_contains "${OUT}" "COMMIT BLOCKED: the encryption guard could not finish" "guard message (${mode})"
	done
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

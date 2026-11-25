#!/usr/bin/env bash
# rekey.sh
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

decrypt_as_b() { # stdin: a json-format blob; decrypt with key B only
	SOPS_AGE_KEY_FILE="${AGE_KEY_B}" sops decrypt --input-type json --output-type binary
}

test_rekey_adds_a_recipient() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "add recipient B"

	# Touching and re-adding changes nothing: the plaintext is the same,
	# so the clean filter reuses the stored blob.
	touch .env
	git add .env
	assert_not_contains "$(stored .env)" "${AGE_PUB_B}" "blob after touch + add"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_eq "$(stored .env | decrypt_as_b)" "A=1" "key B decrypts the staged blob"
	assert_eq "$(cat .env)" "A=1" "working copy is untouched"
	assert_eq "$(git status --porcelain)" "M  .env" "staged, nothing else"

	git commit -q -m "re-key for B"
	local id
	id="$(blob_id .env)"
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "second run"
	assert_contains "${OUT}" "0 file(s) re-keyed" "second run output"
	assert_eq "$(blob_id .env)" "${id}" "blob after a second run"
}

test_rekey_removes_a_recipient() {
	new_repo repo
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "recipients A and B"
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	assert_eq "$(stored .env | decrypt_as_b)" "A=1" "key B decrypts before"

	# shellcheck disable=SC2119  # back to key A only
	write_sops_yaml
	git add .sops.yaml
	git commit -q -m "remove recipient B"
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_not_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	run decrypt_as_b <<<"$(stored .env)"
	assert_ne "${RC}" "0" "key B must not decrypt the re-keyed blob"
	assert_eq "$(plain_of_stored .env)" "A=1" "key A still decrypts"
}

test_rekey_dotenv_nested_file() {
	new_repo repo dotenv
	mkdir -p stacks/app
	printf 'A=1\n' >stacks/app/.env
	git add stacks/app/.env
	git commit -q -m "add a nested .env"
	write_sops_yaml "${AGE_PUB_B}"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "$(stored stacks/app/.env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_eq "$(plain_of_stored stacks/app/.env dotenv)" "A=1" "plaintext"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard after the re-key"
}

# sops picks the creation rule by the file's path relative to .sops.yaml.
# The copies rekey.sh works on must sit at the same relative paths.
test_rekey_follows_path_rules() {
	new_repo repo
	mkdir -p team
	printf 'X=1\n' >team/shared.secret
	printf 'Y=1\n' >private.secret
	git add team/shared.secret private.secret
	git commit -q -m "two secrets, key A only"

	cat >.sops.yaml <<YAML
creation_rules:
  - path_regex: ^team/
    key_groups:
      - age:
          - ${AGE_PUB_A}
          - ${AGE_PUB_B}
  - path_regex: .*
    key_groups:
      - age:
          - ${AGE_PUB_A}
YAML
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "$(stored team/shared.secret)" "${AGE_PUB_B}" "team/ file gets recipient B"
	assert_not_contains "$(stored private.secret)" "${AGE_PUB_B}" "the other file does not"
}

test_rekey_dry_run_and_path_limit() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'B=1\n' >other.secret
	git add .env other.secret
	git commit -q -m "two secrets"
	write_sops_yaml "${AGE_PUB_B}"
	local env_id other_id
	env_id="$(blob_id .env)"
	other_id="$(blob_id other.secret)"

	run "${TOOL}/rekey.sh" --dry-run
	assert_eq "${RC}" "0" "dry run exit status"
	assert_contains "${OUT}" "would re-key  .env" "dry run output"
	assert_eq "$(blob_id .env)" "${env_id}" "dry run stages nothing"

	run "${TOOL}/rekey.sh" other.secret
	assert_eq "${RC}" "0" "limited run exit status"
	assert_ne "$(blob_id other.secret)" "${other_id}" "the named file is re-keyed"
	assert_eq "$(blob_id .env)" "${env_id}" "the other file is left alone"
}

test_rekey_reports_a_plaintext_blob() {
	git init -q repo
	cd repo || exit 1
	printf 'P=legacy\n' >.env
	git add .env
	git commit -q -m "plaintext secret, before the filter"
	vendor_tool
	write_sops_yaml
	printf '.env filter=sops diff=sops\n' >.gitattributes
	git add -A
	git commit -q -m "adopt sops-git-filters"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "1" "rekey.sh exit status"
	assert_contains "${OUT}" "FAILED  .env" "rekey.sh output"
	assert_eq "$(stored .env)" "P=legacy" "the blob is left alone"
}

test_rekey_without_keys_fails_and_stages_nothing() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	write_sops_yaml "${AGE_PUB_B}"
	local id
	id="$(blob_id .env)"

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/rekey.sh"
	assert_eq "${RC}" "1" "rekey.sh exit status"
	assert_eq "$(blob_id .env)" "${id}" "nothing staged"
	assert_eq "$(ls -d .git/sops-rekey.* 2>/dev/null || true)" "" "work directory removed"
}

# git could not write the index (another git process holds the lock, or
# the lock file of a crashed one is still there). Then nothing was
# re-keyed, and rekey.sh must say so and fail.
test_rekey_fails_when_the_index_cannot_be_written() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "add recipient B"
	local before
	before="$(blob_id .env)"

	: >.git/index.lock
	run "${TOOL}/rekey.sh"
	rm -f .git/index.lock
	assert_ne "${RC}" "0" "rekey.sh exit status while the index is locked"
	assert_contains "${OUT}" "FAILED  .env" "rekey.sh output"
	assert_not_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	assert_contains "${OUT}" "0 file(s) re-keyed and staged, 0 already match .sops.yaml, 1 failed" "rekey.sh summary"
	assert_eq "$(blob_id .env)" "${before}" "index entry after the failed run"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status without the lock"
	assert_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
}

# rekey.sh while the working copy still holds the old ciphertext (install.sh
# ran without the key). That copy is a SOPS document, but no longer the
# version git holds: git status must not take it for an edit that undoes
# the re-key. It decrypts to the same plaintext, so the re-keyed blob
# stays (audit A-13).
test_rekey_with_the_old_ciphertext_in_the_working_copy() {
	new_repo origin
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	cd ..
	fresh_clone origin clone
	run env SOPS_AGE_KEY_FILE="${NO_KEY}" "${TOOL}/install.sh"
	assert_contains "$(cat .env)" 'ENC[AES256_GCM' "working copy still holds ciphertext"

	write_sops_yaml "${AGE_PUB_B}"
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_eq "$(git status --porcelain -- .env)" "M  .env" "git status of .env"
	git add -A
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob after git add -A"
	assert_eq "$(stored .env | decrypt_as_b)" "A=1" "key B decrypts the staged blob"
}

# rekey.sh changes the index, and the commit that follows carries the
# .gitattributes of the index: which files are SOPS-managed is read from
# there, as the guard reads it, not from an unstaged edit (audit A-11).
test_rekey_reads_the_attributes_of_the_index() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'not a secret\n' >notes.txt
	git add .env notes.txt
	git commit -q -m "add .env and notes.txt"
	write_sops_yaml "${AGE_PUB_B}"
	git add .sops.yaml
	git commit -q -m "add recipient B"

	# Unstaged: .env loses filter=sops, notes.txt (plaintext in git) gets it.
	printf '.env -filter\n*.txt filter=sops diff=sops\n' >>.gitattributes
	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "${OUT}" "re-keyed  .env" "rekey.sh output"
	# (git may still run the clean filter on notes.txt to compare it, as
	# the working tree's attributes say; that stages nothing.)
	assert_not_contains "${OUT}" "FAILED  notes.txt" "a file the index does not mark is left alone"
	assert_not_contains "${OUT}" "re-keyed  notes.txt" "a file the index does not mark is left alone"
	assert_contains "$(stored .env)" "${AGE_PUB_B}" "recipient B in the staged blob"
	assert_eq "$(stored notes.txt)" "not a secret" "notes.txt in the index"
}

# sops_blob_for_a <text> : a SOPS document (json) of <text> for key A
# only, written to the object store; prints its object id
sops_blob_for_a() {
	printf '%s\n' "$1" |
		sops encrypt --age "${AGE_PUB_A}" --input-type binary --output-type json --filename-override any.secret /dev/stdin |
		git hash-object -w --stdin
}

# Names that git quotes in its text output, and names that look like
# pathspec magic, an option or an index stage: each one is re-keyed under
# its own name. Staged straight into the index.
test_rekey_handles_awkward_names() {
	new_repo repo
	local names=(
		'with space.secret'
		$'tab\there.secret'
		$'new\nline.secret'
		'quote"double.secret'
		"quote'single.secret"
		'back\slash.secret'
		$'ctrl\001char.secret'
		$'cr\rchar.secret'
		$'caf\303\251.secret'
		'glob*star[1]?.secret'
		':colon.secret'
		'-dash.secret'
		'2:stage.secret'
		':(literal)magic.secret'
		'"starts with a quote.secret'
		'sub dir/"quoted" dir/x.secret'
	)
	local name i=0
	for name in "${names[@]}"; do
		i=$((i + 1))
		git update-index --add --cacheinfo "100644,$(sops_blob_for_a "PW=${i}"),${name}"
	done
	git commit -q -m "awkward names"
	write_sops_yaml "${AGE_PUB_B}"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "${OUT}" "${#names[@]} file(s) re-keyed and staged, 0 already match .sops.yaml, 0 failed" "rekey.sh summary"
	i=0
	for name in "${names[@]}"; do
		i=$((i + 1))
		assert_contains "${OUT}" "re-keyed  ${name}"$'\n' "rekey.sh names [${name}]"
		assert_eq "$(git cat-file blob ":0:${name}" | decrypt_as_b)" "PW=${i}" "key B decrypts the staged blob of [${name}]"
	done
}

# A path in a conflict is not re-keyed: each of its stages is reported,
# and the other files are re-keyed all the same.
test_rekey_reports_unmerged_entries() {
	new_repo repo
	printf 'A=1\n' >.env
	git add .env
	git commit -q -m "add .env"
	local stage
	for stage in 1 2 3; do
		printf '100644 %s %s\tc.secret\n' "$(sops_blob_for_a "stage ${stage}")" "${stage}" | git update-index --index-info
	done
	write_sops_yaml "${AGE_PUB_B}"

	run "${TOOL}/rekey.sh"
	assert_eq "${RC}" "1" "rekey.sh exit status"
	assert_eq "$(printf '%s\n' "${OUT}" | grep -c '^FAILED  c.secret: unmerged')" "3" "one line per stage"
	assert_contains "${OUT}" "re-keyed  .env" "the other file is re-keyed"
	assert_contains "${OUT}" "1 file(s) re-keyed and staged, 0 already match .sops.yaml, 3 failed" "rekey.sh summary"
}

# Paths on the command line are taken from where rekey.sh is started.
test_rekey_path_limit_from_a_subdirectory() {
	new_repo repo
	mkdir -p team
	printf 'A=1\n' >team/a.secret
	printf 'B=1\n' >team/b.secret
	printf 'C=1\n' >c.secret
	git add team c.secret
	git commit -q -m "three secrets"
	write_sops_yaml "${AGE_PUB_B}"
	local b_id c_id
	b_id="$(blob_id team/b.secret)"
	c_id="$(blob_id c.secret)"

	run sh -c "cd team && '${PWD}/${TOOL}/rekey.sh' a.secret"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	assert_contains "${OUT}" "re-keyed  team/a.secret" "rekey.sh output"
	assert_eq "$(stored team/a.secret | decrypt_as_b)" "A=1" "key B decrypts the named file"
	assert_eq "$(blob_id team/b.secret)" "${b_id}" "the other file in the directory"
	assert_eq "$(blob_id c.secret)" "${c_id}" "the file outside the directory"

	run sh -c "cd team && '${PWD}/${TOOL}/rekey.sh' --dry-run nothing-here.secret"
	assert_eq "${RC}" "0" "rekey.sh exit status for a path that matches nothing"
	assert_contains "${OUT}" "No tracked files match." "rekey.sh output for a path that matches nothing"
	run "${TOOL}/rekey.sh" --dry-run notes.txt .gitattributes
	assert_contains "${OUT}" "0 file(s) would be re-keyed, 0 already match .sops.yaml, 0 failed." "rekey.sh output for files that are not SOPS-managed"
}

# An answer of git check-attr that does not fit the listing (cut short,
# or in another order) says nothing about which files are SOPS-managed:
# rekey.sh fails and stages nothing.
test_rekey_stages_nothing_when_check_attr_answers_wrong() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'TOKEN=abc\n' >b.secret
	git add .env b.secret
	git commit -q -m "two secrets"
	write_sops_yaml "${AGE_PUB_B}"
	local index_before mode
	index_before="$(git ls-files -s)"
	stub ../fakebin git <<'STUB'
case " $* " in
*" check-attr "*)
	case "${SGF_STUB_MODE}" in
	short) "${REAL}" "$@" </dev/null ;;
	reversed) sort -r | "${REAL}" "$@" ;;
	esac
	exit $?
	;;
esac
exec "${REAL}" "$@"
STUB
	for mode in short reversed; do
		run env SGF_STUB_MODE="${mode}" PATH="${PWD}/../fakebin:${PATH}" "${TOOL}/rekey.sh"
		assert_eq "${RC}" "1" "rekey.sh exit status (${mode})"
		assert_contains "${OUT}" "Nothing was re-keyed" "rekey.sh message (${mode})"
		assert_not_contains "${OUT}" "re-keyed  " "rekey.sh output (${mode})"
		assert_eq "$(git ls-files -s)" "${index_before}" "the index (${mode})"
	done
}

# rekey.sh walked every tracked path in bash, twice, the slow pattern the
# guard lost in audit A-01: 19 seconds with 60,000 tracked files, 50 with
# the 100,000 here. It now lists the SOPS-managed entries as the guard
# does, and its time follows their number: 0.6 seconds here on a laptop,
# for both runs. The limit leaves a slow CI runner six times that.
test_rekey_is_fast_with_many_tracked_files() {
	new_repo repo
	printf 'A=1\n' >.env
	printf 'TOKEN=abc\n' >deploy.secret
	git add .env deploy.secret
	git commit -q -m "two secrets"
	write_sops_yaml "${AGE_PUB_B}"
	local before
	before="$(git ls-files | wc -l)"
	add_index_entries 100000
	assert_eq "$(git ls-files | wc -l | tr -d " ")" "$((before + 100000))" "test fixture: tracked files"

	timed "${TOOL}/rekey.sh" --dry-run
	assert_eq "${RC}" "0" "rekey.sh --dry-run exit status"
	faster_than "${SECS}" 4 || fail "rekey.sh --dry-run took ${SECS} s for 100,000 tracked files"
	timed "${TOOL}/rekey.sh"
	assert_eq "${RC}" "0" "rekey.sh exit status"
	faster_than "${SECS}" 4 || fail "rekey.sh took ${SECS} s for 100,000 tracked files"
	assert_eq "$(stored .env | decrypt_as_b)" "A=1" "key B decrypts .env"
	assert_eq "$(stored deploy.secret | decrypt_as_b)" "TOKEN=abc" "key B decrypts deploy.secret"
}

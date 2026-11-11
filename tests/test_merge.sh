#!/usr/bin/env bash
# merge-driver.sh (merge=sops)
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

# merge_repo [json|dotenv] : a repository with merge=sops on .env, a base
# commit (A=1, B=2, C=3) and a branch "theirs". Leaves the caller on "theirs".
merge_repo() {
	new_repo repo "${1:-json}"
	printf '.env filter=sops diff=sops merge=sops\n' >.gitattributes
	git add .gitattributes
	git commit -q -m "merge=sops on .env"
	printf 'A=1\nB=2\nC=3\n' >.env
	git add .env
	git commit -q -m "base"
	git checkout -q -b theirs
}

# commit_env <message> <content> : replace .env and commit it
commit_env() {
	printf '%s' "$2" >.env
	git add .env
	git commit -q -m "$1"
}

# no_plaintext_in_objects <marker> : no blob in the object store holds <marker>
no_plaintext_in_objects() {
	local id
	for id in $(git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)' | awk '$2 == "blob" {print $1}'); do
		if git cat-file blob "${id}" | grep -q -- "$1"; then
			fail "blob ${id} holds plaintext ($1)"
		fi
	done
}

test_merge_json_combines_changes_to_different_lines() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'

	run git merge --no-edit theirs
	assert_eq "${RC}" "0" "git merge exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs' "merged working copy"
	assert_eq "$(plain_of_stored .env)" $'A=ours\nB=2\nC=theirs' "merged blob"
	assert_eq "$(git status --porcelain)" "" "git status"
	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard after the merge"
	no_plaintext_in_objects 'C=theirs'
}

test_merge_dotenv_combines_changes_to_different_lines() {
	merge_repo dotenv
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'

	run git merge --no-edit theirs
	assert_eq "${RC}" "0" "git merge exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs' "merged working copy"
	assert_eq "$(plain_of_stored .env dotenv)" $'A=ours\nB=2\nC=theirs' "merged blob"
	assert_eq "$(git status --porcelain)" "" "git status"
}

# Both sides changed the same line: an ordinary conflict, markers in plaintext.
test_merge_json_conflict_can_be_resolved() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: C" $'A=1\nB=2\nC=ours\n'

	run git merge --no-edit theirs
	assert_ne "${RC}" "0" "git merge exit status"
	git rev-parse -q --verify MERGE_HEAD >/dev/null || fail "no merge in progress (MERGE_HEAD missing)"
	assert_ne "$(git ls-files -u -- .env)" "" "conflict stages in the index"
	assert_contains "$(cat .env)" "<<<<<<< ours" "working copy"
	assert_contains "$(cat .env)" "C=ours" "working copy"
	assert_contains "$(cat .env)" "C=theirs" "working copy"

	printf 'A=1\nB=2\nC=resolved\n' >.env
	git add .env
	git commit -q --no-edit
	assert_eq "$(plain_of_stored .env)" $'A=1\nB=2\nC=resolved' "resolved blob"
	assert_eq "$(git status --porcelain)" "" "git status"
	no_plaintext_in_objects 'C=ours'
	no_plaintext_in_objects 'C=resolved'
}

# dotenv cannot hold marker lines: our version stays, the conflict is reported.
test_merge_dotenv_conflict_keeps_ours_and_can_take_theirs() {
	merge_repo dotenv
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: C" $'A=1\nB=2\nC=ours\n'

	run git merge --no-edit theirs
	assert_ne "${RC}" "0" "git merge exit status"
	git rev-parse -q --verify MERGE_HEAD >/dev/null || fail "no merge in progress (MERGE_HEAD missing)"
	assert_eq "$(cat .env)" $'A=1\nB=2\nC=ours' "working copy keeps our version"
	assert_contains "${OUT}" "OUR version was kept" "driver message"

	git checkout --theirs -- .env
	assert_eq "$(cat .env)" $'A=1\nB=2\nC=theirs' "working copy after checkout --theirs"
	git add .env
	git commit -q --no-edit
	assert_eq "$(plain_of_stored .env dotenv)" $'A=1\nB=2\nC=theirs' "resolved blob"
}

test_merge_abort_restores_our_version() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: C" $'A=1\nB=2\nC=ours\n'

	run git merge --no-edit theirs
	assert_ne "${RC}" "0" "git merge exit status"
	git merge --abort
	assert_eq "$(cat .env)" $'A=1\nB=2\nC=ours' "working copy after merge --abort"
	assert_eq "$(git status --porcelain)" "" "git status"
}

# Without keys the driver cannot merge. The file must stay as it was.
test_merge_without_keys_leaves_the_file_alone() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'

	run env SOPS_AGE_KEY_FILE="${NO_KEY}" git merge --no-edit theirs
	assert_ne "${RC}" "0" "git merge exit status"
	assert_contains "${OUT}" "cannot decrypt" "driver message"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=3' "working copy is untouched"
	assert_eq "$(ls -d .git/sops-merge.* 2>/dev/null || true)" "" "no plaintext left under .git"
	if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
		git merge --abort
	fi
	assert_eq "$(git status --porcelain)" "" "git status"
}

test_merge_rebase_combines_changes() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'

	run git rebase theirs
	assert_eq "${RC}" "0" "git rebase exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs' "working copy after rebase"
	assert_eq "$(git status --porcelain)" "" "git status"
}

test_merge_cherry_pick_combines_changes() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'

	run git cherry-pick theirs
	assert_eq "${RC}" "0" "git cherry-pick exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs' "working copy after cherry-pick"
}

# git stash --keep-index, then pop: a three-way merge of two versions of the
# secret. It used to die whenever a secret had staged AND unstaged changes.
test_merge_stash_keep_index_then_pop() {
	merge_repo json
	git checkout -q main
	printf 'A=staged\nB=2\nC=3\n' >.env
	git add .env
	printf 'A=staged\nB=2\nC=unstaged\n' >.env

	git stash push -q --keep-index -m wip
	assert_eq "$(cat .env)" $'A=staged\nB=2\nC=3' "working copy while stashed"
	run git stash pop
	assert_eq "${RC}" "0" "git stash pop exit status"
	assert_eq "$(cat .env)" $'A=staged\nB=2\nC=unstaged' "working copy after stash pop"
}

# Two merges at once in one repository (two terminals, an IDE working in
# the background): the files of the one that is still running must
# survive the start of the other. Only what a dead run left behind goes.
test_merge_keeps_the_files_of_a_merge_that_is_still_running() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'

	local gitdir running gone
	gitdir="$(git rev-parse --absolute-git-dir)"
	mkdir "${gitdir}/sops-merge.LIVE01" "${gitdir}/sops-merge.DEAD01" "${gitdir}/sops-merge.OLD001" "${gitdir}/sops-merge.NEW001"
	sleep 60 &
	running=$!
	printf '%s\n' "${running}" >"${gitdir}/sops-merge.LIVE01/pid"
	printf 'A=the other merge is still reading this\n' >"${gitdir}/sops-merge.LIVE01/ours"
	(:) &
	gone=$!
	wait "${gone}"
	printf '%s\n' "${gone}" >"${gitdir}/sops-merge.DEAD01/pid"
	touch -t 202001010000 "${gitdir}/sops-merge.OLD001"

	run git merge --no-edit theirs
	kill "${running}" 2>/dev/null || true
	assert_eq "${RC}" "0" "git merge exit status"
	assert_eq "$(cat .env)" $'A=ours\nB=2\nC=theirs' "merged working copy"
	[[ -f "${gitdir}/sops-merge.LIVE01/ours" ]] || fail "the files of a merge that is still running were removed"
	[[ -d "${gitdir}/sops-merge.NEW001" ]] || fail "the directory of a merge that is just starting was removed"
	[[ ! -e "${gitdir}/sops-merge.DEAD01" ]] || fail "what a dead run left behind is still there"
	[[ ! -e "${gitdir}/sops-merge.OLD001" ]] || fail "a directory from years ago is still there"
}

test_merge_leaves_no_plaintext_under_git_dir() {
	merge_repo json
	commit_env "theirs: C" $'A=1\nB=2\nC=theirs\n'
	git checkout -q main
	commit_env "ours: A" $'A=ours\nB=2\nC=3\n'
	git merge -q --no-edit theirs
	assert_eq "$(ls -d .git/sops-merge.* 2>/dev/null || true)" "" "work directory removed"
	assert_eq "$(find . -maxdepth 1 -name '.merge_file_*' | wc -l | tr -d ' ')" "0" "git's own temporary files removed"
}

#!/usr/bin/env bash
# The pre-commit framework (or prek) with the guard as a local hook.
# These tests are skipped when neither tool is on PATH. SGF_HOOK_RUNNER
# names the one to use; CI sets it, together with SGF_NO_SKIP=1.
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh

hook_runner() {
	if [[ -n "${SGF_HOOK_RUNNER:-}" ]]; then
		command -v "${SGF_HOOK_RUNNER}" 2>/dev/null || true
	else
		command -v pre-commit 2>/dev/null || command -v prek 2>/dev/null || true
	fi
}

precommit_repo() {
	new_repo repo
	cat >.pre-commit-config.yaml <<'YAML'
repos:
  - repo: local
    hooks:
      - id: sops-encryption-guard
        name: Verify SOPS-managed files are encrypted
        language: script
        entry: utilities/sops-git-filters/encryption-guard.sh
        pass_filenames: false
        always_run: true
        stages: [pre-commit]
YAML
	git add .pre-commit-config.yaml
	git commit -q -m "hook configuration"
	"$1" install >/dev/null
	printf 'A=1\nB=2\n' >.env
	git add .env
	git commit -q -m "add .env"
}

# pre-commit stashes unstaged changes as a patch, runs the hooks, and
# applies the patch again. The clean filter compares with the INDEX so
# that this works for a secret with staged and unstaged edits.
test_precommit_stash_keeps_unstaged_edits_of_a_secret() {
	local runner
	runner="$(hook_runner)"
	[[ -n "${runner}" ]] || skip "pre-commit / prek not on PATH"
	precommit_repo "${runner}"

	printf 'A=staged\nB=2\n' >.env
	git add .env
	local staged
	staged="$(blob_id .env)"
	printf 'A=staged\nB=not staged yet\n' >.env

	run git commit -m "commit the staged part only"
	assert_eq "${RC}" "0" "git commit exit status"
	assert_eq "$(git rev-parse HEAD:.env)" "${staged}" "the committed blob is the staged one"
	assert_eq "$(cat .env)" $'A=staged\nB=not staged yet' "working copy keeps the unstaged edit"
	assert_eq "$(git status --porcelain)" " M .env" "git status"
}

# A clone where install.sh never ran has no filter. With the hooks wired,
# the guard is what stops a plaintext secret there.
test_precommit_guard_blocks_plaintext_in_a_clone_without_filters() {
	local runner
	runner="$(hook_runner)"
	[[ -n "${runner}" ]] || skip "pre-commit / prek not on PATH"
	precommit_repo "${runner}"
	cd ..

	fresh_clone repo clone
	"${runner}" install >/dev/null
	printf 'A=plaintext\nB=2\n' >.env
	git add .env
	run git commit -m "plaintext secret from a clone without filters"
	assert_ne "${RC}" "0" "git commit exit status"
	assert_contains "${OUT}" "COMMIT BLOCKED" "guard message"
}

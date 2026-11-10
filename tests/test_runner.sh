#!/usr/bin/env bash
# tests/run.sh itself
# shellcheck disable=SC2154  # OUT/RC/HERE come from tests/run.sh and tests/lib.sh

# mini_runner <dir> : a copy of the runner with one test file of its own,
# read from stdin, and a stand-in tool directory (<dir>/tool).
mini_runner() {
	mkdir -p "$1/tests" "$1/tool"
	cp "${HERE}/run.sh" "${HERE}/lib.sh" "$1/tests/"
	printf '#!/bin/sh\n' >"$1/tool/marker.sh"
	cat >"$1/tests/test_mini.sh"
}

# SGF_TOOL_DIR=../main must work: the tests do not run where the runner
# was started.
test_runner_accepts_a_relative_tool_dir() {
	mini_runner mini <<'MINI'
test_mini_finds_the_tool() {
	[[ -f "${SGF_TOOL_DIR}/marker.sh" ]] || fail "SGF_TOOL_DIR does not lead to the tool from $(pwd): ${SGF_TOOL_DIR}"
}
MINI
	cd mini || exit 1
	run env SGF_TEST_INNER=0 SGF_TOOL_DIR=tool bash tests/run.sh
	assert_eq "${RC}" "0" "runner exit status with SGF_TOOL_DIR=tool"
	assert_contains "${OUT}" "1 passed, 0 failed" "runner summary"

	run env SGF_TEST_INNER=0 SGF_TOOL_DIR=no-such-dir bash tests/run.sh
	assert_eq "${RC}" "2" "runner exit status when SGF_TOOL_DIR does not exist"
}

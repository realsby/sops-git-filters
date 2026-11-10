#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Test runner for sops-git-filters                                ║
# ║                                                                  ║
# ║    tests/run.sh            run every test                        ║
# ║    tests/run.sh guard      run the tests whose name has "guard"  ║
# ║                                                                  ║
# ║  Needs git, sops and age-keygen on PATH. Every test works in a   ║
# ║  throwaway repository with a throwaway age key. The runner       ║
# ║  re-executes itself in an EMPTY environment, so nothing from     ║
# ║  your own git, sops, AWS or GPG setup is read, and no test       ║
# ║  touches the network.                                            ║
# ║                                                                  ║
# ║    SGF_TOOL_DIR=<dir>   test the scripts of another checkout     ║
# ║    SGF_KEEP=1           keep the temporary directory             ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Outer call: build the sandbox, then start again inside it ────
if [[ "${SGF_TEST_INNER:-}" != "1" ]]; then
	for tool in git sops age-keygen; do
		if ! command -v "${tool}" >/dev/null 2>&1; then
			echo "tests/run.sh: ${tool} not found on PATH" >&2
			exit 2
		fi
	done

	root="$(mktemp -d "${TMPDIR:-/tmp}/sgf-tests.XXXXXX")"
	# Physical path: git reports physical paths, and on macOS the temp
	# directory sits behind a symlink.
	root="$(cd "${root}" && pwd -P)"
	mkdir -p "${root}/home" "${root}/tmp" "${root}/keys" "${root}/work"

	exec env -i \
		PATH="${PATH}" \
		HOME="${root}/home" \
		TMPDIR="${root}/tmp" \
		LANG=C LC_ALL=C TERM=dumb \
		GIT_CONFIG_NOSYSTEM=1 \
		GIT_CONFIG_GLOBAL="${root}/gitconfig" \
		GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat PAGER=cat \
		SOPS_AGE_KEY_FILE="${root}/keys/a.txt" \
		AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
		AWS_EC2_METADATA_DISABLED=true \
		SGF_TEST_INNER=1 \
		SGF_TEST_ROOT="${root}" \
		SGF_TOOL_DIR="${SGF_TOOL_DIR:-$(dirname "${HERE}")}" \
		SGF_KEEP="${SGF_KEEP:-}" \
		bash "${HERE}/run.sh" "$@"
fi

# ── Inner call: run the tests ────
# shellcheck source=tests/lib.sh
. "${HERE}/lib.sh"

cleanup() {
	if [[ "${SGF_KEEP}" == "1" ]]; then
		echo "kept: ${SGF_TEST_ROOT}"
	else
		rm -rf "${SGF_TEST_ROOT}"
	fi
}
trap cleanup EXIT

sgf_test_setup

for file in "${HERE}"/test_*.sh; do
	# shellcheck source=/dev/null
	. "${file}"
done

filter="${1:-}"
passed=0
failed=0
skipped=0
failed_names=""

echo "sops $(sops --disable-version-check --version 2>/dev/null | head -1 | awk '{print $2}'), $(git --version), bash ${BASH_VERSION}"
echo "scripts under test: ${SGF_TOOL_DIR}"

for name in $(declare -F | awk '{print $3}' | grep '^test_' | sort); do
	if [[ -n "${filter}" && "${name}" != *"${filter}"* ]]; then
		continue
	fi
	dir="${SGF_TEST_ROOT}/work/${name}"
	mkdir -p "${dir}"

	# Not an `if`: errexit must stay active inside the test's subshell.
	set +e
	(
		set -euo pipefail
		cd "${dir}"
		"${name}"
	) >"${dir}.log" 2>&1
	status=$?
	set -e

	if [[ "${status}" -eq 0 ]]; then
		passed=$((passed + 1))
		echo "ok   - ${name}"
	elif [[ "${status}" -eq 77 ]]; then
		skipped=$((skipped + 1))
		echo "skip - ${name} ($(tail -1 "${dir}.log"))"
	else
		failed=$((failed + 1))
		failed_names="${failed_names} ${name}"
		echo "FAIL - ${name}"
		sed 's/^/    | /' "${dir}.log"
	fi
done

echo
if [[ "${skipped}" -gt 0 ]]; then
	echo "${passed} passed, ${failed} failed, ${skipped} skipped"
else
	echo "${passed} passed, ${failed} failed"
fi
if [[ "${failed}" -ne 0 ]]; then
	echo "failed:${failed_names}"
	exit 1
fi

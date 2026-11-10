#!/usr/bin/env bash
# Helpers for the test files. Sourced by tests/run.sh.
# shellcheck disable=SC2034  # variables here are used by the test files

# Where the tool lives inside every test repository (the submodule /
# vendored layout the README recommends).
TOOL=utilities/sops-git-filters

# ── One-time setup: throwaway keys and git identity ────
sgf_test_setup() {
	age-keygen -o "${SGF_TEST_ROOT}/keys/a.txt" 2>/dev/null
	age-keygen -o "${SGF_TEST_ROOT}/keys/b.txt" 2>/dev/null
	AGE_PUB_A="$(age-keygen -y "${SGF_TEST_ROOT}/keys/a.txt")"
	AGE_PUB_B="$(age-keygen -y "${SGF_TEST_ROOT}/keys/b.txt")"
	AGE_KEY_B="${SGF_TEST_ROOT}/keys/b.txt"
	NO_KEY="${SGF_TEST_ROOT}/keys/does-not-exist.txt"

	git config --global user.name "Test"
	git config --global user.email "test@example.invalid"
	git config --global init.defaultBranch main
	git config --global commit.gpgsign false
	git config --global advice.detachedHead false
}

# ── Assertions (a failed assertion ends the test) ────
fail() {
	echo "ASSERTION FAILED: $*" >&2
	exit 1
}

assert_eq() { # <actual> <expected> [what]
	[[ "$1" == "$2" ]] || fail "${3:-value}: expected [$2], got [$1]"
}

assert_ne() { # <actual> <unexpected> [what]
	[[ "$1" != "$2" ]] || fail "${3:-value}: must not be [$2]"
}

assert_contains() { # <text> <needle> [what]
	case "$1" in
	*"$2"*) ;;
	*) fail "${3:-text}: [$2] not found in [${1:0:600}]" ;;
	esac
}

assert_not_contains() { # <text> <needle> [what]
	case "$1" in
	*"$2"*) fail "${3:-text}: [$2] must not appear" ;;
	*) ;;
	esac
}

# run <command...> : never fails; sets OUT (stdout+stderr) and RC
run() {
	RC=0
	OUT="$("$@" 2>&1)" || RC=$?
}

# ── Repository helpers ────
vendor_tool() {
	mkdir -p "${TOOL}"
	cp "${SGF_TOOL_DIR}"/*.sh "${TOOL}/"
	chmod +x "${TOOL}"/*.sh
}

# write_sops_yaml [extra age recipient...] : catch-all rule, key A first
# shellcheck disable=SC2120  # the extra recipients are optional
write_sops_yaml() {
	{
		printf 'creation_rules:\n  - path_regex: .*\n    key_groups:\n      - age:\n'
		printf '          - %s\n' "${AGE_PUB_A}" "$@"
	} >.sops.yaml
}

# new_repo <dir> [json|dotenv] : create a configured repository and cd into it
new_repo() {
	local dir="$1" format="${2:-json}"
	git init -q "${dir}"
	cd "${dir}" || exit 1
	vendor_tool
	# shellcheck disable=SC2119  # no extra recipients here
	write_sops_yaml
	printf '.env filter=sops diff=sops\n*.secret filter=sops diff=sops\n' >.gitattributes
	if [[ "${format}" != "json" ]]; then
		printf 'SOPS_STORE_FORMAT=%s\n' "${format}" >.sops-filter.conf
	fi
	git add -A
	git commit -q -m scaffold
	"${TOOL}/install.sh"
}

# fresh_clone <source-dir> <new-dir> : clone WITHOUT running install.sh, cd into it
fresh_clone() {
	git clone -q "$1" "$2"
	cd "$2" || exit 1
}

# path_with_only <dir> <command...> : link the named commands into <dir>
# and print its path. As PATH it hides every other command (sops, say).
path_with_only() {
	local dir="$1" cmd
	shift
	mkdir -p "${dir}"
	for cmd in "$@"; do
		ln -sf "$(command -v "${cmd}")" "${dir}/${cmd}"
	done
	(cd "${dir}" && pwd)
}

# stored <path> : the blob git holds for <path> in the index
stored() {
	git cat-file blob "$(git ls-files -s -- "$1" | awk '{print $2}')"
}

# plain_of_stored <path> [format] : decrypt the index blob of <path>
plain_of_stored() {
	if [[ "${2:-json}" == "dotenv" ]]; then
		stored "$1" | sops decrypt --input-type dotenv --output-type dotenv /dev/stdin
	else
		stored "$1" | sops decrypt --input-type json --output-type binary /dev/stdin
	fi
}

blob_id() { # <path> : object id of the index entry
	git ls-files -s -- "$1" | awk '{print $2}'
}

# stub <dir> <command> : write an executable stand-in for <command> into
# <dir>; the script body comes from stdin. REAL holds the real command.
stub() {
	mkdir -p "$1"
	{
		printf '#!/usr/bin/env bash\nREAL=%q\n' "$(command -v "$2")"
		cat
	} >"$1/$2"
	chmod +x "$1/$2"
}

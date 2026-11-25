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

# skip <reason> : end the test without counting it as passed or failed
skip() {
	echo "$*"
	exit 77
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
	(CDPATH='' cd -- "${dir}" && pwd)
}

# path_without <dir> <command...> : link every command on PATH into <dir>
# except the ones named, and print its path. As PATH it is the same PATH
# without those commands (the first of each name wins, as for PATH).
path_without() {
	local dir="$1" entry IFS=:
	shift
	mkdir -p "${dir}"
	for entry in ${PATH}; do
		[[ -d "${entry}" ]] || continue
		# One ln per directory; names that are already there fail and stay.
		ln -s "${entry}"/* "${dir}/" 2>/dev/null || true
	done
	for entry in "$@"; do
		rm -f "${dir:?}/${entry}"
	done
	(CDPATH='' cd -- "${dir}" && pwd)
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

# swap <old> <new>   (text on stdin) : the first <old> becomes <new>, as text
swap() {
	awk -v old="$1" -v new="$2" '!done && (i = index($0, old)) {
		$0 = substr($0, 1, i - 1) new substr($0, i + length(old))
		done = 1
	}
	{ print }'
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

# installed_dir : where install.sh puts the copy of the scripts git runs
installed_dir() {
	printf '%s/sops-git-filters\n' "$(CDPATH='' cd -- "$(git rev-parse --git-common-dir)" && pwd -P)"
}

# installed_source : the checkout of the tool, as install.sh recorded it
installed_source() {
	sed -n 's/^source=//p' "$(installed_dir)/INSTALLED"
}

# The filter commands install.sh writes: the same in every repository.
# shellcheck disable=SC2016  # the command substitution belongs to git's shell
INSTALLED_CMD_PREFIX='"$(git rev-parse --git-common-dir)"/sops-git-filters'

# mode_of <file> : permission bits as octal digits (GNU and BSD stat)
mode_of() {
	stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"
}

# add_index_entries <count> : put <count> more files into the index, the
# way a large repository has them: filler/dNNN/fNNNNNN.txt, spread over
# 300 directories, all with the same small blob. Only the index gets
# them, no file is written to disk: enough for what lists the index.
add_index_entries() {
	local oid
	oid="$(printf 'filler\n' | git hash-object -w --stdin)"
	awk -v n="$1" -v oid="${oid}" 'BEGIN {
		for (i = 0; i < n; i++) printf "100644 %s\tfiller/d%03d/f%06d.txt\n", oid, i % 300, i
	}' | git update-index --index-info
}

# timed <command...> : never fails; runs the command with its output
# discarded, sets RC and SECS (wall-clock seconds, e.g. 0.123)
timed() {
	local TIMEFORMAT=%R
	RC=0
	SECS="$({ time "$@" >/dev/null 2>&1; } 2>&1)" || RC=$?
}

# faster_than <seconds> <limit> : true when <seconds> < <limit>
faster_than() {
	awk -v s="$1" -v limit="$2" 'BEGIN { exit !(s + 0 < limit + 0) }'
}

# ── Hooks that earlier releases wrote ────
# old_hook <hook name> <the HARDEN line> : the hook file as install.sh
# wrote it from v1.1.0 to v2.0.0, byte for byte
old_hook() {
	cat <<EOF_HOOK
#!/usr/bin/env bash
# managed by sops-git-filters (secret file permissions)
#
# $1: git cannot store mode 0600, so a checkout or merge that
# re-runs the SOPS smudge filter recreates secrets with the caller's
# umask (0644 by default). Re-tighten every filter=sops file.
#
# Generated by install.sh — edit harden-permissions.sh, not this file.
# Delete it to opt out; re-running install.sh restores it.
set -u
root="\$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
$2
[ -x "\${HARDEN}" ] || exit 0
"\${HARDEN}" --root "\${root}" --quiet || true
exit 0
EOF_HOOK
}

# hook_of_2_1 <hook name> <the HARDEN line> : the hook file as install.sh
# wrote it in v2.1.x, byte for byte
hook_of_2_1() {
	cat <<EOF_HOOK
#!/usr/bin/env bash
# managed by sops-git-filters (secret file permissions)
#
# $1: git cannot store mode 0600, so a command that writes a
# SOPS-managed file again (through the smudge filter) leaves it with
# the caller's umask (0644 by default). Re-tighten every filter=sops file.
#
# Generated by install.sh — edit harden-permissions.sh, not this file.
# Delete it to opt out; re-running install.sh restores it.
set -u
root="\$(git rev-parse --show-toplevel 2>/dev/null)" || exit 0
$2
[ -x "\${HARDEN}" ] || exit 0
"\${HARDEN}" --root "\${root}" --quiet || true
exit 0
EOF_HOOK
}

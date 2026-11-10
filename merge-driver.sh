#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS merge driver for git                                       ║
# ║                                                                  ║
# ║  Git merges what it stores, and for a SOPS-managed file that is  ║
# ║  ciphertext. When both sides changed a secret, the two blobs     ║
# ║  differ on every line, git writes conflict markers INTO the      ║
# ║  ciphertext, the smudge filter cannot decrypt the result, and    ║
# ║  the merge dies half-way: no MERGE_HEAD, nothing to abort, and   ║
# ║  the working copy of the file is gone. Rebase, cherry-pick and   ║
# ║  stash pop fail the same way.                                    ║
# ║                                                                  ║
# ║  This driver merges the PLAINTEXT instead:                       ║
# ║                                                                  ║
# ║    1. decrypt the three versions (ancestor, ours, theirs)        ║
# ║    2. run `git merge-file` on the plaintext                      ║
# ║    3. encrypt the result with clean-filter.sh and hand it back   ║
# ║                                                                  ║
# ║  Turn it on per path in .gitattributes:                          ║
# ║                                                                  ║
# ║    .env  filter=sops diff=sops merge=sops                        ║
# ║                                                                  ║
# ║  install.sh registers the driver (merge.sops.driver).            ║
# ║                                                                  ║
# ║  A real conflict (both sides changed the same lines):            ║
# ║    json format    the working copy gets the usual                ║
# ║                   <<<<<<< ======= >>>>>>> markers, in            ║
# ║                   plaintext. Edit the file, then `git add` it.   ║
# ║    dotenv format  marker lines are not KEY=VALUE and cannot be   ║
# ║                   stored. OUR version is kept and the conflict   ║
# ║                   is reported; take a side with                  ║
# ║                   `git checkout --theirs|--ours -- <file>` or    ║
# ║                   use `git mergetool`, then `git add`.           ║
# ║                                                                  ║
# ║  Plaintext on disk: the three decrypted versions exist for the   ║
# ║  length of the merge in a private directory (mode 0700) under    ║
# ║  .git/, removed on exit. `git merge-file` needs real files.      ║
# ║                                                                  ║
# ║  Exit status (git's contract for merge drivers):                 ║
# ║    0    merged cleanly                                           ║
# ║    1    conflict                                                 ║
# ║    129  the driver could not work (no sops, no keys): git        ║
# ║         treats it as a failed merge of this file, not as a       ║
# ║         conflict, and the file is left as it was                 ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

fail() {
	echo "sops merge driver: $*" >&2
	exit 129
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -r "${SCRIPT_DIR}/lib.sh" ]] || fail "lib.sh is missing next to merge-driver.sh (${SCRIPT_DIR})"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

# merge.sops.driver = <this script> %O %A %B %L %P
#   %O ancestor, %A ours (and where the result goes), %B theirs: temporary
#   files holding the stored blobs, i.e. ciphertext. %L marker size.
#   %P the path of the file being merged.
[[ $# -eq 5 ]] || fail "usage: merge-driver.sh %O %A %B %L %P"
BASE="$1"
OURS="$2"
THEIRS="$3"
MARKER_SIZE="$4"
PATHNAME="$5"

command -v sops >/dev/null 2>&1 || fail "sops not found on PATH"
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "not inside a git repository"
STORE_FORMAT="$(sgf_store_format "${PROJECT_ROOT}")" || exit 129
OTHER_FORMAT="$(sgf_other_format "${STORE_FORMAT}")"

case "${STORE_FORMAT}" in
json) DECRYPT_ARGS=(--input-type json --output-type binary) ;;
dotenv) DECRYPT_ARGS=(--input-type dotenv --output-type dotenv) ;;
esac

# ── A private place for the plaintext ────
# Under .git: same disk as the working tree's own plaintext, never
# swept into a commit, and not a shared temp directory.
GIT_DIR_ABS="$(git rev-parse --absolute-git-dir 2>/dev/null)" || fail "cannot locate the git directory"
umask 077
# A run that was killed (SIGKILL) could not clean up after itself and
# left plaintext behind. Remove such leftovers now: only directories
# that match this script's own mktemp template.
for stale in "${GIT_DIR_ABS}"/sops-merge.??????; do
	if [[ -d "${stale}" && ! -L "${stale}" ]]; then
		rm -rf "${stale}"
	fi
done
WORK="$(mktemp -d "${GIT_DIR_ABS}/sops-merge.XXXXXX")" || fail "cannot create a work directory under ${GIT_DIR_ABS}"
trap 'rm -rf "${WORK}"' EXIT
trap 'exit 129' HUP INT TERM

# decrypt_version <file with the stored blob> <file for the plaintext> <which>
decrypt_version() {
	local src="$1" dst="$2" which="$3" content
	if [[ ! -s "${src}" ]]; then
		# Empty: the file does not exist on this side.
		: >"${dst}"
		return 0
	fi
	content="$(cat "${src}" && printf x)"
	content="${content%x}"
	if sgf_is_sops_doc "${STORE_FORMAT}" "${content}"; then
		sops decrypt "${DECRYPT_ARGS[@]}" --filename-override "${PATHNAME}" "${src}" >"${dst}" ||
			fail "cannot decrypt ${which} version of ${PATHNAME} (sops' message is above). Are your keys or cloud credentials available?"
	elif sgf_is_sops_doc "${OTHER_FORMAT}" "${content}"; then
		fail "${which} version of ${PATHNAME} is stored in the ${OTHER_FORMAT} format, but .sops-filter.conf says ${STORE_FORMAT}. Finish the format change on both branches first."
	else
		# Not a SOPS document: committed before the filter existed.
		cat "${src}" >"${dst}"
	fi
}

decrypt_version "${BASE}" "${WORK}/base" "the common ancestor's"
decrypt_version "${OURS}" "${WORK}/ours" "our"
decrypt_version "${THEIRS}" "${WORK}/theirs" "their"

# ── Three-way merge of the plaintext ────
# Exit status: 0 clean, 1..127 number of conflicts, anything else an error.
merge_status=0
git merge-file --marker-size="${MARKER_SIZE}" -L ours -L base -L theirs \
	"${WORK}/ours" "${WORK}/base" "${WORK}/theirs" || merge_status=$?
if [[ "${merge_status}" -gt 127 ]]; then
	fail "git merge-file failed on ${PATHNAME}"
fi

# ── A conflict the storage format cannot hold ────
# The merged text now has marker lines. In the dotenv format they are not
# KEY=VALUE lines and cannot be stored: keep OUR version (the file is
# left untouched) and report the conflict.
if [[ "${merge_status}" -ne 0 && "${STORE_FORMAT}" == "dotenv" ]]; then
	echo "sops merge driver: CONFLICT in ${PATHNAME}: both sides changed the same lines." >&2
	echo "  Conflict markers cannot be stored in the dotenv format, so OUR version was kept." >&2
	echo "  Take a side:  git checkout --theirs -- ${PATHNAME}   (or --ours)" >&2
	echo "  or merge by hand with git mergetool.  Then: git add ${PATHNAME}" >&2
	exit 1
fi

# ── Encrypt the result the way `git add` would ────
# clean-filter.sh reuses our stored blob when the merge changed nothing,
# and verifies what sops returns.
"${SCRIPT_DIR}/clean-filter.sh" "${PATHNAME}" <"${WORK}/ours" >"${WORK}/result" ||
	fail "could not encrypt the merged ${PATHNAME} (see the message above)"
cat "${WORK}/result" >"${OURS}"

if [[ "${merge_status}" -ne 0 ]]; then
	echo "sops merge driver: CONFLICT in ${PATHNAME}. The working copy has conflict markers, in plaintext." >&2
	echo "  Edit the file, then: git add ${PATHNAME}" >&2
	exit 1
fi
exit 0

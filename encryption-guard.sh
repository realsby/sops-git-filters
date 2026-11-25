#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Encryption Guard (pre-commit hook)                         ║
# ║                                                                  ║
# ║  Second line of defense behind the clean filter: blocks a        ║
# ║  commit while any file managed by the "sops" git filter is       ║
# ║  tracked in plaintext. Catches the cases the filter can't: a     ║
# ║  clone where the filters were never configured, a bypassed       ║
# ║  filter, or an index entry written before the filter existed.    ║
# ║                                                                  ║
# ║  What is checked: EVERY entry in the index whose filter          ║
# ║  attribute is "sops", not only the paths staged for this         ║
# ║  commit. A secret that was committed in plaintext long ago is    ║
# ║  reported until it is fixed. The attribute is read from the      ║
# ║  .gitattributes files in the index, the ones the commit          ║
# ║  carries, not from the working tree.                             ║
# ║                                                                  ║
# ║  How: each blob is read by object id and must be a completely    ║
# ║  encrypted SOPS document in the repository's storage format      ║
# ║  (lib.sh). A search for the string ENC[AES256_GCM is not         ║
# ║  enough: a plaintext file can mention it, a dotenv file can      ║
# ║  have one encrypted value next to plaintext ones, and a SOPS     ║
# ║  envelope can carry plaintext (its MAC is always ENC[...]).      ║
# ║                                                                  ║
# ║  The guard fails closed: if it cannot list the index, read the   ║
# ║  attributes or read a blob, the commit is blocked.               ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

# This script may be reached through a symlink
# (.git/hooks/pre-commit -> ../../utilities/sops-git-filters/encryption-guard.sh).
# Follow it, so lib.sh is found next to the real file.
SELF="${BASH_SOURCE[0]}"
while [[ -L "${SELF}" ]]; do
	SELF_DIR="$(CDPATH='' cd -P -- "$(dirname "${SELF}")" && pwd)"
	SELF="$(readlink "${SELF}")"
	[[ "${SELF}" == /* ]] || SELF="${SELF_DIR}/${SELF}"
done
SCRIPT_DIR="$(CDPATH='' cd -P -- "$(dirname "${SELF}")" && pwd)"

blocked() { # <headline> : print the banner; details follow from the caller
	echo "========================================================" >&2
	echo " COMMIT BLOCKED: $1" >&2
	echo "========================================================" >&2
	echo "" >&2
}

if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	blocked "the encryption guard is incomplete"
	echo " lib.sh is missing next to encryption-guard.sh (${SCRIPT_DIR})." >&2
	echo " Update or re-copy sops-git-filters." >&2
	exit 1
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

PROJECT_ROOT="$(git rev-parse --show-toplevel)"
STORE_FORMAT="$(sgf_store_format "${PROJECT_ROOT}")" || exit 1
OTHER_FORMAT="$(sgf_other_format "${STORE_FORMAT}")"

# ── Check the entries ────────────────────────────────────────────
# check_entries reads the lines of managed_entries (below) on stdin, one
# per SOPS-managed index entry, and fills INDEX_MODES, INDEX_OIDS and
# INDEX_PATHS with them. Exit status:
#   0 every SOPS-managed blob is an encrypted SOPS document
#   1 at least one is not (already reported)
#   2 the check itself could not be completed
INDEX_MODES=()
INDEX_OIDS=()
INDEX_PATHS=()
check_entries() {
	local i=0 line meta path status why managed=0
	local unencrypted="" unreadable="" other_format=""

	while IFS= read -r line; do
		meta="${line%%$'\t'*}"
		if ! unquote_path "${line#*$'\t'}"; then
			echo "encryption-guard: cannot read the name git printed for an index entry — cannot verify the index" >&2
			return 2
		fi
		path="${REPLY}"
		INDEX_MODES[i]="${meta%% *}"
		meta="${meta#* }"
		INDEX_OIDS[i]="${meta%% *}"
		INDEX_PATHS[i]="${path}"
		case "${INDEX_MODES[i]}" in
		120000 | 160000)
			# A symlink or a submodule: git never runs a filter on these.
			;;
		*)
			managed=$((managed + 1))
			status=0
			sgf_blob_is_sops_doc "${STORE_FORMAT}" "${INDEX_OIDS[i]}" "${PROJECT_ROOT}" || status=$?
			if [[ "${status}" -eq 1 ]] && left_out_of_commit "${i}"; then
				# Intent to add: not part of this commit, see below.
				managed=$((managed - 1))
				status=0
			fi
			case "${status}" in
			0) ;;
			2) unreadable="${unreadable}   - ${path}"$'\n' ;;
			*)
				# Encrypted, but in the format .sops-filter.conf does not
				# name: a storage-format change that is not finished.
				if sgf_blob_is_sops_doc "${OTHER_FORMAT}" "${INDEX_OIDS[i]}" "${PROJECT_ROOT}"; then
					other_format="${other_format}   - ${path}"$'\n'
				else
					# Why not: a line number or a key name, never a value.
					why="$(sgf_blob_problem "${STORE_FORMAT}" "${INDEX_OIDS[i]}" "${PROJECT_ROOT}")"
					unencrypted="${unencrypted}   - ${path}${why:+  (${why})}"$'\n'
				fi
				;;
			esac
			;;
		esac
		i=$((i + 1))
	done

	if [[ -n "${unreadable}" ]]; then
		blocked "cannot read SOPS-managed files from the index"
		printf '%s' "${unreadable}" >&2
		return 2
	fi

	if [[ -n "${unencrypted}" ]]; then
		blocked "SOPS-managed files are not encrypted"
		echo " These files have filter=sops in .gitattributes, but the version" >&2
		echo " in the index is not a completely encrypted SOPS document" >&2
		echo " (expected format: ${STORE_FORMAT}):" >&2
		echo "" >&2
		printf '%s' "${unencrypted}" >&2
		echo "" >&2
		echo " To fix:" >&2
		echo "   1. Configure the filters: run install.sh from this tool's directory." >&2
		echo "   2. Re-stage through the filter:  git add --renormalize -- <file>" >&2
		echo "   3. A file that was already committed like this is in history:" >&2
		echo "      rotate that secret." >&2
		echo " If the reason names a key that sops does not write and your sops is" >&2
		echo " newer than this tool, update sops-git-filters instead." >&2
		echo "========================================================" >&2
		return 1
	fi

	if [[ -n "${other_format}" ]]; then
		blocked "SOPS-managed files are stored in the other format"
		echo " .sops-filter.conf says ${STORE_FORMAT}, but the index holds these files" >&2
		echo " as ${OTHER_FORMAT} (encrypted, in the other format):" >&2
		echo "" >&2
		printf '%s' "${other_format}" >&2
		echo "" >&2
		echo " To finish the format change, re-run install.sh, then re-encrypt:" >&2
		echo "   SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize -- <files>" >&2
		echo "========================================================" >&2
		return 1
	fi

	# SOPS-managed files are tracked — encryption must be possible at all.
	if [[ "${managed}" -gt 0 && ! -f "${PROJECT_ROOT}/.sops.yaml" ]]; then
		blocked "SOPS not configured"
		echo " ${managed} tracked file(s) require SOPS encryption but" >&2
		echo " .sops.yaml is missing." >&2
		echo "" >&2
		echo " To fix:" >&2
		echo "   1. Create .sops.yaml with your encryption keys" >&2
		echo "   2. Run install.sh to configure the git filters" >&2
		echo "========================================================" >&2
		return 1
	fi
	return 0
}

# ── Entries this commit leaves out ───────────────────────────────
# `git add -N <file>` (intent to add) puts the path in the index with
# the empty blob, to show the file in `git diff`. That blob is no SOPS
# document, but it never reaches a commit: a plain `git commit` leaves
# the entry out, and `git commit -a` or `git commit -- <file>` stage the
# content, through the filter, before this hook runs. Blocking it would
# block every commit until the file is staged (audit A-05).
#
# left_out_of_commit <index position> succeeds only when the entry holds
# the empty blob AND is missing from the tree git builds from the index
# for the commit (`git write-tree`, which skips intent-to-add entries;
# it also writes that tree to the object store, as the commit will).
# There is no documented way to read the intent-to-add flag itself. Any
# answer it cannot get or does not expect counts as "in the commit", so
# the entry is checked as before: it fails closed. A path with a newline
# cannot be asked about on the one line `git cat-file --batch-check`
# reads, and is checked as before too.
COMMIT_TREE=""
left_out_of_commit() {
	local path="${INDEX_PATHS[$1]}" size answer
	[[ "${path}" != *$'\n'* ]] || return 1
	size="$(git -C "${PROJECT_ROOT}" cat-file -s "${INDEX_OIDS[$1]}" </dev/null 2>/dev/null)" || return 1
	[[ "${size}" == "0" ]] || return 1
	if [[ -z "${COMMIT_TREE}" ]]; then
		# Fails while a path is unmerged: then nothing is left out.
		COMMIT_TREE="$(git -C "${PROJECT_ROOT}" write-tree </dev/null 2>/dev/null)" || COMMIT_TREE=""
		[[ -n "${COMMIT_TREE}" ]] || return 1
	fi
	answer="$(printf '%s:%s\n' "${COMMIT_TREE}" "${path}" |
		git -C "${PROJECT_ROOT}" cat-file --batch-check 2>/dev/null)" || return 1
	[[ "${answer}" == "${COMMIT_TREE}:${path} missing" ]]
}

# ── Which entries are SOPS-managed ───────────────────────────────
# managed_entries prints one line per index entry whose filter attribute
# is "sops":  "<mode> <object id> <stage>" TAB <path>. Each stage of an
# unmerged path is an entry of its own. Blobs are later read by object
# id, so no path is ever turned into a revision (a file named like
# "2:prod.secret" would otherwise be read as index stage 2).
#
# Git lists the index (`git ls-files -s`) and answers for the attribute
# of every path in it (`git check-attr`); awk puts the two together, and
# only the managed entries reach bash. Reading every entry in bash took
# 8 seconds with 60,000 tracked files, on every commit; this takes 0.2
# (audit A-01). The text output is read, not the -z one: the awk of
# macOS ends a line at a NUL byte. In text, git prints a path as it is,
# or in double quotes with C-style escapes when it holds a control
# character, a double quote or a backslash (unquote_path below). The
# same path is printed the same way by both commands; core.quotepath=off
# leaves the bytes above 127 alone, in both.
#
# --cached: the attributes come from the .gitattributes files in the
# index, the ones this commit carries. Without it git reads the working
# tree, and a local edit that is not staged (".env -filter", left from
# debugging) would decide which blobs are checked. That same edit keeps
# `git add` from running the filter, so the plaintext it stages would
# pass unseen (audit A-11). For the same reason the list does not come
# from `git ls-files -- ':(attr:filter=sops)'`, one call that is faster
# still: that pathspec reads the attributes of the working tree.
#
# -C: from the top of the working tree. `git ls-files` lists only what
# is below the current directory, so a guard started in a subdirectory
# would pass over every secret outside it.
#
# The index is listed twice: once for the entries, once for check-attr.
# Answer number i must be about entry number i, and every entry must get
# one; anything else (an answer cut short, an index that changed in
# between) is an error. pipefail: a git command that fails fails the
# pipeline too.
managed_entries() {
	{
		git -C "${PROJECT_ROOT}" -c core.quotepath=off ls-files -s &&
			echo &&
			git -C "${PROJECT_ROOT}" -c core.quotepath=off ls-files -s |
			awk '{ print substr($0, index($0, "\t") + 1) }' |
				git -C "${PROJECT_ROOT}" -c core.quotepath=off check-attr --cached --stdin filter
	} | awk '
	# Up to the empty line: the entries. After it: one answer per entry,
	# "<path>: filter: <value>".
	BEGIN { listing = 1 }
	listing {
		if ($0 == "") {
			listing = 0
			next
		}
		tab = index($0, "\t")
		n++
		meta[n] = substr($0, 1, tab - 1)
		path[n] = substr($0, tab + 1)
		next
	}
	{
		i++
		head = path[i] ": filter: "
		if (i > n || substr($0, 1, length(head)) != head) {
			print "encryption-guard: git check-attr answered out of order — cannot verify the index" | "cat 1>&2"
			failed = 1
			exit
		}
		if (substr($0, length(head) + 1) == "sops") print meta[i] "\t" path[i]
	}
	END {
		if (failed) exit 2
		if (listing) {
			print "encryption-guard: the list of index entries was cut short — cannot verify the index" | "cat 1>&2"
			exit 2
		}
		if (i != n) {
			printf "encryption-guard: git check-attr answered for %d of %d index entries — cannot verify the index\n", i, n | "cat 1>&2"
			exit 2
		}
	}'
}

# unquote_path <path as managed_entries prints it>
# The path itself, in REPLY. Undoes the quoting of git (quote_c_style):
# a quoted path is in double quotes, with \a \b \t \n \v \f \r \" \\ and
# \ooo (three octal digits) for the bytes it escapes. Returns 1 for
# anything else, which git does not print.
unquote_path() {
	local rest="$1" out="" c
	if [[ "${rest}" != \"* ]]; then
		REPLY="${rest}"
		return 0
	fi
	[[ "${#rest}" -ge 2 && "${rest}" == *\" ]] || return 1
	rest="${rest:1:${#rest}-2}"
	while [[ -n "${rest}" ]]; do
		c="${rest:0:1}"
		if [[ "${c}" != "\\" ]]; then
			out="${out}${c}"
			rest="${rest:1}"
			continue
		fi
		c="${rest:1:1}"
		case "${c}" in
		a) out="${out}"$'\a' ;;
		b) out="${out}"$'\b' ;;
		t) out="${out}"$'\t' ;;
		n) out="${out}"$'\n' ;;
		v) out="${out}"$'\v' ;;
		f) out="${out}"$'\f' ;;
		r) out="${out}"$'\r' ;;
		'"' | "\\") out="${out}${c}" ;;
		[0-3])
			[[ "${rest:1:3}" == [0-3][0-7][0-7] ]] || return 1
			# shellcheck disable=SC2059  # the format is the escape itself
			printf -v c "\\${rest:1:3}"
			out="${out}${c}"
			rest="${rest:2}"
			;;
		*) return 1 ;;
		esac
		rest="${rest:2}"
	done
	REPLY="${out}"
}

# `|| status=$?` keeps errexit from ending the script before the
# message below. With pipefail, a failing listing fails the pipeline
# too, even when check_entries saw nothing wrong in the part it got.
status=0
managed_entries | check_entries || status=$?

case "${status}" in
0) exit 0 ;;
1) exit 1 ;;
*)
	blocked "the encryption guard could not finish its check"
	echo " The index could not be listed, or its attributes or blobs could" >&2
	echo " not be read (see above). Nothing was verified, so nothing is let through." >&2
	exit 1
	;;
esac

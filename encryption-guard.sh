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
# ║  carries, not from the working tree. Git also reads attribute    ║
# ║  files no commit carries ($GIT_DIR/info/attributes above all);   ║
# ║  the guard blocks while one of them could change the filter      ║
# ║  attribute of a path, and names the line.                        ║
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
# check_entries reads the lines of sgf_managed_entries (lib.sh) on stdin, one
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
		if ! sgf_unquote_path "${line#*$'\t'}"; then
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
		# attr.tree (git 2.42) and GIT_ATTR_SOURCE make git add read the
		# attributes from a tree, not from .gitattributes: where that tree
		# marks nothing, git add runs no filter, and step 2 changes nothing.
		if [[ -n "${GIT_ATTR_SOURCE:-}" ]] ||
			git -C "${PROJECT_ROOT}" config attr.tree >/dev/null 2>&1; then
			echo " attr.tree or GIT_ATTR_SOURCE is set: git add takes the attributes" >&2
			echo " from that tree, not from .gitattributes. Unset it before step 2." >&2
		fi
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

	# SOPS-managed files are tracked, so encryption must be possible at all.
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
# sgf_managed_entries (lib.sh) prints one line per index entry whose
# filter attribute is "sops", read from the .gitattributes files of the
# index: the ones this commit carries (audit A-11). One `git ls-files`
# and one `git check-attr` joined in awk, so only the managed entries
# reach bash (audit A-01). Every stage of an unmerged path is an entry.

# ── Attribute files that no commit carries ───────────────────────
# check-attr --cached replaces the .gitattributes of the working tree by
# those of the index, but git still reads three files outside the tree:
#
#   $GIT_DIR/info/attributes   above every .gitattributes
#   core.attributesFile        below them all (default
#                              ~/.config/git/attributes)
#   the system file            below them all ($(prefix)/etc/gitattributes)
#
# A line in info/attributes such as ".env -filter" wins over the
# "filter=sops" of the commit. `git add` then stages the plaintext, and
# the guard, which asks git, no longer counted .env as SOPS-managed: the
# plaintext reached the commit (audit A-11). The two lower files cannot
# override a .gitattributes with a line of their own, but a macro they
# define applies wherever its name is used: "[attr]binary -filter"
# reaches every path a .gitattributes marks "filter=sops binary".
#
# Git cannot be asked for the attributes without these files, so the
# guard reads them and blocks while one of them could change the filter
# attribute of a path:
#   - info/attributes: a line that sets filter to anything but "sops"
#     (filter, -filter, !filter, filter=lfs), sets a macro, or redefines
#     a macro of the root .gitattributes of the index;
#   - any of the three: a macro definition that sets filter to anything
#     but "sops", or sets another macro.
# A macro is a name an [attr] line defines, in these files or in the
# root .gitattributes (the only one git takes macros from). The built-in
# "binary" (-diff -merge -text) counts only once a file redefines it.
# Only a macro that is set expands: "-name", "!name" and "name=value"
# do not. Lines with none of this (`*.bin binary`, comments) pass. A
# quoted pattern with a blank in it is split like the attributes after
# it: a word of it can only add a false alarm, never hide an attribute.
#
# A file that exists but cannot be read fails the check. Git older than
# 2.42 cannot say where the system file is; it is not read then.
# attr.tree and GIT_ATTR_SOURCE need nothing here: check-attr --cached
# ignores them (check_entries names them when plaintext is staged).
#
# attribute_overrides prints "<file>:<line number>: <line>" for each
# such line. Exit status: 0 done (with output or not), 2 cannot tell.
attribute_overrides() {
	local info global system file
	local -a files=()

	info="$(git -C "${PROJECT_ROOT}" rev-parse --git-path info/attributes)" || return 2
	if ! global="$(git -C "${PROJECT_ROOT}" var GIT_ATTR_GLOBAL 2>/dev/null)"; then
		# git before 2.42: the same lookup, by hand.
		global="$(git -C "${PROJECT_ROOT}" config --type=path core.attributesFile 2>/dev/null)" || global=""
		if [[ -z "${global}" && -n "${XDG_CONFIG_HOME:-}" ]]; then
			global="${XDG_CONFIG_HOME}/git/attributes"
		elif [[ -z "${global}" && -n "${HOME:-}" ]]; then
			global="${HOME}/.config/git/attributes"
		fi
	fi
	# Prints nothing and fails under GIT_ATTR_NOSYSTEM, and before 2.42.
	system="$(git -C "${PROJECT_ROOT}" var GIT_ATTR_SYSTEM 2>/dev/null)" || system=""

	# awk takes the role of each file from an assignment before it. Every
	# path is made absolute, so none is taken for an assignment itself.
	for file in "system=${system}" "global=${global}" "info=${info}"; do
		[[ -n "${file#*=}" ]] || continue
		sgf_is_absolute "${file#*=}" || file="${file%%=*}=${PROJECT_ROOT}/${file#*=}"
		[[ -e "${file#*=}" ]] || continue
		if [[ -d "${file#*=}" || ! -r "${file#*=}" ]]; then
			echo "encryption-guard: cannot read ${file#*=}, an attributes file git reads too" >&2
			return 2
		fi
		files+=("role=${file%%=*}" "${file#*=}")
	done
	[[ "${#files[@]}" -gt 0 ]] || return 0

	# On stdin: the root .gitattributes of the index (a blob per stage
	# while it is unmerged), for the names of its macros.
	{
		git -C "${PROJECT_ROOT}" ls-files -s -- .gitattributes |
			awk -F '\t' '$2 == ".gitattributes" { split($1, m, " "); print m[2] }' |
			while IFS= read -r file; do
				git -C "${PROJECT_ROOT}" cat-file blob "${file}" </dev/null || exit 2
				echo
			done
	} | awk '
	{
		text = $0
		sub(/\r$/, "", text)
		gsub(/\r/, " ") # git counts a CR as a blank
		if (NF == 0 || substr($1, 1, 1) == "#") next
		n++
		src[n] = role
		file[n] = FILENAME
		num[n] = FNR
		line[n] = text
		first = 2
		if (substr($1, 1, 6) == "[attr]") {
			name = substr($1, 7)
			if (name == "") {
				name = $2
				first = 3
			}
			defines[n] = name
			macro[name] = 1
			if (role == "tree") tree_macro[name] = 1
		}
		for (i = first; i <= NF; i++) {
			t = $i
			c = substr(t, 1, 1)
			if (c == "-" || c == "!") t = substr(t, 2)
			eq = index(t, "=")
			key = eq ? substr(t, 1, eq - 1) : t
			if (key == "filter" && $i != "filter=sops") touches[n] = 1
			if (c != "-" && c != "!" && !eq) uses[n] = uses[n] " " key
		}
	}
	END {
		for (k = 1; k <= n; k++) {
			if (src[k] == "tree") continue
			if (src[k] != "info" && defines[k] == "") continue
			bad = touches[k]
			m = split(uses[k], used, " ")
			for (j = 1; j <= m; j++)
				if (used[j] in macro) bad = 1
			if (src[k] == "info" && defines[k] != "" && (defines[k] in tree_macro)) bad = 1
			if (bad) printf "%s:%d: %s\n", file[k], num[k], line[k]
		}
	}' role=tree - "${files[@]}" || return 2
}

# `|| status=$?` keeps errexit from ending the script before the
# message below. With pipefail, a failing listing fails the pipeline
# too, even when check_entries saw nothing wrong in the part it got.
status=0
overrides="$(attribute_overrides)" || status=$?
if [[ "${status}" -eq 0 && -n "${overrides}" ]]; then
	blocked "a local attributes file can change which files are encrypted"
	echo " These lines set the filter attribute, or a macro that can, in a file" >&2
	echo " that no commit carries:" >&2
	echo "" >&2
	printf '%s\n' "${overrides}" | sed 's/^/   /' >&2
	echo "" >&2
	echo " git add obeys them, and may stage a secret in plaintext, while the" >&2
	echo " guard checks the files the .gitattributes of the commit mark" >&2
	echo " filter=sops: it cannot verify what the commit will hold." >&2
	echo "" >&2
	echo " To fix: remove those lines; what a path needs belongs in .gitattributes," >&2
	echo " in a commit. Then re-stage the secrets: git add --renormalize -- <files>" >&2
	echo "========================================================" >&2
	exit 1
fi
if [[ "${status}" -eq 0 ]]; then
	sgf_managed_entries "${PROJECT_ROOT}" encryption-guard "cannot verify the index" |
		check_entries || status=$?
fi

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

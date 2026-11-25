#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Shared helpers for sops-git-filters                             ║
# ║                                                                  ║
# ║  Sourced by the other scripts (clean-filter.sh, smudge-filter.sh,║
# ║  install.sh, encryption-guard.sh, merge-driver.sh, rekey.sh,     ║
# ║  preflight.sh). It must sit next to them: copy it along when you ║
# ║  vendor the scripts. Nothing here runs on its own.               ║
# ║                                                                  ║
# ║  The main job of this file is one question, asked in three       ║
# ║  places: "is this blob a completely encrypted SOPS document?"    ║
# ║                                                                  ║
# ║    clean-filter.sh      checks what sops produced BEFORE it      ║
# ║                         hands it to git                          ║
# ║    encryption-guard.sh  checks every tracked blob at commit      ║
# ║    install.sh           reports blobs committed in plaintext     ║
# ║                                                                  ║
# ║  The answer comes from the structure of the document, not from   ║
# ║  a search for the string ENC[: a plaintext file can contain      ║
# ║  that string, and a SOPS envelope can carry plaintext.           ║
# ║                                                                  ║
# ║  Callers must run with LC_ALL=C (byte-wise pattern ranges).      ║
# ╚══════════════════════════════════════════════════════════════════╝

# The version of these scripts. install.sh records it next to the copy it
# installs under .git/, and that copy compares it with this line in the
# checkout to notice an update that was not installed yet (see
# sgf_warn_if_outdated). Keep it on one line, in exactly this form, and
# within the first 8 KiB of this file: it is read as text, never by
# running the file, and only that much of the file is read.
# shellcheck disable=SC2034  # read by install.sh
SGF_VERSION="3.1.0"

# Oldest sops this tool accepts. Up to 3.10.2, sops applies a creation
# rule's encrypted_regex / unencrypted_regex / encrypted_suffix /
# unencrypted_suffix to the single "data" key of the binary store, and
# when the rule does not select that key the whole file is stored in
# clear inside a SOPS envelope. 3.11.0 ignores those options for the
# binary store.
#
# The scripts call `sops encrypt` and `sops decrypt` with no file: sops
# reads stdin then (every version from this one on). Not with /dev/stdin
# as the file: on Windows sops is a Windows program, and Git Bash hands
# it that path as C:\proc\self\fd\0, which does not exist there.
# shellcheck disable=SC2034  # read by install.sh and clean-filter.sh
SGF_MIN_SOPS_VERSION="3.11.0"

# ── Storage format ────────────────────────────────────────────────
# sgf_store_format <repo root>
# Prints "json" (default) or "dotenv", read from SOPS_STORE_FORMAT in
# .sops-filter.conf. The file is parsed, never sourced. Returns 1 with
# a message for any other value.
sgf_store_format() {
	local root="$1" value=""
	if [[ -f "${root}/.sops-filter.conf" ]]; then
		# `|| true`: the file may hold no SOPS_STORE_FORMAT line at all
		# (only SOPS_FILE_MODE, say); grep then exits 1.
		value=$({ grep -E '^SOPS_STORE_FORMAT=' "${root}/.sops-filter.conf" || true; } |
			tail -1 | cut -d= -f2 | tr -d '[:space:]')
	fi
	[[ -n "${value}" ]] || value="json"
	case "${value}" in
	json | dotenv)
		printf '%s\n' "${value}"
		;;
	*)
		echo "ERROR: invalid SOPS_STORE_FORMAT '${value}' in .sops-filter.conf (expected: json or dotenv)" >&2
		return 1
		;;
	esac
}

# sgf_other_format <format> : the storage format that is NOT <format>
sgf_other_format() {
	case "$1" in
	json) printf 'dotenv\n' ;;
	*) printf 'json\n' ;;
	esac
}

# ── The SOPS-managed entries of the index ─────────────────────────
# sgf_ls_managed <repo root>
# Prints the index entries whose filter attribute is "sops", as
# `git ls-files -s -z` does: "<mode> <object id> <stage>" TAB <path> NUL,
# every stage of an unmerged path. One git call does the selection, the
# pathspec ":(attr:filter=sops)" (git >= 2.13), not a bash loop over
# every tracked path, which is slow in a large repository (audit A-01).
# The attribute is read as `git check-attr` reads it by default: from
# the .gitattributes files of the working tree, and from the index where
# the working tree has none. (encryption-guard.sh and rekey.sh read the
# index's only: sgf_managed_entries below.)
#
# The pathspec settings of the caller are dropped, in a subshell: with
# GIT_LITERAL_PATHSPECS=1, which `git --literal-pathspecs` exports, git
# would look for a file named like the pathspec and list nothing.
sgf_ls_managed() {
	(
		unset GIT_LITERAL_PATHSPECS GIT_GLOB_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_ICASE_PATHSPECS
		git -C "$1" ls-files -s -z -- ':(attr:filter=sops)'
	)
}

# ── The SOPS-managed entries of the index, by its own attributes ──
# sgf_managed_entries <repo root> <who> <what a failure means> [<pathspec>...]
# Prints one line per index entry whose filter attribute is "sops":
# "<mode> <object id> <stage>" TAB <path>. Each stage of an unmerged path
# is an entry of its own. Blobs are later read by object id, so no path
# is ever turned into a revision (a file named like "2:prod.secret" would
# otherwise be read as index stage 2). With pathspecs, the entries they
# match (as `git ls-files -- <pathspec>`, from the top of the working
# tree). Used by encryption-guard.sh and rekey.sh.
#
# Git lists the index (`git ls-files -s`) and answers for the attribute
# of every path in it (`git check-attr`); awk puts the two together, and
# only the managed entries reach bash. Reading every entry in bash took
# 8 seconds with 60,000 tracked files, on every commit; this takes 0.2
# (audit A-01). The text output is read, not the -z one: the awk of
# macOS ends a line at a NUL byte. In text, git prints a path as it is,
# or in double quotes with C-style escapes when it holds a control
# character, a double quote or a backslash (sgf_unquote_path below). The
# same path is printed the same way by both commands; core.quotepath=off
# leaves the bytes above 127 alone, in both.
#
# --cached: the attributes come from the .gitattributes files in the
# index, the ones the next commit carries. Without it git reads the
# working tree, and a local edit that is not staged (".env -filter", left
# from debugging) would decide which blobs are checked. That same edit
# keeps `git add` from running the filter, so the plaintext it stages
# would pass unseen (audit A-11). For the same reason the list does not
# come from `git ls-files -- ':(attr:filter=sops)'` (sgf_ls_managed), one
# call that is faster still: that pathspec reads the attributes of the
# working tree.
#
# -C: from the top of the working tree. `git ls-files` lists only what
# is below the current directory, so a guard started in a subdirectory
# would pass over every secret outside it.
#
# The index is listed twice: once for the entries, once for check-attr.
# Answer number i must be about entry number i, and every entry must get
# one; anything else (an answer cut short, an index that changed in
# between) is an error: "<who>: ... — <what a failure means>" on stderr,
# and exit status 2. pipefail: a git command that fails fails the
# pipeline too.
sgf_managed_entries() {
	local root="$1" who="$2" means="$3"
	shift 3
	{
		git -C "${root}" -c core.quotepath=off ls-files -s -- "$@" &&
			echo &&
			git -C "${root}" -c core.quotepath=off ls-files -s -- "$@" |
			awk '{ print substr($0, index($0, "\t") + 1) }' |
				git -C "${root}" -c core.quotepath=off check-attr --cached --stdin filter
	} | awk -v who="${who}" -v means="${means}" '
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
			print who ": git check-attr answered out of order — " means | "cat 1>&2"
			failed = 1
			exit
		}
		if (substr($0, length(head) + 1) == "sops") print meta[i] "\t" path[i]
	}
	END {
		if (failed) exit 2
		if (listing) {
			print who ": the list of index entries was cut short — " means | "cat 1>&2"
			exit 2
		}
		if (i != n) {
			printf "%s: git check-attr answered for %d of %d index entries — %s\n", who, i, n, means | "cat 1>&2"
			exit 2
		}
	}'
}

# sgf_unquote_path <path as sgf_managed_entries prints it>
# The path itself, in REPLY. Undoes the quoting of git (quote_c_style):
# a quoted path is in double quotes, with \a \b \t \n \v \f \r \" \\ and
# \ooo (three octal digits) for the bytes it escapes. Returns 1 for
# anything else, which git does not print.
sgf_unquote_path() {
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

# ── Paths in the commands a message prints ────────────────────────
# A message that tells the user what to run gives the full path in single
# quotes, so the line can be pasted as it is, from any directory of the
# working tree, whatever characters the name holds.
#
# sgf_paste_path <absolute path> : the path, quoted for a shell. For
# what takes a file name: rm, a redirection.
#
# Each ' becomes '\'' (close the quotes, a quoted ', open them again).
# Done in bash, not in a $(... | sed): a command substitution drops the
# newlines at the end, and they are part of a name: for ".env.prod" with
# a newline at its end, `rm '<top>/.env.prod'` would remove another file.
# The pattern and the replacement are unquoted variables: bash 3.2 keeps
# the quotes of "$q" in the result of "${1//"$q"/"$r"}", and bash 5.2
# reads an unquoted & in the replacement as the match (there is none).
sgf_paste_path() {
	local q="'" r="'\\''"
	printf "'%s'" "${1//$q/$r}"
}

# sgf_paste_pathspec <absolute path> : the same, for a git command that
# takes a pathspec (git add, git checkout --). Git reads a pathspec as a
# pattern: "[ab].env" names a.env too, and `git checkout -- '[ab].env'`
# would throw away the edits in a.env. A path with a character that git
# treats as a wildcard (* ? [ \) gets the :(literal) magic; any other
# stays as it is, easier to read.
sgf_paste_pathspec() {
	case "$1" in
	*[\*\?\[\\]*) sgf_paste_path ":(literal)$1" ;;
	*) sgf_paste_path "$1" ;;
	esac
}

# ── A path that leads through a symlink ───────────────────────────
# sgf_through_symlink <repo root> <path>
# True when <path>, relative to <repo root> as git lists it (no "." or
# ".." parts), is a symlink itself or lies below a directory that is
# one. Git does not follow such a path: it lists the entry as deleted or
# as a type change and writes nothing there. A script that writes to
# "<root>/<path>" would follow it, to wherever the link leads, out of the
# working tree too (audit A-06, A-14). Only the parts below <repo root>
# are looked at: the root itself may be reached any way. Builtins only,
# one lstat per part. harden-permissions.sh has a copy of it: it runs
# without this file.
sgf_through_symlink() {
	local dir="$1" rest="$2"
	while [[ "${rest}" == */* ]]; do
		dir="${dir}/${rest%%/*}"
		rest="${rest#*/}"
		[[ ! -L "${dir}" ]] || return 0
	done
	[[ -L "${dir}/${rest}" ]]
}

# ── One encrypted value ───────────────────────────────────────────
# An awk function shared by the two document checks below. True when
# the string is exactly one SOPS ciphertext value, as aes/cipher.go of
# sops writes it (the same from 3.5.0 to 3.13.3):
#
#   ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<type>]
#
#   data   the ciphertext, as long as the value: padded base64 (Go's
#          StdEncoding), at least one byte. sops writes no ENC[...] for
#          an empty value (it writes "" instead), and its own parser
#          wants at least one character there.
#   iv     the nonce, 32 bytes: 43 characters and "=" (44)
#   tag    the GCM tag, 16 bytes: 22 characters and "==" (24)
#   type   one that sops can decrypt: str int float bool bytes time
#          comment (str for a value and the MAC, comment for a dotenv
#          comment; time came with 3.10)
#
# The whole string is matched: the fields in that order, nothing before
# or after them (audit A-16). That narrows what a hand-made value can
# carry, but cannot rule it out: a short password made of base64
# characters is valid base64. Only `sops decrypt` checks the MAC.
#
# No interval expressions ({43}): not every awk has them (old mawk).
# The lengths are counted with length() instead.
#
# The checks are written in awk, not in bash, for speed: bash pattern
# matching on a whole document takes time quadratic in its length (a
# few hundred kilobytes took minutes), awk reads it once.
SGF_AWK_IS_TOKEN='
function is_b64(s) {
	return length(s) % 4 == 0 && s ~ "^[A-Za-z0-9+/]*=?=?$"
}
function is_token(s,    f) {
	if (substr(s, 1, 20) != "ENC[AES256_GCM,data:" || substr(s, length(s), 1) != "]") return 0
	# base64 has no comma: the four fields split cleanly
	if (split(substr(s, 21, length(s) - 21), f, ",") != 4) return 0
	return f[1] != "" && is_b64(f[1]) &&
	    length(f[2]) == 47 && substr(f[2], 1, 3) == "iv:" && substr(f[2], 4) ~ "^[A-Za-z0-9+/]*=$" &&
	    length(f[3]) == 28 && substr(f[3], 1, 4) == "tag:" && substr(f[3], 5) ~ "^[A-Za-z0-9+/]*==$" &&
	    f[4] ~ "^type:(str|int|float|bool|bytes|time|comment)$"
}
'

# ── The metadata sops writes ──────────────────────────────────────
# A document is accepted only when its metadata holds nothing but the
# names sops itself writes. Anything else next to them could be a
# secret in clear, and both the guard and the clean filter (which tells
# a working copy that holds ciphertext from plaintext with it) rely on
# this check.
#
# The names come from stores/stores.go of sops. No release from 3.5.0 to
# 3.13.3 writes a name that is not listed here, so documents written
# long ago are accepted too (age came with 3.7, mac_only_encrypted and
# the comment regexes with 3.9, hckms with 3.12). They were compared
# with real output of 3.9.1, 3.10.2, 3.11.0, 3.12.1 and 3.13.3 for age,
# AWS KMS, key groups and partial-encryption rules:
#
#   meta_scalar   plain values of the "sops" object
#   meta_keytype  its lists of key entries, also inside key_groups
#   meta_entry    the fields of one key entry, per kind of key
#
# Only names and nesting are checked, not what the fields hold. Some
# hold free text by design: an encrypted_regex, or "context" of a kms
# entry (the AWS encryption context, a map of names the user chose).
#
# A sops release that adds a metadata name needs that name added here.
# Until then its documents are refused (never let through), and
# sgf_doc_problem names the key.
SGF_AWK_META='
function meta_scalar(k) {
	return k ~ /^(lastmodified|mac|version|unencrypted_suffix|encrypted_suffix|unencrypted_regex|encrypted_regex|unencrypted_comment_regex|encrypted_comment_regex|mac_only_encrypted|shamir_threshold)$/
}
function meta_keytype(k) {
	return k ~ /^(kms|gcp_kms|hckms|azure_kv|hc_vault|age|pgp)$/
}
function meta_entry(type, k) {
	return (type ":" k) ~ /^(kms:(arn|role|context|created_at|enc|aws_profile)|gcp_kms:(resource_id|created_at|enc)|hckms:(key_id|created_at|enc)|azure_kv:(vault_url|name|version|created_at|enc)|hc_vault:(vault_address|engine_path|key_name|created_at|enc)|age:(recipient|enc)|pgp:(created_at|enc|fp))$/
}
# The key one entry names, from its fields in F: what sops shows for it.
# A recipient, an ARN, a key URL: public by design, never a secret.
function key_name(type) {
	if (type == "age") return F["recipient"]
	if (type == "kms") return F["arn"]
	if (type == "gcp_kms") return F["resource_id"]
	if (type == "azure_kv") return F["vault_url"] "/keys/" F["name"]
	if (type == "hc_vault") return F["vault_address"] "/v1/" F["engine_path"] "/keys/" F["key_name"]
	if (type == "pgp") return F["fp"]
	if (type == "hckms") return F["key_id"]
	return ""
}
# One line per key entry: <group> TAB <type> <name>. Group 1 is the first
# key group; a document without key_groups has that one group only. The
# name is cut short and shown in printable ASCII only: a document from
# someone else can hold anything there.
function print_key(group, type,    name) {
	name = key_name(type)
	gsub(/[^ -~]/, "?", name)
	if (length(name) > 200) name = substr(name, 1, 200) "..."
	print group "\t" type " " name
}
# A key name is repeated in a message only when it looks like a name.
function shown(k) {
	return (k ~ /^[A-Za-z0-9_]+$/ && length(k) <= 40) ? ": " k : ""
}
'

# ── json store ────────────────────────────────────────────────────
# The awk program behind sgf_json_envelope_kind. It accepts the document
# the clean filter stores in json mode and nothing else:
#
#   { "data": "<one ENC[...] value, or empty>", "sops": { <metadata> } }
#
# The WHOLE document is checked, token by token, with the nesting kept
# on a stack: "data" must be the first key, "sops" the second and the
# last, and inside "sops" every key at every level must be one sops
# writes (see above), "mac" must be an encrypted value and "version"
# must be there. So {"data":"","sops":{},"x":{"password":"..."}} is not
# a SOPS document, and neither is one with an extra key in "sops".
#
# How it stays fast: a line is cut at its double quotes with one
# split(), so string contents (the megabytes of "data") are never
# walked character by character; only the few characters between
# strings are. A JSON string cannot hold a raw newline, so no string
# spans two lines.
#
# With -v explain=1 it prints the reason for a refusal (a few words,
# no content of the document) instead of the kind.
# shellcheck disable=SC2016  # $0 and friends belong to awk
SGF_AWK_JSON='
function fail(msg) { if (!failed) { failed = 1; why = msg } }

# The stack. Kinds: doc, meta, list (of key entries), entry, ctx (the kms
# encryption context), groups (key_groups), group. A list and its entries
# also carry the kind of key they hold (kms, age, ...). States of an
# object: k0 key or end, k key, c colon, v value, e comma or end. Of a
# list: v0 value or end, v value, e comma or end.
function push(kind, st, type) { depth++; K[depth] = kind; St[depth] = st; Type[depth] = type; Fid[depth] = ++fid }
function pop() {
	depth--
	if (depth == 0) done = 1
	else St[depth] = "e"
}
function is_obj(kind) { return kind != "list" && kind != "groups" }
function ready() {
	if (done) { fail("text after the end of the document"); return 0 }
	if (depth == 0) { fail("it does not start with {"); return 0 }
	return 1
}

function on_key(s,    kind) {
	kind = K[depth]
	if (seen[Fid[depth], s]++) { fail("a key appears twice" shown(s)); return }
	if (kind == "doc") {
		ndoc++
		if (ndoc == 1 && s != "data") { fail("the first key is not \"data\""); return }
		if (ndoc == 2 && s != "sops") { fail("the second key is not \"sops\""); return }
		if (ndoc > 2) { fail("a key after \"sops\"" shown(s)); return }
	} else if (kind == "meta") {
		if (!meta_scalar(s) && !meta_keytype(s) && s != "key_groups") { fail("a key in the sops metadata that sops does not write" shown(s)); return }
	} else if (kind == "group") {
		if (!meta_keytype(s)) { fail("a key in a key group that sops does not write" shown(s)); return }
	} else if (kind == "entry") {
		if (!meta_entry(Type[depth], s)) { fail("a field in a key entry that sops does not write" shown(s)); return }
	}
	Key[depth] = s
	St[depth] = "c"
}

function on_string(s,    kind, st, k) {
	if (!ready()) return
	kind = K[depth]; st = St[depth]
	if (!is_obj(kind)) { fail("a string where a key entry belongs"); return }
	if (st == "k0" || st == "k") { on_key(s); return }
	if (st != "v") { fail("it is not valid JSON"); return }
	k = Key[depth]
	if (kind == "doc") {
		if (k != "data") { fail("\"sops\" is not an object"); return }
		if (s == "") datakind = "empty"
		else if (is_token(s)) datakind = "enc"
		else { fail("\"data\" is not encrypted"); return }
	} else if (kind == "meta") {
		if (!meta_scalar(k)) { fail("a string where a list belongs" shown(k)); return }
		if (k == "mac") {
			if (!is_token(s)) { fail("\"mac\" is not an encrypted value"); return }
			mac = 1
		}
		if (k == "version" && s != "") ver = 1
	} else if (kind == "group") {
		fail("a string where a list belongs" shown(k)); return
	} else if (kind == "entry" && k == "context") {
		fail("\"context\" is not an object"); return
	} else if (kind == "entry" && keys) {
		F[k] = s
	}
	St[depth] = "e"
}

# A number, true, false or null.
function on_scalar(t,    kind, k) {
	if (!ready()) return
	kind = K[depth]
	if (!is_obj(kind)) { fail("a value where a key entry belongs"); return }
	if (St[depth] != "v") { fail("it is not valid JSON"); return }
	k = Key[depth]
	if (kind == "doc") { fail(k == "data" ? "\"data\" is not a string" : "\"sops\" is not an object"); return }
	if (t != "null") {
		if (kind == "group" || (kind == "entry" && k == "context") ||
		    (kind == "meta" && k != "mac_only_encrypted" && k != "shamir_threshold")) {
			fail("a value of the wrong kind" shown(k)); return
		}
	}
	St[depth] = "e"
}

function on_open(c,    kind, st, k) {
	if (done) { fail("text after the end of the document"); return }
	if (depth == 0) {
		if (c == "{") push("doc", "k0", "")
		else fail("it does not start with {")
		return
	}
	kind = K[depth]; st = St[depth]
	if (is_obj(kind)) {
		if (st != "v") { fail("it is not valid JSON"); return }
		k = Key[depth]
		if (c == "{" && kind == "doc" && k == "sops") push("meta", "k0", "")
		else if (c == "{" && kind == "entry" && k == "context") push("ctx", "k0", "")
		else if (c == "[" && kind == "meta" && meta_keytype(k)) push("list", "v0", k)
		else if (c == "[" && kind == "meta" && k == "key_groups") push("groups", "v0", "")
		else if (c == "[" && kind == "group") push("list", "v0", k)
		else fail("an object or a list where sops writes none" shown(k))
		return
	}
	if (st != "v0" && st != "v") { fail("it is not valid JSON"); return }
	if (c == "{" && kind == "list") {
		group = K[depth - 1] == "group" ? ngroups : 1
		split("", F)
		push("entry", "k0", Type[depth])
	} else if (c == "{" && kind == "groups") { ngroups++; push("group", "k0", "") }
	else fail("a list inside a list")
}

function on_close(c,    kind, st) {
	if (!ready()) return
	kind = K[depth]; st = St[depth]
	if (c == "}") {
		if (!is_obj(kind) || (st != "k0" && st != "e")) { fail("it is not valid JSON"); return }
		if (kind == "doc" && ndoc != 2) { fail("\"data\" and \"sops\" are not both there"); return }
		if (kind == "entry" && keys) print_key(group, Type[depth])
	} else if (is_obj(kind) || (st != "v0" && st != "e")) {
		fail("it is not valid JSON"); return
	}
	pop()
}

function on_colon() {
	if (!ready()) return
	if (!is_obj(K[depth]) || St[depth] != "c") { fail("it is not valid JSON"); return }
	St[depth] = "v"
}

function on_comma() {
	if (!ready()) return
	if (St[depth] != "e") { fail("it is not valid JSON"); return }
	St[depth] = is_obj(K[depth]) ? "k" : "v"
}

# What stands between two strings: brackets, colons, commas, a number,
# true, false or null. Never long in a document sops wrote.
function outside(s,    c) {
	if (length(s) > 1000) { fail("it is not a SOPS document"); return }
	while (s != "" && !failed) {
		c = substr(s, 1, 1)
		if (c == " " || c == "\t" || c == "\r") { s = substr(s, 2); continue }
		if (c == "{" || c == "[") on_open(c)
		else if (c == "}" || c == "]") on_close(c)
		else if (c == ":") on_colon()
		else if (c == ",") on_comma()
		else if (match(s, /^-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?/)) {
			on_scalar("number")
			s = substr(s, RLENGTH + 1)
			continue
		} else if (match(s, /^(true|false|null)/)) {
			on_scalar(substr(s, 1, RLENGTH))
			s = substr(s, RLENGTH + 1)
			continue
		} else { fail(depth == 0 && !done ? "it does not start with {" : "it is not valid JSON"); return }
		s = substr(s, 2)
	}
}

# True when s ends in an odd number of backslashes: the double quote
# that followed it in the line was escaped and belongs to the string.
function open_ended(s,    n, k) {
	n = length(s)
	k = 0
	while (n > 0 && substr(s, n, 1) == "\\") { k++; n-- }
	return k % 2
}

failed { next }
# A quick look before a line is cut up: until "data" has been seen, the
# document can only go on with {, with "data", or with nothing. Plain
# text and other JSON are turned away here, at their first line, however
# long that line is.
depth == 0 && !done && $0 !~ /^[ \t\r]*($|\{[ \t\r]*($|"data"))/ {
	fail("it does not start with { and \"data\"")
	next
}
depth == 1 && ndoc == 0 && $0 !~ /^[ \t\r]*($|"data")/ {
	fail("the first key is not \"data\"")
	next
}
{
	n = split($0, part, "\"")
	instr = 0
	for (i = 1; i <= n && !failed; i++) {
		if (!instr) {
			outside(part[i])
			if (i < n) { instr = 1; more = 0 }
			continue
		}
		str = more ? str "\"" part[i] : part[i]
		if (i == n) { fail("it is not valid JSON"); break }
		if (open_ended(part[i])) { more = 1; continue }
		on_string(str)
		instr = 0
	}
}
END {
	if (!failed && !done) fail("it is not a complete JSON document")
	if (!failed && !mac) fail("the sops metadata has no \"mac\"")
	if (!failed && !ver) fail("the sops metadata has no \"version\"")
	if (failed) {
		if (explain) print why
		exit 1
	}
	if (!explain && !keys) print datakind
}
'

# sgf_json_envelope_kind   (document on stdin)
# Succeeds for a json-format SOPS document (see SGF_AWK_JSON). Prints
# "enc" when "data" holds ciphertext and "empty" when it is the empty
# string, which is what sops writes for an empty file.
#
# The whole input is read even when the answer is known after the
# first line, so the writer never gets a broken pipe.
sgf_json_envelope_kind() {
	awk "${SGF_AWK_IS_TOKEN}${SGF_AWK_META}${SGF_AWK_JSON}"
}

# ── dotenv store ──────────────────────────────────────────────────
# The awk program behind sgf_is_sops_dotenv. True when every line is
# one of
#   KEY=<one ENC[...] value>      KEY=            (empty value)
#   #<one ENC[...] value>         #               (empty comment)
#   sops_<metadata>=<anything>    (blank line)
# and the metadata carries sops_mac (an encrypted value) and
# sops_version. A value or a comment left in clear makes it false.
#
# sops_<metadata> is not "any key that starts with sops_": only the
# names sops writes (see SGF_AWK_META) in the flat form the dotenv
# store gives them, such as
#   sops_lastmodified          sops_age__list_0__map_recipient
#   sops_kms__list_0__map_context__map_<name>
#   sops_key_groups__list_1__map_age__list_0__map_enc
# Any other sops_ key is an ordinary key: its value must be encrypted.
# shellcheck disable=SC2016  # $0 and friends belong to awk
SGF_AWK_DOTENV='
function is_meta_line(key,    r, p, type, field) {
	if (substr(key, 1, 5) != "sops_") return 0
	r = substr(key, 6)
	if (meta_scalar(r)) return 1
	sub(/^key_groups__list_[0-9]+__map_/, "", r)
	p = index(r, "__list_")
	if (p == 0) return 0
	type = substr(r, 1, p - 1)
	r = substr(r, p + 7)
	if (!meta_keytype(type) || !match(r, /^[0-9]+__map_/)) return 0
	field = substr(r, RLENGTH + 1)
	if (substr(field, 1, 13) == "context__map_") return type == "kms" && length(field) > 13
	return field != "context" && meta_entry(type, field)
}
function fail(msg) { if (!bad) { bad = 1; why = "line " NR ": " msg } }
{
	sub(/\r$/, "")
	if ($0 == "" || $0 == "#") next
	if (substr($0, 1, 1) == "#") {
		if (!is_token(substr($0, 2))) fail("a comment that is not encrypted")
		next
	}
	eq = index($0, "=")
	if (eq == 0) { fail("neither a comment nor KEY=VALUE"); next }
	key = substr($0, 1, eq - 1)
	val = substr($0, eq + 1)
	if (is_meta_line(key)) {
		if (key == "sops_mac") {
			if (is_token(val)) mac = 1
			else fail("sops_mac is not an encrypted value")
		}
		if (key == "sops_version" && val != "") ver = 1
		next
	}
	if (val != "" && !is_token(val)) {
		if (substr(key, 1, 5) == "sops_") fail("a sops_ key that sops does not write, with a value in clear")
		else fail("a value that is not encrypted")
	}
}
END {
	if (!bad && !mac) { bad = 1; why = "there is no sops_mac line" }
	if (!bad && !ver) { bad = 1; why = "there is no sops_version line" }
	if (bad) {
		if (explain) print why
		exit 1
	}
}
'

# The keys of a dotenv-format document (sgf_doc_keys): the sops_ lines of
# key entries, such as
#   sops_age__list_0__map_recipient=age1...
#   sops_key_groups__list_1__map_kms__list_0__map_arn=arn:aws:kms:...
# shellcheck disable=SC2016  # $0 and friends belong to awk
SGF_AWK_DOTENV_KEYS='
{ sub(/\r$/, "") }
substr($0, 1, 5) == "sops_" && (eq = index($0, "=")) {
	r = substr($0, 6, eq - 6)
	g = 1
	if (match(r, /^key_groups__list_[0-9]+__map_/)) {
		g = substr(r, 18, RLENGTH - 23) + 1
		r = substr(r, RLENGTH + 1)
	}
	p = index(r, "__list_")
	if (p == 0) next
	type = substr(r, 1, p - 1)
	r = substr(r, p + 7)
	if (!meta_keytype(type) || !match(r, /^[0-9]+__map_/)) next
	id = g SUBSEP type SUBSEP substr(r, 1, RLENGTH - 6)
	if (!(id in seen)) { seen[id] = 1; order[++n] = id }
	V[id, substr(r, RLENGTH + 1)] = substr($0, eq + 1)
}
END {
	nf = split("recipient arn resource_id vault_url name vault_address engine_path key_name fp key_id", field, " ")
	for (i = 1; i <= n; i++) {
		split(order[i], part, SUBSEP)
		split("", F)
		for (j = 1; j <= nf; j++) F[field[j]] = V[order[i], field[j]]
		print_key(part[1], part[2])
	}
}
'

# sgf_is_sops_dotenv   (document on stdin)
sgf_is_sops_dotenv() {
	awk "${SGF_AWK_IS_TOKEN}${SGF_AWK_META}${SGF_AWK_DOTENV}"
}

# sgf_doc_problem <format>   (document on stdin)
# Says in a few words why the document is not a completely encrypted
# SOPS document in that format: a line number or a key name, never a
# value. Prints nothing for a document that is one.
sgf_doc_problem() {
	case "$1" in
	json) awk -v explain=1 "${SGF_AWK_IS_TOKEN}${SGF_AWK_META}${SGF_AWK_JSON}" || true ;;
	dotenv) awk -v explain=1 "${SGF_AWK_IS_TOKEN}${SGF_AWK_META}${SGF_AWK_DOTENV}" || true ;;
	esac
}

# sgf_dotenv_input_problem   (plaintext on stdin)
# Checks a plaintext dotenv file BEFORE sops sees it. The sops dotenv
# parser works line by line and takes everything left of the first "="
# as a key, which it stores in clear. So a quoted value that continues
# on the next lines turns those lines into plaintext keys, and a line
# without "=" makes sops fail with an error that prints the line.
#
# Accepted: empty lines, lines starting with "#", and KEY=VALUE where
# KEY (after an optional "export ") is made of A-Z a-z 0-9 _ . - and
# VALUE does not open a quote it leaves unclosed.
#
# Prints the reason for the first bad line and returns 1. The message
# holds the line number only, never the content.
sgf_dotenv_input_problem() {
	awk '
	{
		line = $0
		sub(/\r$/, "", line)
		if (line == "" || substr(line, 1, 1) == "#") next
		eq = index(line, "=")
		if (eq == 0) {
			print "line " NR " is neither a comment nor KEY=VALUE"
			exit 1
		}
		key = substr(line, 1, eq - 1)
		val = substr(line, eq + 1)
		sub(/^[ \t]*/, "", key)
		sub(/^export[ \t]+/, "", key)
		sub(/[ \t]+$/, "", key)
		if (key !~ /^[A-Za-z_][A-Za-z0-9_.-]*$/) {
			print "line " NR ": the key has characters outside A-Z a-z 0-9 _ . -"
			exit 1
		}
		quote = substr(val, 1, 1)
		if ((quote == "\"" || quote == "\047") && index(substr(val, 2), quote) == 0) {
			print "line " NR ": the value opens a quote that is not closed on that line (multi-line values cannot be stored in the dotenv format)"
			exit 1
		}
	}
	'
}

# ── Either store ──────────────────────────────────────────────────
# sgf_is_sops_doc <format> <document>
# For the json format the kind of the "data" value ("enc" or "empty")
# is left in SGF_DATA_KIND.
SGF_DATA_KIND=""
sgf_is_sops_doc() {
	SGF_DATA_KIND=""
	case "$1" in
	json) SGF_DATA_KIND="$(printf '%s' "$2" | sgf_json_envelope_kind)" ;;
	dotenv) printf '%s' "$2" | sgf_is_sops_dotenv ;;
	*) return 1 ;;
	esac
}

# sgf_blob_is_sops_doc <format> <object id> [git -C dir]
# Checks a blob straight from the object store. Returns 2 when the blob
# cannot be read, 1 when it is not a SOPS document.
#
# A blob with a NUL byte is never one (audit A-12). sops writes none,
# and the clean filter refuses content that has any. Above all, the awk
# of macOS ends a line at a NUL byte and never looks at the rest of it:
# a complete SOPS document followed by "\0DB_PASSWORD=hunter2" would
# pass the document check there. So the NUL bytes are counted, in the
# same single read of the blob: tee hands it to the document check
# (fd 3) and to tr, which keeps the NUL bytes only, and wc counts them.
# The verdict is "doc" from the check and the count from wc, in either
# order; anything else (a read that failed, a check that failed, a count
# that is not 0) is "not a SOPS document".
sgf_blob_is_sops_doc() {
	local format="$1" oid="$2" dir="${3:-.}" verdict
	git -C "${dir}" cat-file -e "${oid}" 2>/dev/null || return 2
	case "${format}" in
	json | dotenv) ;;
	*) return 1 ;;
	esac
	verdict="$(
		{
			{
				git -C "${dir}" cat-file blob "${oid}" | tee /dev/fd/3 | tr -cd '\000' | wc -c >&4
			} 3>&1 | sgf_doc_check "${format}" >/dev/null && echo doc
		} 4>&1
	)" || return 1
	case "${verdict//[[:space:]]/}" in
	0doc | doc0) return 0 ;;
	*) return 1 ;;
	esac
}

# sgf_doc_check <format>   (document on stdin)
# sgf_json_envelope_kind or sgf_is_sops_dotenv, by format.
sgf_doc_check() {
	case "$1" in
	json) sgf_json_envelope_kind ;;
	dotenv) sgf_is_sops_dotenv ;;
	*) cat >/dev/null && return 1 ;;
	esac
}

# sgf_blob_problem <format> <object id> [git -C dir]
# sgf_doc_problem for a blob in the object store. A blob with NUL bytes
# is named as such: the document check cannot be trusted with one (see
# sgf_blob_is_sops_doc). Only called for a blob that failed that check,
# so reading it twice costs nothing on the common path.
sgf_blob_problem() {
	local nuls
	nuls="$(git -C "${3:-.}" cat-file blob "$2" 2>/dev/null | tr -cd '\000' | wc -c)" || nuls=""
	nuls="${nuls//[!0-9]/}"
	if [[ -n "${nuls}" && "${nuls}" != "0" ]]; then
		echo "it holds NUL bytes (${nuls}), which a SOPS document never has"
		return 0
	fi
	git -C "${3:-.}" cat-file blob "$2" 2>/dev/null | sgf_doc_problem "$1"
}

# ── Content with NUL bytes ────────────────────────────────────────
# The scripts hold file content in shell variables, and a shell variable
# cannot hold a NUL byte: bash drops it (4.4 and later print a warning,
# 3.2 says nothing). A keystore, a DER certificate or a UTF-16 text file
# would be stored damaged, with exit status 0. So content is counted on
# its way into the variable, and the caller refuses it when the count
# is not 0.
#
# sgf_cat_counting_nuls   (content on stdin)
# Copies stdin to stdout and then prints "x<number of NUL bytes>". One
# pass: tee hands every chunk to the capture (fd 3) and to tr, which
# keeps the NUL bytes only; wc counts them. The count is printed when tr
# has seen the end of the input, so it always follows the content. Use:
#
#   SGF_CAPTURED="$(sgf_cat_counting_nuls)" || ...   then   sgf_split_counted
sgf_cat_counting_nuls() {
	{
		tee /dev/fd/3 | {
			nuls="$(tr -cd '\000' | wc -c)"
			printf 'x%s' "${nuls//[!0-9]/}"
		}
	} 3>&1
}

# sgf_split_counted
# Takes SGF_CAPTURED apart: the content goes to SGF_CONTENT (byte for
# byte, trailing newlines included, NUL bytes dropped by the shell) and
# the number of NUL bytes the input had to SGF_NUL_COUNT. Returns 1 when
# SGF_CAPTURED does not end in the trailer (the pipeline was cut short).
# shellcheck disable=SC2034  # read by the scripts that source this file
SGF_CAPTURED=""
SGF_CONTENT=""
SGF_NUL_COUNT=""
sgf_split_counted() {
	local tail="${SGF_CAPTURED}" len="${#SGF_CAPTURED}"
	# Look for the trailer in the last bytes only: a pattern match over
	# the whole of a large file is slow.
	if [[ "${len}" -gt 24 ]]; then
		tail="${SGF_CAPTURED:$((len - 24))}"
	fi
	SGF_NUL_COUNT="${tail##*x}"
	case "${SGF_NUL_COUNT}" in
	"" | *[!0-9]*)
		SGF_NUL_COUNT=""
		return 1
		;;
	esac
	[[ "${tail}" == *x"${SGF_NUL_COUNT}" ]] || return 1
	SGF_CONTENT="${SGF_CAPTURED%x"${SGF_NUL_COUNT}"}"
	SGF_CAPTURED=""
}

# ── Which keys a document names, and what to check for them ───────
# sgf_doc_key_types   (SOPS document on stdin, either format)
# Prints the kinds of key the document was encrypted for, one per line:
# age kms gcp_kms azure_kv hc_vault pgp hckms. It reads the metadata
# sops stores in clear (recipients, key ids), nothing else.
sgf_doc_key_types() {
	awk '
	/"recipient"[ \t]*:/ || /^sops_.*__map_recipient=/ { t["age"] = 1 }
	/"arn"[ \t]*:/ || /^sops_.*__map_arn=/ { t["kms"] = 1 }
	/"resource_id"[ \t]*:/ || /^sops_.*__map_resource_id=/ { t["gcp_kms"] = 1 }
	/"vault_url"[ \t]*:/ || /^sops_.*__map_vault_url=/ { t["azure_kv"] = 1 }
	/"vault_address"[ \t]*:/ || /^sops_.*__map_vault_address=/ { t["hc_vault"] = 1 }
	/"fp"[ \t]*:/ || /^sops_.*__map_fp=/ { t["pgp"] = 1 }
	/"key_id"[ \t]*:/ || /^sops_.*__map_key_id=/ { t["hckms"] = 1 }
	END {
		n = split("age kms gcp_kms azure_kv hc_vault pgp hckms", order, " ")
		for (i = 1; i <= n; i++) if (order[i] in t) print order[i]
	}
	'
}

# sgf_doc_keys <format>   (SOPS document on stdin)
# Prints the keys the document was encrypted for, one per line, in the
# order of the document:  <key group> TAB <type> <name>, for example
#   1	age age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
#   2	kms arn:aws:kms:eu-central-1:111111111111:key/...
# Key group 1 is the first one (or the only one: a document without
# key_groups). It reads the metadata sops stores in clear, nothing else.
# Fails when a json document is not a SOPS document.
sgf_doc_keys() {
	case "$1" in
	json) awk -v keys=1 "${SGF_AWK_IS_TOKEN}${SGF_AWK_META}${SGF_AWK_JSON}" ;;
	dotenv) awk "${SGF_AWK_META}${SGF_AWK_DOTENV_KEYS}" ;;
	*) return 1 ;;
	esac
}

# sgf_credential_hint <indent> [key type...]
# What to check when sops cannot decrypt, one line per kind of key, each
# line starting with <indent>. Without key types (the document could not
# be read, or names none of the known kinds) every kind is listed.
sgf_credential_hint() {
	local indent="$1" type
	shift
	[[ $# -gt 0 ]] || set -- age kms gcp_kms azure_kv hc_vault pgp
	for type in "$@"; do
		case "${type}" in
		age) printf '%s%s\n' "${indent}" "age: the private key must be where sops looks (SOPS_AGE_KEY_FILE, SOPS_AGE_KEY, or its default keys.txt)" ;;
		kms) printf '%s%s\n' "${indent}" "AWS KMS: sign in again (aws sso login, or the AWS credentials / AWS_PROFILE you normally use)" ;;
		gcp_kms) printf '%s%s\n' "${indent}" "GCP KMS: sign in again (gcloud auth application-default login, or GOOGLE_APPLICATION_CREDENTIALS)" ;;
		azure_kv) printf '%s%s\n' "${indent}" "Azure Key Vault: sign in again (az login, or the AZURE_* variables of a service principal)" ;;
		hc_vault) printf '%s%s\n' "${indent}" "HashiCorp Vault: sign in again (vault login; VAULT_ADDR and VAULT_TOKEN must be set)" ;;
		pgp) printf '%s%s\n' "${indent}" "PGP: the secret key must be in your gpg keyring and gpg-agent must be able to ask for its passphrase (GPG_TTY)" ;;
		hckms) printf '%s%s\n' "${indent}" "Huawei Cloud KMS: check the Huawei Cloud credentials sops reads" ;;
		esac
	done
}

# ── sops version ──────────────────────────────────────────────────
# sgf_sops_version : prints X.Y.Z of the sops on PATH, or nothing.
sgf_sops_version() {
	local out
	# --disable-version-check: a bare --version asks GitHub for the
	# latest release.
	out="$(sops --disable-version-check --version 2>/dev/null || sops --version 2>/dev/null || true)"
	printf '%s\n' "${out}" | sed -n 's/^sops \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -1
}

# sgf_version_ge <a> <b> : true when version a (X.Y.Z) is at least b.
sgf_version_ge() {
	local a="$1" b="$2" x y
	for _ in 1 2 3; do
		x="${a%%.*}"
		y="${b%%.*}"
		if ((10#${x} > 10#${y})); then return 0; fi
		if ((10#${x} < 10#${y})); then return 1; fi
		a="${a#*.}"
		b="${b#*.}"
	done
	return 0
}

# ── The installed copy and the checkout ───────────────────────────
# Git does not run the scripts of the checkout (utilities/sops-git-filters
# or wherever the tool lives). install.sh copies the ones git needs into
# <git common dir>/sops-git-filters/ and points the filter, the merge
# driver and the hooks there, so that checking out a branch cannot swap
# the code that sees the plaintext. The price: an update of the checkout
# does nothing until install.sh has run again. The installed copy says so.

# sgf_version_of <a lib.sh> : prints the X.Y.Z of its SGF_VERSION line, or
# nothing. The file may come from a branch nobody reviewed, and the
# installed copy reads it on its own at every git command, so:
#   - it is never sourced, and nothing of it is printed unless it is a
#     plain version number;
#   - only a regular file is read, and not through a symlink: a symlink to
#     /dev/zero or a FIFO in its place would never return;
#   - only its first 8 KiB are read (the line is near the top), whatever
#     the file holds and however long its lines are.
SGF_VERSION_READ_BYTES=8192
sgf_version_of() {
	local line text version=""
	[[ -f "$1" && ! -L "$1" && -r "$1" ]] || return 0
	text="$(head -c "${SGF_VERSION_READ_BYTES}" -- "$1" 2>/dev/null | tr -d '\000')" || return 0
	while IFS= read -r line; do
		case "${line}" in
		'SGF_VERSION="'*'"')
			version="${line#SGF_VERSION=\"}"
			version="${version%\"}"
			break
			;;
		esac
	done <<<"${text}"
	! sgf_is_version "${version}" || printf '%s\n' "${version}"
}

# sgf_is_version <text> : true for X.Y.Z made of digits, nothing else
sgf_is_version() {
	case "$1" in
	"" | *[!0-9.]* | .* | *. | *..* | *.*.*.*) return 1 ;;
	*.*.*) return 0 ;;
	*) return 1 ;;
	esac
}

# sgf_warn_if_outdated <directory of the running script> <repository root>
# Only the installed copy has the file INSTALLED next to it (written by
# install.sh: its version, and where the checkout of the tool lives). When
# that checkout holds a newer version than the copy, one line on stderr
# says that install.sh must run again. Never fails.
sgf_warn_if_outdated() {
	local dir="$1" root="$2" line installed="" source="" theirs=""
	[[ -r "${dir}/INSTALLED" ]] || return 0
	while IFS= read -r line; do
		case "${line}" in
		version=*) installed="${line#version=}" ;;
		source=*) source="${line#source=}" ;;
		esac
	done <"${dir}/INSTALLED"
	if ! sgf_is_version "${installed}" || [[ -z "${source}" ]]; then
		return 0
	fi
	case "${source}" in
	/*) ;;
	*) source="${root}/${source}" ;;
	esac
	theirs="$(sgf_version_of "${source}/lib.sh")"
	[[ -n "${theirs}" ]] || return 0
	if ! sgf_version_ge "${installed}" "${theirs}"; then
		echo "sops-git-filters: git runs the installed copy, version ${installed}, but ${source} holds ${theirs}." >&2
		echo "  The update has no effect until you run ${source}/install.sh (from a checkout you trust)." >&2
	fi
	return 0
}

# ── What the clean filter remembers between two runs ──────────────
# Git runs the clean filter on a secret with uncommitted changes each
# time it looks at the file: once for `git status`, twice for `git diff`,
# once more for `git add` and `git commit -a` (issue #21). Each run
# decrypted the stored version and encrypted the edit again: two calls to
# a key service, and a new ciphertext every time. So the filter remembers
# for a few minutes what a run found, and the next run that is asked the
# same question gives the same answer without asking sops (see
# clean-filter.sh for the question and the answers).
#
# What is stored, in <git common dir>/sops-git-filters/cache/ (0700):
#   key          32 random bytes in hex (0600), made at the first use
#   e-<name>     one answer per file (0600): "sgf-cache 1 <check> <time>
#                <object id>", the time in seconds since 1970
#   swept        when old entries were last removed
# <name> and <check> are the two halves of an HMAC-SHA256 under that key
# of the question, which holds the plaintext. No plaintext and no plain
# hash of it is written: a SHA-256 of a short password can be tested
# offline against guesses, an HMAC cannot be without the key. The answer
# is the id of a blob in git's object store (ciphertext).
#
# The HMAC is computed here from a plain SHA-256 tool, as RFC 2104 says
# (tested against the vectors of RFC 4231): `openssl dgst -hmac <key>`
# would put the key in the arguments of a process, which other users of
# the machine can see. sha256sum (coreutils, busybox), openssl or shasum
# compute the SHA-256; with none of them the filter works as before,
# without the cache. The plaintext reaches the tool on stdin only.
#
# An entry is used for SGF_CACHE_TTL seconds after it was written, then
# removed. At most SGF_CACHE_MAX entries are kept. Writes go to a
# temporary file that is then renamed, so a run never reads half an
# entry, and two runs at once never fail each other. Anything unexpected
# turns the cache off for that run, never the filter: no SHA-256 tool, no
# random source, a directory or key that is a symlink, belongs to someone
# else or is open to the group or others; an entry that does not read as
# one is removed.
#
# The functions below change the umask and may stop at any error: the
# clean filter calls them in a subshell, with their output discarded.
SGF_CACHE_TTL=600
SGF_CACHE_MAX=512
SGF_CACHE_DIR=""
SGF_CACHE_NOW=""
SGF_SHA256_TOOL=""
SGF_HMAC_IPAD=""
SGF_HMAC_OPAD=""

# sgf_sha256   (data on stdin) : prints its SHA-256 in hex
sgf_sha256() {
	local out
	case "${SGF_SHA256_TOOL}" in
	sha256sum) out="$(sha256sum)" || return 1 ;;
	openssl) out="$(openssl dgst -sha256)" || return 1 ;;
	shasum) out="$(shasum -a 256)" || return 1 ;;
	*) return 1 ;;
	esac
	# "<hex>  -" (sha256sum, shasum), "<hex>" (LibreSSL) or
	# "SHA2-256(stdin)= <hex>" (OpenSSL 3)
	case "${SGF_SHA256_TOOL}" in
	openssl) out="${out##* }" ;;
	*) out="${out%% *}" ;;
	esac
	[[ "${#out}" -eq 64 && "${out}" != *[!0-9a-f]* ]] || return 1
	printf '%s\n' "${out}"
}

# sgf_sha256_tool : sets SGF_SHA256_TOOL to the first one on PATH
sgf_sha256_tool() {
	local tool
	for tool in sha256sum openssl shasum; do
		if command -v "${tool}" >/dev/null 2>&1; then
			SGF_SHA256_TOOL="${tool}"
			return 0
		fi
	done
	return 1
}

# sgf_hmac_init <key in hex, 1 to 64 bytes>
# Prepares the two key blocks of HMAC-SHA256 (the key padded with zero
# bytes to 64, XOR 0x36 and XOR 0x5c), as printf formats of \x escapes.
sgf_hmac_init() {
	local key="$1" i byte ipad="" opad=""
	[[ -n "${key}" && $((${#key} % 2)) -eq 0 && "${#key}" -le 128 && "${key}" != *[!0-9a-f]* ]] || return 1
	for ((i = 0; i < 128; i += 2)); do
		byte="${key:i:2}"
		[[ -n "${byte}" ]] || byte=00
		printf -v ipad '%s\\x%02x' "${ipad}" "$((16#${byte} ^ 0x36))"
		printf -v opad '%s\\x%02x' "${opad}" "$((16#${byte} ^ 0x5c))"
	done
	SGF_HMAC_IPAD="${ipad}"
	SGF_HMAC_OPAD="${opad}"
}

# sgf_hmac_sha256 <command...> : prints the HMAC-SHA256, in hex, of what
# the command prints, under the key of sgf_hmac_init. The key blocks are
# written by printf, a builtin: they never appear in the arguments of a
# process.
sgf_hmac_sha256() {
	local inner fmt="" i
	[[ -n "${SGF_HMAC_IPAD}" && -n "${SGF_HMAC_OPAD}" ]] || return 1
	# shellcheck disable=SC2059  # the format is the key block: \x escapes only
	inner="$({ printf "${SGF_HMAC_IPAD}" && "$@"; } | sgf_sha256)" || return 1
	for ((i = 0; i < 64; i += 2)); do
		fmt="${fmt}\\x${inner:i:2}"
	done
	# shellcheck disable=SC2059  # the formats are \x escapes only
	{ printf "${SGF_HMAC_OPAD}" && printf "${fmt}"; } | sgf_sha256
}

# sgf_cache_open <git common dir>
# Makes the cache directory and its key where they are missing, checks
# both, and prepares the HMAC. Sets SGF_CACHE_DIR and SGF_CACHE_NOW.
# Removes old entries once per SGF_CACHE_TTL. Returns 1 when the cache
# cannot be used; the caller then works without it.
sgf_cache_open() {
	local top="$1/sops-git-filters" dir key tmp now
	dir="${top}/cache"
	SGF_CACHE_DIR=""
	umask 077
	sgf_sha256_tool || return 1
	now="$(date +%s)" || return 1
	[[ -n "${now}" && "${now}" != *[!0-9]* && "${#now}" -le 12 ]] || return 1
	SGF_CACHE_NOW="${now}"

	# The directory of the installed copy (install.sh makes it), and the
	# cache in it: real directories, owned by the user who runs git.
	if [[ ! -e "${top}" && ! -L "${top}" ]]; then
		mkdir -m 700 "${top}" 2>/dev/null || true
	fi
	[[ -d "${top}" && ! -L "${top}" && -O "${top}" ]] || return 1
	if [[ ! -e "${dir}" && ! -L "${dir}" ]]; then
		mkdir -m 700 "${dir}" 2>/dev/null || true
	fi

	# The key: written under another name, then linked into place. A link
	# does not replace a file that is there, so when two runs make a key
	# at the same moment, one of them wins and both use it.
	if [[ ! -e "${dir}/key" && ! -L "${dir}/key" ]]; then
		sgf_private "${dir}" || return 1
		key="$(od -An -tx1 -N32 /dev/urandom)" || return 1
		key="${key//[!0-9a-f]/}"
		[[ "${#key}" -eq 64 ]] || return 1
		tmp="${dir}/tmp.${now}.$$.key"
		printf '%s\n' "${key}" >"${tmp}" || return 1
		ln "${tmp}" "${dir}/key" 2>/dev/null || true
		rm -f "${tmp}"
	fi
	sgf_private "${dir}" "${dir}/key" || return 1
	IFS= read -r key <"${dir}/key" || return 1
	[[ "${#key}" -eq 64 ]] || return 1
	sgf_hmac_init "${key}" || return 1
	SGF_CACHE_DIR="${dir}"

	if ! IFS= read -r tmp <"${dir}/swept" 2>/dev/null || ! sgf_cache_fresh "${tmp}"; then
		sgf_cache_sweep
		printf '%s\n' "${now}" >"${dir}/tmp.${now}.$$.swept" &&
			mv -f "${dir}/tmp.${now}.$$.swept" "${dir}/swept"
	fi
	return 0
}

# sgf_private <path>... : true when each path is a directory or a regular
# file, not a symlink, owned by the user who runs this, with no
# permission bit for the group or others (one call to find for all).
sgf_private() {
	local path open
	for path in "$@"; do
		[[ (-d "${path}" || -f "${path}") && ! -L "${path}" && -O "${path}" ]] || return 1
	done
	open="$(find "$@" -prune \( -perm -0040 -o -perm -0020 -o -perm -0010 \
		-o -perm -0004 -o -perm -0002 -o -perm -0001 \) -print)" || return 1
	[[ -z "${open}" ]]
}

# sgf_cache_fresh <time> : true for a time of the last SGF_CACHE_TTL
# seconds (SGF_CACHE_NOW is now)
sgf_cache_fresh() {
	[[ -n "$1" && "$1" != *[!0-9]* && "${#1}" -le 12 ]] || return 1
	(((SGF_CACHE_NOW - 10#$1) >= 0 && (SGF_CACHE_NOW - 10#$1) < SGF_CACHE_TTL))
}

# sgf_is_object_id <text> : 40 (SHA-1) or 64 (SHA-256) lower-case hex digits
sgf_is_object_id() {
	[[ ("${#1}" -eq 40 || "${#1}" -eq 64) && "$1" != *[!0-9a-f]* ]]
}

# sgf_cache_get <name> <check> : prints "<object id> <age in seconds>"
# for an entry of that name that holds that check and is fresh. Removes
# an entry that is not.
sgf_cache_get() {
	local file="${SGF_CACHE_DIR}/e-$1" tag version check time answer rest
	[[ -n "${SGF_CACHE_DIR}" && -f "${file}" && ! -L "${file}" ]] || return 1
	if IFS=' ' read -r tag version check time answer rest <"${file}" &&
		[[ "${tag} ${version}" == "sgf-cache 1" && "${check}" == "$2" && -z "${rest}" ]] &&
		sgf_cache_fresh "${time}" && sgf_is_object_id "${answer}"; then
		printf '%s %s\n' "${answer}" "$((SGF_CACHE_NOW - 10#${time}))"
		return 0
	fi
	rm -f "${file}"
	return 1
}

# sgf_cache_put <name> <check> <object id>
sgf_cache_put() {
	local tmp="${SGF_CACHE_DIR}/tmp.${SGF_CACHE_NOW}.$$.${RANDOM}"
	[[ -n "${SGF_CACHE_DIR}" ]] && sgf_is_object_id "$3" || return 1
	# Too many entries: the old ones go first, all of them if need be.
	set -- "$@" "${SGF_CACHE_DIR}"/e-*
	if [[ $# -gt $((SGF_CACHE_MAX + 3)) ]]; then
		sgf_cache_sweep
	fi
	printf 'sgf-cache 1 %s %s %s\n' "$2" "${SGF_CACHE_NOW}" "$3" >"${tmp}" || return 1
	mv -f "${tmp}" "${SGF_CACHE_DIR}/e-$1" || {
		rm -f "${tmp}"
		return 1
	}
}

# sgf_cache_sweep : removes the entries that are no longer fresh or do
# not read as one, and temporary files left behind; all entries when more
# than SGF_CACHE_MAX remain.
sgf_cache_sweep() {
	local file name time tag version check answer rest kept=0
	local -a old=()
	for file in "${SGF_CACHE_DIR}"/e-* "${SGF_CACHE_DIR}"/tmp.*; do
		[[ -e "${file}" || -L "${file}" ]] || continue
		name="${file##*/}"
		time=""
		case "${name}" in
		tmp.*)
			time="${name#tmp.}"
			time="${time%%.*}"
			;;
		*)
			if [[ -f "${file}" && ! -L "${file}" ]]; then
				IFS=' ' read -r tag version check time answer rest <"${file}" || time=""
			fi
			;;
		esac
		if sgf_cache_fresh "${time}"; then
			[[ "${name}" == tmp.* ]] || kept=$((kept + 1))
		else
			old[${#old[@]}]="${file}"
		fi
	done
	if [[ "${kept}" -gt "${SGF_CACHE_MAX}" ]]; then
		for file in "${SGF_CACHE_DIR}"/e-*; do
			old[${#old[@]}]="${file}"
		done
	fi
	[[ "${#old[@]}" -eq 0 ]] || rm -f -- "${old[@]}"
}

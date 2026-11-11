#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Shared helpers for sops-git-filters                             ║
# ║                                                                  ║
# ║  Sourced by clean-filter.sh, install.sh and encryption-guard.sh. ║
# ║  It must sit next to them: copy it along when you vendor the     ║
# ║  scripts. Nothing here runs on its own.                          ║
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

# Oldest sops this tool accepts. Up to 3.10.2, sops applies a creation
# rule's encrypted_regex / unencrypted_regex / encrypted_suffix /
# unencrypted_suffix to the single "data" key of the binary store, and
# when the rule does not select that key the whole file is stored in
# clear inside a SOPS envelope. 3.11.0 ignores those options for the
# binary store.
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

# ── One encrypted value ───────────────────────────────────────────
# An awk function shared by the two document checks below. True when
# the string is exactly one SOPS ciphertext value:
#   ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<word>]
# and holds no character outside that alphabet.
#
# The checks are written in awk, not in bash, for speed: bash pattern
# matching on a whole document takes time quadratic in its length (a
# few hundred kilobytes took minutes), awk reads it once.
SGF_AWK_IS_TOKEN='
function is_token(s) {
	if (substr(s, 1, 20) != "ENC[AES256_GCM,data:") return 0
	if (substr(s, length(s), 1) != "]") return 0
	if (index(s, ",iv:") == 0 || index(s, ",tag:") == 0 || index(s, ",type:") == 0) return 0
	return match(s, "[^]A-Za-z0-9+/=,:_[]") == 0
}
'

# ── The metadata sops writes ──────────────────────────────────────
# A document is accepted only when its metadata holds nothing but the
# names sops itself writes. Anything else next to them could be a
# secret in clear, and both the guard and the clean filter (which
# stores a working copy that already is a SOPS document unchanged)
# rely on this check.
#
# The names come from stores/stores.go of sops 3.9.0 to 3.13.3 (the
# same list in every release; hckms and key_id came with 3.12.0) and
# were compared with real output of 3.9.1, 3.10.2, 3.11.0, 3.12.1 and
# 3.13.3 for age, AWS KMS, key groups and partial-encryption rules:
#
#   meta_scalar   plain values of the "sops" object
#   meta_keytype  its lists of key entries, also inside key_groups
#   meta_entry    the fields of one key entry, per kind of key
#
# One field is free-form by design: "context" of a kms entry, the AWS
# encryption context, is a map of names the user chose.
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
	if (c == "{" && kind == "list") push("entry", "k0", Type[depth])
	else if (c == "{" && kind == "groups") push("group", "k0", "")
	else fail("a list inside a list")
}

function on_close(c,    kind, st) {
	if (!ready()) return
	kind = K[depth]; st = St[depth]
	if (c == "}") {
		if (!is_obj(kind) || (st != "k0" && st != "e")) { fail("it is not valid JSON"); return }
		if (kind == "doc" && ndoc != 2) { fail("\"data\" and \"sops\" are not both there"); return }
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
	if (!explain) print datakind
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
sgf_blob_is_sops_doc() {
	local format="$1" oid="$2" dir="${3:-.}"
	git -C "${dir}" cat-file -e "${oid}" 2>/dev/null || return 2
	case "${format}" in
	json) git -C "${dir}" cat-file blob "${oid}" | sgf_json_envelope_kind >/dev/null ;;
	dotenv) git -C "${dir}" cat-file blob "${oid}" | sgf_is_sops_dotenv ;;
	*) return 1 ;;
	esac
}

# sgf_blob_problem <format> <object id> [git -C dir]
# sgf_doc_problem for a blob in the object store.
sgf_blob_problem() {
	git -C "${3:-.}" cat-file blob "$2" 2>/dev/null | sgf_doc_problem "$1"
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

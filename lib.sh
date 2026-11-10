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
function ltrim(s) {
	sub(/^[ \t\r\n]+/, "", s)
	return s
}
'

# ── json store ────────────────────────────────────────────────────
# sgf_json_envelope_kind   (document on stdin)
# Succeeds for the document the clean filter stores in json mode and
# for nothing else:
#
#   { "data": "<one ENC[...] value, or empty>", "sops": { ... } }
#
# "data" must be the first key and "sops" the second and last one.
# Prints "enc" when "data" holds ciphertext and "empty" when it is the
# empty string, which is what sops writes for an empty file.
#
# The whole input is read even when the answer is known after the
# first line, so the writer never gets a broken pipe.
sgf_json_envelope_kind() {
	awk "${SGF_AWK_IS_TOKEN}"'
	function reject() { failed = 1 }
	failed { next }
	state == 0 {
		# Before and at the start of the document: "{", then "data".
		# sops prints them on two lines; a minified document has one.
		if (head == "" && $0 ~ /^[ \t\r]*$/) next
		head = head $0 "\n"
		lines++
		h = ltrim(head)
		if (substr(h, 1, 1) != "{") { reject(); next }
		h = ltrim(substr(h, 2))
		if (h == "") {
			if (lines > 2) reject()
			next
		}
		if (substr(h, 1, 6) != "\"data\"") { reject(); next }
		h = ltrim(substr(h, 7))
		if (substr(h, 1, 1) != ":") { reject(); next }
		h = ltrim(substr(h, 2))
		if (substr(h, 1, 1) != "\"") { reject(); next }
		h = substr(h, 2)
		# A JSON string cannot hold a raw newline or an unescaped quote:
		# the value ends at the next quote, on this line.
		closing = index(h, "\"")
		if (closing == 0) { reject(); next }
		token = substr(h, 1, closing - 1)
		if (token != "" && !is_token(token)) { reject(); next }
		kind = (token == "") ? "empty" : "enc"
		rest = substr(h, closing + 1)
		head = ""
		state = 1
		next
	}
	{
		# After the value: the metadata. A sops document has a few dozen
		# lines here; refuse anything that goes on and on.
		if (++tail_lines > 5000) { reject(); next }
		rest = rest $0 "\n"
	}
	END {
		if (failed || state != 1) exit 1
		r = ltrim(rest)
		if (substr(r, 1, 1) != ",") exit 1
		r = ltrim(substr(r, 2))
		if (substr(r, 1, 6) != "\"sops\"") exit 1
		r = ltrim(substr(r, 7))
		if (substr(r, 1, 1) != ":") exit 1
		r = ltrim(substr(r, 2))
		if (substr(r, 1, 1) != "{") exit 1
		if (r !~ /}[ \t\r\n]*}[ \t\r\n]*$/) exit 1
		print kind
	}
	'
}

# ── dotenv store ──────────────────────────────────────────────────
# sgf_is_sops_dotenv   (document on stdin)
# True when every line is one of
#   KEY=<one ENC[...] value>      KEY=            (empty value)
#   #<one ENC[...] value>         #               (empty comment)
#   sops_<metadata>=<anything>    (blank line)
# and the metadata carries sops_mac and sops_version. A value or a
# comment left in clear makes it false.
sgf_is_sops_dotenv() {
	awk "${SGF_AWK_IS_TOKEN}"'
	{
		sub(/\r$/, "")
		if ($0 == "" || $0 == "#") next
		if (substr($0, 1, 1) == "#") {
			if (!is_token(substr($0, 2))) bad = 1
			next
		}
		eq = index($0, "=")
		if (eq == 0) { bad = 1; next }
		key = substr($0, 1, eq - 1)
		val = substr($0, eq + 1)
		if (substr(key, 1, 5) == "sops_") {
			if (key == "sops_mac" && is_token(val)) mac = 1
			if (key == "sops_version" && val != "") ver = 1
			next
		}
		if (val != "" && !is_token(val)) bad = 1
	}
	END { exit (bad || !mac || !ver) ? 1 : 0 }
	'
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

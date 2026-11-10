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

# ── One encrypted value ───────────────────────────────────────────
# sgf_is_enc_token <string>
# True when the string is exactly one SOPS ciphertext value:
#   ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<word>]
# and holds no character outside that alphabet.
sgf_is_enc_token() {
	local token="$1"
	case "${token}" in
	'ENC[AES256_GCM,data:'*',iv:'*',tag:'*',type:'*']') ;;
	*) return 1 ;;
	esac
	case "${token}" in
	*[!]A-Za-z0-9+/=,:_[]*) return 1 ;;
	*) ;;
	esac
	return 0
}

# ── json store ────────────────────────────────────────────────────
# sgf_is_sops_json <document>
# True for the document the clean filter stores in json mode and for
# nothing else:
#
#   { "data": "<one ENC[...] value, or empty>", "sops": { ... } }
#
# "data" must be the first key and "sops" the second and last one.
# An empty "data" is what sops writes for an empty file. The value
# found is left in SGF_DATA_TOKEN for callers that need to tell the
# two cases apart.
SGF_DATA_TOKEN=""
sgf_is_sops_json() {
	local doc="$1" rest after
	local head_re='^[[:space:]]*\{[[:space:]]*"data":[[:space:]]*"'
	local sops_re='^[[:space:]]*,[[:space:]]*"sops":[[:space:]]*\{'
	local tail_re='\}[[:space:]]*\}[[:space:]]*$'

	SGF_DATA_TOKEN=""
	[[ "${doc}" =~ ${head_re} ]] || return 1

	rest="${doc#*\"data\":*\"}"       # after the opening quote of the value
	SGF_DATA_TOKEN="${rest%%\"*}"     # up to the next quote
	after="${rest#*\"}"               # after the closing quote

	if [[ -n "${SGF_DATA_TOKEN}" ]]; then
		sgf_is_enc_token "${SGF_DATA_TOKEN}" || return 1
	fi
	[[ "${after}" =~ ${sops_re} ]] || return 1
	[[ "${after}" =~ ${tail_re} ]] || return 1
	return 0
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
	awk '
	function is_token(s,   t) {
		if (substr(s, 1, 20) != "ENC[AES256_GCM,data:") return 0
		if (substr(s, length(s), 1) != "]") return 0
		if (index(s, ",iv:") == 0 || index(s, ",tag:") == 0 || index(s, ",type:") == 0) return 0
		t = s
		gsub(/[A-Za-z0-9+=,:_]/, "", t)
		gsub("/", "", t)
		gsub("\\[", "", t)
		gsub("\\]", "", t)
		return t == ""
	}
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
sgf_is_sops_doc() {
	case "$1" in
	json) sgf_is_sops_json "$2" ;;
	dotenv) printf '%s' "$2" | sgf_is_sops_dotenv ;;
	*) return 1 ;;
	esac
}

# sgf_blob_is_sops_doc <format> <object id> [git -C dir]
# Reads a blob from the object store and checks it. Returns 2 when the
# blob cannot be read, 1 when it is not a SOPS document.
sgf_blob_is_sops_doc() {
	local format="$1" oid="$2" dir="${3:-.}" content
	# The trailing x keeps the final newlines that $(...) would strip.
	# 2>/dev/null: bash >= 4.4 warns about NUL bytes in a binary blob.
	{ content="$(git -C "${dir}" cat-file blob "${oid}" && printf x)"; } 2>/dev/null || return 2
	sgf_is_sops_doc "${format}" "${content%x}"
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

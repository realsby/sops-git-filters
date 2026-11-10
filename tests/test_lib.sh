#!/usr/bin/env bash
# lib.sh: the document checks, without git or sops.
# shellcheck disable=SC2154  # SGF_TOOL_DIR comes from tests/run.sh

ENC='ENC[AES256_GCM,data:abc+/=,iv:AAAA,tag:BBBB==,type:str]'
ENC_COMMENT='ENC[AES256_GCM,data:abc,iv:AAAA,tag:BBBB,type:comment]'

load_lib() {
	export LC_ALL=C
	# shellcheck source=lib.sh
	. "${SGF_TOOL_DIR}/lib.sh"
}

is() { "$@" || fail "expected true: $*"; }
is_not() { if "$@"; then fail "expected false: $*"; fi; }

test_lib_enc_token() {
	load_lib
	is sgf_is_enc_token "${ENC}"
	is sgf_is_enc_token "${ENC_COMMENT}"
	is_not sgf_is_enc_token "${ENC} trailing text"
	is_not sgf_is_enc_token 'ENC[AES256_GCM,data:a b,iv:AAAA,tag:BBBB,type:str]'
	is_not sgf_is_enc_token 'ENC[AES256_GCM,data:a\nb,iv:AAAA,tag:BBBB,type:str]'
	is_not sgf_is_enc_token 'ENC[AES256_GCM,data:abc]'
	is_not sgf_is_enc_token 'hunter2'
	is_not sgf_is_enc_token ''
}

test_lib_json_document() {
	load_lib
	local meta=$'"sops": {\n\t\t"mac": "'"${ENC}"$'",\n\t\t"version": "3.13.3"\n\t}\n}\n'

	is sgf_is_sops_json $'{\n\t"data": "'"${ENC}"$'",\n\t'"${meta}"
	assert_eq "${SGF_DATA_TOKEN}" "${ENC}" "SGF_DATA_TOKEN"
	is sgf_is_sops_json $'{\n\t"data": "",\n\t'"${meta}"
	assert_eq "${SGF_DATA_TOKEN}" "" "SGF_DATA_TOKEN for an empty file"
	is sgf_is_sops_json '{"data":"'"${ENC}"'","sops":{"version":"3.13.3"}}'
	is sgf_is_sops_json $'{\n  "data": "'"${ENC}"$'",\n  "sops": {\n    "version": "3.13.3"\n  }\n}'

	# content in clear inside a real envelope
	is_not sgf_is_sops_json $'{\n\t"data": "TOP-SECRET\\n",\n\t'"${meta}"
	is_not sgf_is_sops_json $'{\n\t"data": "say \\"hi\\"",\n\t'"${meta}"
	# another key next to data, before or after the metadata
	is_not sgf_is_sops_json $'{\n\t"data": "'"${ENC}"$'",\n\t"note": "plain",\n\t'"${meta}"
	is_not sgf_is_sops_json $'{\n\t"data": "'"${ENC}"$'",\n\t"sops": {},\n\t"note": "plain"\n}\n'
	# not an envelope at all
	is_not sgf_is_sops_json $'PW=hunter2\n# old value was ENC[AES256_GCM,data:xxxx]\n'
	is_not sgf_is_sops_json "A=${ENC}"
	is_not sgf_is_sops_json ''
}

test_lib_dotenv_document() {
	load_lib
	local doc
	doc="#${ENC_COMMENT}"$'\n#\n'"A=${ENC}"$'\nEMPTY=\n'"export B=${ENC}"$'\n'"sops_mac=${ENC}"$'\nsops_version=3.13.3\nsops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\n'

	is sgf_is_sops_doc dotenv "${doc}"
	is sgf_is_sops_doc dotenv "$(printf '%s' "${doc}" | sed 's/$/\r/')"   # CRLF checkout
	is_not sgf_is_sops_doc dotenv "${doc}PLAIN=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}# a comment in clear"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}no equals sign"$'\n'
	is_not sgf_is_sops_doc dotenv "A=${ENC}"$'\n'            # no sops metadata
	is_not sgf_is_sops_doc dotenv $'A=\nB=\n'
	is_not sgf_is_sops_doc dotenv ''
	is_not sgf_is_sops_doc json "${doc}"
}

test_lib_dotenv_input() {
	load_lib
	local out
	ok_input() { printf '%s' "$1" | sgf_dotenv_input_problem >/dev/null || fail "expected acceptable input: $1"; }
	bad_input() { # <input> <expected text> <forbidden text>
		if out="$(printf '%s' "$1" | sgf_dotenv_input_problem)"; then
			fail "expected a refusal for: $1"
		fi
		assert_contains "${out}" "$2" "reason"
		[[ -z "${3:-}" ]] || assert_not_contains "${out}" "$3" "reason must not print content"
	}

	ok_input $'# comment\n#\nA=1\n\nexport B=2\nC="x y" # note\nD=\'q\'\nE=\n a.b-c = 3\nU=https://u:p@h/?a=b\n'
	ok_input $'A=1\r\nB=2\r\n'
	ok_input ''
	bad_input $'A=1\nKEY="-----BEGIN\nMIIE\n-----END"\n' "line 2" "BEGIN"
	bad_input $'A=1\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n' "line 2" "MIIE"
	bad_input $'A=1\n  # indented, so not a comment for sops = x\n' "line 2" "indented"
	bad_input $'two words=1\n' "line 1" "two words"
	bad_input $'A=\'unclosed\n' "line 1" "unclosed"
}

test_lib_version_compare() {
	load_lib
	is sgf_version_ge 3.11.0 3.11.0
	is sgf_version_ge 3.13.3 3.11.0
	is sgf_version_ge 3.100.0 3.11.0
	is sgf_version_ge 4.0.0 3.11.0
	is_not sgf_version_ge 3.10.2 3.11.0
	is_not sgf_version_ge 3.9.4 3.11.0
	is_not sgf_version_ge 2.99.99 3.11.0
	assert_ne "$(sgf_sops_version)" "" "version of the sops on PATH"
}

test_lib_store_format() {
	load_lib
	mkdir repo
	assert_eq "$(sgf_store_format repo)" "json" "default"
	printf 'SOPS_FILE_MODE=640\n' >repo/.sops-filter.conf
	assert_eq "$(sgf_store_format repo)" "json" "conf without SOPS_STORE_FORMAT"
	printf 'SOPS_STORE_FORMAT=dotenv\r\n' >repo/.sops-filter.conf
	assert_eq "$(sgf_store_format repo)" "dotenv" "dotenv, CRLF file"
	printf 'SOPS_STORE_FORMAT=yaml\n' >repo/.sops-filter.conf
	is_not sgf_store_format repo
}

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

# envelope <value of "data"> : a json-format document around that value
envelope() {
	printf '{\n\t"data": "%s",\n\t"sops": {\n\t\t"mac": "%s",\n\t\t"version": "3.13.3"\n\t}\n}\n' "$1" "${ENC}"
}

test_lib_enc_token() {
	load_lib
	is sgf_is_sops_doc json "$(envelope "${ENC}")"
	is sgf_is_sops_doc json "$(envelope "${ENC_COMMENT}")"
	is_not sgf_is_sops_doc json "$(envelope "${ENC} trailing text")"
	is_not sgf_is_sops_doc json "$(envelope 'ENC[AES256_GCM,data:a b,iv:AAAA,tag:BBBB,type:str]')"
	is_not sgf_is_sops_doc json "$(envelope 'ENC[AES256_GCM,data:a\nb,iv:AAAA,tag:BBBB,type:str]')"
	is_not sgf_is_sops_doc json "$(envelope 'ENC[AES256_GCM,data:abc]')"
	is_not sgf_is_sops_doc json "$(envelope 'hunter2')"
}

test_lib_json_document() {
	load_lib
	local meta=$'"sops": {\n\t\t"mac": "'"${ENC}"$'",\n\t\t"version": "3.13.3"\n\t}\n}\n'

	is sgf_is_sops_doc json $'{\n\t"data": "'"${ENC}"$'",\n\t'"${meta}"
	assert_eq "${SGF_DATA_KIND}" "enc" "SGF_DATA_KIND"
	is sgf_is_sops_doc json $'{\n\t"data": "",\n\t'"${meta}"
	assert_eq "${SGF_DATA_KIND}" "empty" "SGF_DATA_KIND for an empty file"
	is sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{"mac":"'"${ENC}"'","version":"3.13.3"}}'
	is sgf_is_sops_doc json $'{\n  "data": "'"${ENC}"$'",\n  "sops": {\n    "version": "3.13.3",\n    "mac": "'"${ENC}"$'"\n  }\n}'
	is sgf_is_sops_doc json $'\n\n{\r\n\t"data": "'"${ENC}"$'",\r\n\t"sops": {\r\n\t\t"mac": "'"${ENC}"$'",\r\n\t\t"version": "3.13.3"\r\n\t}\r\n}\r\n'

	# content in clear inside a real envelope
	is_not sgf_is_sops_doc json $'{\n\t"data": "TOP-SECRET\\n",\n\t'"${meta}"
	is_not sgf_is_sops_doc json $'{\n\t"data": "say \\"hi\\"",\n\t'"${meta}"
	# another key next to data, before or after the metadata
	is_not sgf_is_sops_doc json $'{\n\t"data": "'"${ENC}"$'",\n\t"note": "plain",\n\t'"${meta}"
	is_not sgf_is_sops_doc json $'{\n\t"data": "'"${ENC}"$'",\n\t"sops": {},\n\t"note": "plain"\n}\n'
	is_not sgf_is_sops_doc json $'{\n\t"note": "plain",\n\t"data": "'"${ENC}"$'",\n\t'"${meta}"
	# not an envelope at all
	is_not sgf_is_sops_doc json $'PW=hunter2\n# old value was ENC[AES256_GCM,data:xxxx]\n'
	is_not sgf_is_sops_doc json "A=${ENC}"
	is_not sgf_is_sops_doc json '{'
	is_not sgf_is_sops_doc json ''
}

# sops_doc <the inside of "sops"> : a json-format document with that metadata
sops_doc() {
	printf '{\n\t"data": "%s",\n\t"sops": {%s}\n}\n' "${ENC}" "$1"
}

# The whole document counts, not its first lines and its last braces.
# The first two are the examples from the review of this check.
test_lib_json_document_is_checked_to_the_end() {
	load_lib
	local good='"mac": "'"${ENC}"'", "version": "3.13.3"'
	is sgf_is_sops_doc json "$(sops_doc "${good}")"

	is_not sgf_is_sops_doc json '{"data":"","sops":{},"credentials":{"password":"hunter2"}}'
	is_not sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{},"secret":{"password":"plaintext"}}'
	# a complete document, and then one more key
	is_not sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{'"${good}"'},"credentials":{"password":"hunter2"}}'
	is_not sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{'"${good}"'},"note":"hunter2"}'
	# text after the document, or a second one
	is_not sgf_is_sops_doc json "$(sops_doc "${good}")PASSWORD=hunter2"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}")$(sops_doc "${good}")"

	# inside "sops": only what sops writes
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "password": "hunter2"')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "credentials": {"password": "hunter2"}')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "lastmodified": {"password": "hunter2"}')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "unencrypted_suffix": ["hunter2"]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "age": "hunter2"')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "age": ["hunter2"]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "age": [{"recipient": "age1x", "enc": "e", "note": "hunter2"}]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "age": [{"recipient": {"password": "hunter2"}}]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "key_groups": [{"passwords": [{"enc": "hunter2"}]}]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "key_groups": [{"age": [{"enc": "e"}], "note": "hunter2"}]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "pgp": [{"fp": "F", "enc": {"password": "hunter2"}}]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "age": [{"recipient": "age1x", "context": {"password": "hunter2"}}]')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "age": [{"recipient": "age1x", "arn": "hunter2"}]')"

	# "mac" must be an encrypted value, "version" must be there, no key twice
	is_not sgf_is_sops_doc json "$(sops_doc '"mac": "hunter2", "version": "3.13.3"')"
	is_not sgf_is_sops_doc json "$(sops_doc '"version": "3.13.3"')"
	is_not sgf_is_sops_doc json "$(sops_doc '"mac": "'"${ENC}"'"')"
	is_not sgf_is_sops_doc json "$(sops_doc '"mac": "'"${ENC}"'", "version": ""')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"', "mac": "hunter2"')"
	is_not sgf_is_sops_doc json '{"data":"'"${ENC}"'","data":"hunter2","sops":{'"${good}"'}}'

	# not JSON
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"',')"
	is_not sgf_is_sops_doc json "$(sops_doc "${good}"' "version" "3.13.3"')"
	is_not sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{'"${good}"'}'
	is_not sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{'"${good}"'}}}'
	is_not sgf_is_sops_doc json '["data","sops"]'
}

# Metadata as sops really writes it. The shapes are those of 3.9.1 (a
# null for every key type that is not used) and of 3.13.3, with AWS KMS,
# an encryption context, age, key groups and a quote inside a string.
test_lib_json_document_accepts_what_sops_writes() {
	load_lib
	local kms='{"arn": "arn:aws:kms:eu-central-1:111111111111:key/0000", "role": "arn:aws:iam::111111111111:role/r", "context": {"Env": "prod", "Team": null}, "created_at": "2026-01-01T00:00:00Z", "enc": "AQICAH==", "aws_profile": ""}'
	local age='{"recipient": "age1qqqq", "enc": "-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\\n-----END AGE ENCRYPTED FILE-----\\n"}'

	is sgf_is_sops_doc json "$(sops_doc '"kms": ['"${kms}"'], "gcp_kms": null, "azure_kv": null, "hc_vault": null, "age": ['"${age}"', '"${age}"'], "lastmodified": "2026-01-01T00:00:00Z", "mac": "'"${ENC}"'", "pgp": null, "unencrypted_suffix": "_unencrypted", "version": "3.9.1"')"
	is sgf_is_sops_doc json "$(sops_doc '"age": ['"${age}"'], "kms": ['"${kms}"'], "lastmodified": "2026-01-01T00:00:00Z", "mac": "'"${ENC}"'", "version": "3.13.3"')"
	is sgf_is_sops_doc json "$(sops_doc '"key_groups": [{"age": ['"${age}"'], "hc_vault": []}, {"kms": ['"${kms}"'], "hc_vault": null, "age": []}], "lastmodified": "2026-01-01T00:00:00Z", "mac": "'"${ENC}"'", "shamir_threshold": 2, "version": "3.13.3"')"
	is sgf_is_sops_doc json "$(sops_doc '"encrypted_regex": "^(a|\"b\\\")$", "mac_only_encrypted": true, "mac": "'"${ENC}"'", "version": "3.13.3"')"
	is sgf_is_sops_doc json "$(sops_doc '"pgp": [{"created_at": "2026-01-01T00:00:00Z", "enc": "-----BEGIN PGP MESSAGE-----\\n\\nhQ==\\n-----END PGP MESSAGE-----", "fp": "ABCDEF"}], "gcp_kms": [{"resource_id": "projects/p/locations/l/keyRings/r/cryptoKeys/k", "created_at": "t", "enc": "e"}], "azure_kv": [{"vault_url": "https://v.vault.azure.net", "name": "n", "version": "v", "created_at": "t", "enc": "e"}], "hc_vault": [{"vault_address": "https://v", "engine_path": "transit", "key_name": "k", "created_at": "t", "enc": "e"}], "hckms": [{"key_id": "k", "created_at": "t", "enc": "e"}], "mac": "'"${ENC}"'", "version": "3.13.3"')"
}

# The reason for a refusal names a key or a line, never a value.
test_lib_doc_problem_says_why_without_content() {
	load_lib
	local out
	out="$(sops_doc '"mac": "'"${ENC}"'", "version": "3.14.0", "new_field": "hunter2"' | sgf_doc_problem json)"
	assert_contains "${out}" "new_field" "reason names the unknown key"
	assert_not_contains "${out}" "hunter2" "reason"
	out="$(printf '{"data":"","sops":{},"credentials":{"password":"hunter2"}}' | sgf_doc_problem json)"
	assert_ne "${out}" "" "a reason is given"
	assert_not_contains "${out}" "hunter2" "reason"
	out="$(printf 'A=%s\nsops_password=hunter2\nsops_mac=%s\nsops_version=3.13.3\n' "${ENC}" "${ENC}" | sgf_doc_problem dotenv)"
	assert_contains "${out}" "line 2" "reason names the line"
	assert_not_contains "${out}" "hunter2" "reason"
	assert_eq "$(sops_doc '"mac": "'"${ENC}"'", "version": "3.13.3"' | sgf_doc_problem json)" "" "no reason for a good document"
}

# The check must stay fast on a large file: bash pattern matching on a
# whole document is quadratic, and half a megabyte took minutes.
test_lib_json_document_check_is_linear() {
	load_lib
	local big doc
	big="$(awk 'BEGIN { for (i = 0; i < 40000; i++) printf "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2" }')"
	doc="$(envelope "ENC[AES256_GCM,data:${big},iv:AAAA,tag:BBBB,type:str]")"
	assert_eq "$((${#doc} > 2000000))" "1" "the test document is over 2 MB"

	SECONDS=0
	is sgf_is_sops_doc json "${doc}"
	is_not sgf_is_sops_doc dotenv "${doc}"
	is_not sgf_is_sops_doc json "${big}"
	[[ "${SECONDS}" -lt 30 ]] || fail "checking a 2 MB document took ${SECONDS}s"
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

	# sops_ does not make a key metadata: only the names sops writes do.
	# The first two are the examples from the review of this check.
	is_not sgf_is_sops_doc dotenv "${doc}sops_password=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_API_TOKEN=plaintext"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_age__list_0__map_note=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_age__list_x__map_enc=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_vault__list_0__map_enc=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_age__list_0__map_context__map_pw=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_age__list_0__map_arn=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "${doc}sops_lastmodified_x=hunter2"$'\n'
	is_not sgf_is_sops_doc dotenv "A=${ENC}"$'\nsops_mac=hunter2\nsops_version=3.13.3\n'
	is sgf_is_sops_doc dotenv "${doc}sops_API_TOKEN=${ENC}"$'\n'    # encrypted, so nothing leaks
	# what sops writes for AWS KMS, an encryption context and key groups
	is sgf_is_sops_doc dotenv "${doc}"$'sops_kms__list_0__map_arn=arn:aws:kms:eu-central-1:111111111111:key/0000\nsops_kms__list_0__map_aws_profile=\nsops_kms__list_0__map_created_at=2026-01-01T00:00:00Z\nsops_kms__list_0__map_enc=AQICAH==\nsops_kms__list_0__map_role=arn:aws:iam::111111111111:role/r\nsops_kms__list_12__map_context__map_Env=prod\nsops_lastmodified=2026-01-01T00:00:00Z\nsops_unencrypted_suffix=_unencrypted\nsops_shamir_threshold=2\nsops_mac_only_encrypted=true\nsops_encrypted_regex=^(A|B)$\nsops_key_groups__list_1__map_age__list_0__map_recipient=age1qqqq\nsops_key_groups__list_1__map_kms__list_0__map_context__map_Team=core\nsops_pgp__list_0__map_fp=ABCDEF\nsops_hc_vault__list_0__map_engine_path=transit\n'
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

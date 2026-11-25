#!/usr/bin/env bash
# lib.sh: the document checks, without sops.
# shellcheck disable=SC2154  # SGF_TOOL_DIR comes from tests/run.sh

# Encrypted values shaped like the ones sops writes: data in base64, an
# iv of 32 bytes and a tag of 16 (44 and 24 characters of base64).
IV='aK0NDUmGF5rgQKERiDsl8ZmCs+7aY6DdOPGhvm21fiw='
TAG='jZYZLFyNneDOtZnXYZjGaQ=='
ENC="ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG},type:str]"
ENC_COMMENT="ENC[AES256_GCM,data:NXZXkGPhZlPbJQ==,iv:${IV},tag:${TAG},type:comment]"

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
	is_not sgf_is_sops_doc json "$(envelope "ENC[AES256_GCM,data:a bc,iv:${IV},tag:${TAG},type:str]")"
	is_not sgf_is_sops_doc json "$(envelope "ENC[AES256_GCM,data:a\\nb,iv:${IV},tag:${TAG},type:str]")"
	is_not sgf_is_sops_doc json "$(envelope 'ENC[AES256_GCM,data:abc]')"
	is_not sgf_is_sops_doc json "$(envelope 'hunter2')"
}

# in_every_place <is|is_not> <ENC[...] value> : the value as "data" and as
# "mac" of a json document, and as a value, a comment and sops_mac of a
# dotenv document. Everything else in the documents is in order.
in_every_place() {
	local verdict="$1" token="$2" meta=$'\nsops_version=3.13.3\n'
	"${verdict}" sgf_is_sops_doc json "$(envelope "${token}")"
	"${verdict}" sgf_is_sops_doc json '{"data":"'"${ENC}"'","sops":{"mac":"'"${token}"'","version":"3.13.3"}}'
	"${verdict}" sgf_is_sops_doc dotenv "A=${token}"$'\n'"sops_mac=${ENC}${meta}"
	"${verdict}" sgf_is_sops_doc dotenv "#${token}"$'\n'"A=${ENC}"$'\n'"sops_mac=${ENC}${meta}"
	"${verdict}" sgf_is_sops_doc dotenv "A=${ENC}"$'\n'"sops_mac=${token}${meta}"
}

# An ENC[...] value is checked as a whole (audit A-16), not for its
# alphabet: the fields in the order sops writes them, data in padded
# base64, an iv of 32 bytes and a tag of 16 (44 and 24 characters), a
# type sops can decrypt, and nothing after the closing bracket. The first
# two are the examples from the review of this check: a password in the
# place of the ciphertext, and a password after a real value.
test_lib_enc_token_is_checked_as_a_whole() {
	load_lib
	local token
	for token in \
		'ENC[AES256_GCM,data:MyPassword123,iv:x,tag:y,type:str]' \
		"${ENC}hunter2]" \
		"ENC[AES256_GCM,data:MyPassword123,iv:${IV},tag:${TAG},type:str]" \
		"ENC[AES256_GCM,data:hunter2_,iv:${IV},tag:${TAG},type:str]" \
		"ENC[AES256_GCM,data:ab=c,iv:${IV},tag:${TAG},type:str]" \
		"ENC[AES256_GCM,data:abc+/w==,tag:${TAG},iv:${IV},type:str]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG},type:str,pw:hunter2]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV:1},tag:${TAG},type:str]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV%=}A,tag:${TAG},type:str]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG:2},type:str]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG%=}A,type:str]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG},type:hunter]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG},type:]" \
		"ENC[AES256_GCM,data:abc+/w==,iv:${IV},tag:${TAG},type:str]${ENC}" \
		"ENC[AES256_GCM,data:,iv:${IV},tag:${TAG},type:str]"; do
		in_every_place is_not "${token}"
	done

	# What sops writes: any length of data (with or without padding), and
	# the types it encrypts. An empty value is no ENC[...] value at all:
	# sops writes "" (json) or KEY= and # (dotenv), see the tests above.
	for token in "${ENC}" "${ENC_COMMENT}" \
		"ENC[AES256_GCM,data:2NFR,iv:${IV},tag:${TAG},type:float]" \
		"ENC[AES256_GCM,data:Bl36N6NEn2HbeGo=,iv:${IV},tag:${TAG},type:str]" \
		"ENC[AES256_GCM,data:AQ==,iv:${IV},tag:${TAG},type:int]" \
		"ENC[AES256_GCM,data:8nzB5Q==,iv:${IV},tag:${TAG},type:bool]" \
		"ENC[AES256_GCM,data:KJ/kQeEdkF3JdCnQAgY4Xxc1xnE=,iv:${IV},tag:${TAG},type:time]" \
		"ENC[AES256_GCM,data:AAAA,iv:${IV},tag:${TAG},type:bytes]"; do
		in_every_place is "${token}"
	done
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
	doc="$(envelope "ENC[AES256_GCM,data:${big},iv:${IV},tag:${TAG},type:str]")"
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

# The paths in the commands a message prints: quoted for a shell, and,
# where git would take them as a pattern, marked :(literal).
test_lib_paste_path_and_pathspec() {
	load_lib
	assert_eq "$(sgf_paste_path "/r/a b'c.env")" "'/r/a b'\\''c.env'" "a path with a blank and a quote"
	assert_eq "$(sgf_paste_pathspec "/r/a b'c.env")" "'/r/a b'\\''c.env'" "no wildcard: the path as it is"
	assert_eq "$(sgf_paste_pathspec '/r/[ab].env')" "':(literal)/r/[ab].env'" "brackets"
	assert_eq "$(sgf_paste_pathspec '/r/x*.env')" "':(literal)/r/x*.env'" "a star"
	assert_eq "$(sgf_paste_pathspec '/r/x?.env')" "':(literal)/r/x?.env'" "a question mark"
	assert_eq "$(sgf_paste_pathspec '/r/x\y.env')" "':(literal)/r/x\\y.env'" "a backslash"

	# Pasted, the quoted string is the path again, byte for byte. A
	# trailing newline is part of the name: dropped, `rm '<path>'` would
	# name another file (".env.prod" for ".env.prod<newline>").
	local p x
	# shellcheck disable=SC1003,SC2016  # the backslashes, $(...) and backticks are meant literally
	for p in "/r/a b'c.env" "/r/'" "/r/''" "/r/\\'" '/r/x\y' '/r/x\\' \
		$'/r/.env.prod\n' $'/r/.env.prod\n\n' $'/r/a\nb.env' $'\n' \
		'-rf' '/r/$(touch pwned)' '/r/`touch pwned`' '/r/$HOME' '/r/*?[x]' \
		'/r/a&b' $'/r/\xff\'' ''; do
		x=""
		eval "x=$(sgf_paste_path "${p}")"
		assert_eq "${x}" "${p}" "sgf_paste_path, pasted back: $(printf '%q' "${p}")"
		x=""
		eval "x=$(sgf_paste_pathspec "${p}")"
		case "${p}" in
		*[\*\?\[\\]*) assert_eq "${x}" ":(literal)${p}" "sgf_paste_pathspec, pasted back: $(printf '%q' "${p}")" ;;
		*) assert_eq "${x}" "${p}" "sgf_paste_pathspec, pasted back: $(printf '%q' "${p}")" ;;
		esac
	done
	[[ ! -e pwned ]] || fail "a name was run as a command"
}

# On Windows git prints an absolute path with a drive letter, C:/Users/...
# Taken for a relative path, a machine-wide core.hooksPath of ~/.githooks
# became a directory inside the repository: install.sh wrote the hooks
# there, where git never runs them, instead of leaving that shared
# directory alone (and the guard skipped the global attributes file).
test_lib_absolute_path() {
	load_lib
	is sgf_is_absolute /home/me/.githooks
	is_not sgf_is_absolute .git/hooks
	is_not sgf_is_absolute ./hooks
	is_not sgf_is_absolute ''
	OSTYPE=msys
	is sgf_is_absolute C:/Users/me/.githooks
	is sgf_is_absolute 'C:\Users\me\.githooks'
	is sgf_is_absolute /c/Users/me/.githooks
	is_not sgf_is_absolute .git/hooks
	is_not sgf_is_absolute C:hooks
	is sgf_is_absolute '\\server\share\attributes'
	is sgf_is_absolute //server/share/attributes
	is_not sgf_is_absolute '\hooks'
	OSTYPE=linux-gnu
	is_not sgf_is_absolute C:/Users/me/.githooks
	is_not sgf_is_absolute '\\server\share\attributes'
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

# ── Which keys a document names, and the hint for them ────
test_lib_key_types_and_credential_hint() {
	load_lib
	local doc
	doc='{
	"data": "'"${ENC}"'",
	"sops": {
		"kms": [
			{
				"arn": "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000",
				"created_at": "2026-01-01T00:00:00Z",
				"enc": "AQICAH"
			}
		],
		"age": [
			{
				"recipient": "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				"enc": "-----BEGIN AGE ENCRYPTED FILE-----\n"
			}
		],
		"mac": "'"${ENC}"'",
		"version": "3.13.3"
	}
}'
	assert_eq "$(printf '%s\n' "${doc}" | sgf_doc_key_types | tr '\n' ' ')" "age kms " "key types of a json document"

	doc="A=${ENC}
sops_gcp_kms__list_0__map_resource_id=projects/p/locations/global/keyRings/r/cryptoKeys/k
sops_key_groups__list_0__map_pgp__list_0__map_fp=0123456789ABCDEF
sops_hc_vault__list_0__map_vault_address=https://vault.example.invalid
sops_azure_kv__list_0__map_vault_url=https://v.vault.azure.net
x__map_recipient=${ENC}
sops_mac=${ENC}
sops_version=3.13.3"
	assert_eq "$(printf '%s\n' "${doc}" | sgf_doc_key_types | tr '\n' ' ')" \
		"gcp_kms azure_kv hc_vault pgp " "key types of a dotenv document"
	assert_eq "$(printf 'A=1\n' | sgf_doc_key_types)" "" "key types of a plaintext file"

	assert_contains "$(sgf_credential_hint '> ' kms)" "> AWS KMS: sign in again (aws sso login" "hint for AWS KMS"
	assert_eq "$(sgf_credential_hint '' kms age | wc -l | tr -d ' ')" "2" "one line per key type"
	# No key type known: every kind is listed, none is favoured.
	local all
	all="$(sgf_credential_hint '')"
	local word
	for word in "age:" "AWS KMS:" "GCP KMS:" "Azure Key Vault:" "HashiCorp Vault:" "PGP:"; do
		assert_contains "${all}" "${word}" "hint without a key type"
	done
}

# The keys a document names, for the line the clean filter prints when a
# re-encryption changes them (audit A-15): every kind of key, in key
# groups too, from json in any layout and from dotenv, the same list.
test_lib_doc_keys() {
	load_lib
	local json dotenv want
	# One line: sgf_doc_keys must not depend on the layout sops writes.
	json='{"data": "'"${ENC}"'", "sops": {"key_groups": [{"age": [{"enc": "x", "recipient": "age1aaaa"}], "kms": [{"arn": "arn:aws:kms:eu-central-1:111111111111:key/k1", "role": "", "context": {"Env": "prod"}, "created_at": "t", "enc": "x", "aws_profile": ""}], "gcp_kms": [{"resource_id": "projects/p/locations/global/keyRings/r/cryptoKeys/k", "created_at": "t", "enc": "x"}]}, {"azure_kv": [{"vault_url": "https://v.vault.azure.net", "name": "k", "version": "1", "created_at": "t", "enc": "x"}], "hc_vault": [{"vault_address": "https://vault.example.invalid:8200", "engine_path": "transit", "key_name": "k", "created_at": "t", "enc": "x"}], "pgp": [{"created_at": "t", "enc": "x", "fp": "0123456789ABCDEF"}], "hckms": [{"key_id": "region:id", "created_at": "t", "enc": "x"}], "age": [{"recipient": "age1aaaa", "enc": "x"}]}], "shamir_threshold": 2, "mac": "'"${ENC}"'", "version": "3.13.3"}}'
	dotenv="A=${ENC}
sops_key_groups__list_0__map_age__list_0__map_enc=x
sops_key_groups__list_0__map_age__list_0__map_recipient=age1aaaa
sops_key_groups__list_0__map_kms__list_0__map_arn=arn:aws:kms:eu-central-1:111111111111:key/k1
sops_key_groups__list_0__map_kms__list_0__map_context__map_Env=prod
sops_key_groups__list_0__map_gcp_kms__list_0__map_resource_id=projects/p/locations/global/keyRings/r/cryptoKeys/k
sops_key_groups__list_1__map_azure_kv__list_0__map_name=k
sops_key_groups__list_1__map_azure_kv__list_0__map_vault_url=https://v.vault.azure.net
sops_key_groups__list_1__map_hc_vault__list_0__map_engine_path=transit
sops_key_groups__list_1__map_hc_vault__list_0__map_key_name=k
sops_key_groups__list_1__map_hc_vault__list_0__map_vault_address=https://vault.example.invalid:8200
sops_key_groups__list_1__map_pgp__list_0__map_fp=0123456789ABCDEF
sops_key_groups__list_1__map_hckms__list_0__map_key_id=region:id
sops_key_groups__list_1__map_age__list_0__map_recipient=age1aaaa
sops_mac=${ENC}
sops_shamir_threshold=2
sops_version=3.13.3"
	want=$'1\tage age1aaaa\n1\tgcp_kms projects/p/locations/global/keyRings/r/cryptoKeys/k\n1\tkms arn:aws:kms:eu-central-1:111111111111:key/k1\n2\tage age1aaaa\n2\tazure_kv https://v.vault.azure.net/keys/k\n2\thc_vault https://vault.example.invalid:8200/v1/transit/keys/k\n2\thckms region:id\n2\tpgp 0123456789ABCDEF'
	is sgf_is_sops_doc json "${json}"
	is sgf_is_sops_doc dotenv "${dotenv}"$'\n'
	assert_eq "$(printf '%s\n' "${json}" | sgf_doc_keys json | sort)" "${want}" "keys of a json document"
	assert_eq "$(printf '%s\n' "${dotenv}" | sgf_doc_keys dotenv | sort)" "${want}" "keys of a dotenv document"

	# Without key_groups: the one group is group 1.
	assert_eq "$(sops_doc '"age": [{"recipient": "age1bbbb", "enc": "x"}], "mac": "'"${ENC}"'", "version": "3.13.3"' | sgf_doc_keys json)" \
		$'1\tage age1bbbb' "keys of a json document without key groups"
	assert_eq "$(printf 'sops_age__list_0__map_recipient=age1bbbb\n' | sgf_doc_keys dotenv)" \
		$'1\tage age1bbbb' "keys of a dotenv document without key groups"
	# What is shown is printable: the document can come from anyone.
	assert_eq "$(printf 'sops_age__list_0__map_recipient=age1\033[2Jx\n' | sgf_doc_keys dotenv)" \
		$'1\tage age1?[2Jx' "a control character in a recipient"
	# Not a SOPS document: no list, and a failure.
	is_not sgf_doc_keys json <<<'{"data": "", "sops": {"age": [{"recipient": "age1", "x": "y"}]}}'
}

# ── Content with NUL bytes ────
test_lib_counts_nul_bytes_and_keeps_the_content() {
	load_lib
	# capture <printf format> : sets SGF_CONTENT and SGF_NUL_COUNT
	capture() {
		# shellcheck disable=SC2059  # the format is the test input
		SGF_CAPTURED="$(printf "$1" | sgf_cat_counting_nuls 2>/dev/null)"
		sgf_split_counted
	}
	capture 'A=1\n'
	assert_eq "${SGF_NUL_COUNT}:${SGF_CONTENT}" $'0:A=1\n' "plain text"
	capture ''
	assert_eq "${SGF_NUL_COUNT}:${SGF_CONTENT}" "0:" "empty input"
	capture 'three newlines\n\n\n'
	assert_eq "${SGF_NUL_COUNT}:${SGF_CONTENT}" $'0:three newlines\n\n\n' "trailing newlines are kept"
	# Content that looks like the trailer the capture ends in.
	capture 'ends in x'
	assert_eq "${SGF_NUL_COUNT}:${SGF_CONTENT}" "0:ends in x" "content ending in x"
	capture 'x12'
	assert_eq "${SGF_NUL_COUNT}:${SGF_CONTENT}" "0:x12" "content that looks like a trailer"
	capture 'a\0b\0\n'
	assert_eq "${SGF_NUL_COUNT}" "2" "NUL bytes are counted"
	capture '\0'
	assert_eq "${SGF_NUL_COUNT}" "1" "a single NUL byte"

	# A capture that was cut short is not taken for content.
	SGF_CAPTURED="123"
	is_not sgf_split_counted
	SGF_CAPTURED=""
	is_not sgf_split_counted
}

# A blob with a NUL byte is never a SOPS document: the awk of macOS does
# not look past a NUL byte on its line (audit A-12). The check of a blob
# reads it once, and still tells "cannot read" (2) from "not one" (1).
test_lib_blob_with_a_nul_byte_is_not_a_document() {
	load_lib
	git_init repo
	cd repo || exit 1
	local good dotenv status
	good="$(envelope "${ENC}" | git hash-object -w --stdin)"
	dotenv="$(printf 'A=%s\nsops_mac=%s\nsops_version=3.13.3\n' "${ENC}" "${ENC}" | git hash-object -w --stdin)"
	is sgf_blob_is_sops_doc json "${good}"
	is sgf_blob_is_sops_doc dotenv "${dotenv}"
	assert_eq "$(sgf_blob_problem json "${good}")" "" "problem of a good blob"

	local nul_json nul_dotenv
	nul_json="$({
		envelope "${ENC}"
		printf '\000"pw": "hunter2"\n'
	} | git hash-object -w --stdin)"
	nul_dotenv="$({
		printf 'A=%s\nsops_mac=%s\nsops_version=3.13.3\n' "${ENC}" "${ENC}"
		printf 'B=%s\000PW=hunter2\n' "${ENC}"
	} | git hash-object -w --stdin)"
	is_not sgf_blob_is_sops_doc json "${nul_json}"
	is_not sgf_blob_is_sops_doc dotenv "${nul_dotenv}"
	assert_eq "$(sgf_blob_problem json "${nul_json}")" "it holds NUL bytes (1), which a SOPS document never has" "problem"
	assert_eq "$(sgf_blob_problem dotenv "${nul_dotenv}")" "it holds NUL bytes (1), which a SOPS document never has" "problem"

	status=0
	sgf_blob_is_sops_doc json 0123456789abcdef0123456789abcdef01234567 || status=$?
	assert_eq "${status}" "2" "status for a blob that is not there"
}

# ── The version line of a checkout, read as text ────
# bounded <seconds> <command...> : run the command, kill it when it takes
# longer. A reader that hangs must fail the test, not the test run.
bounded() {
	local limit="$1" pid dog rc=0
	shift
	"$@" &
	pid=$!
	(
		sleep "${limit}"
		kill -9 "${pid}" 2>/dev/null
	) >/dev/null 2>&1 &
	dog=$!
	wait "${pid}" 2>/dev/null || rc=$?
	kill "${dog}" 2>/dev/null || true
	wait "${dog}" 2>/dev/null || true
	return "${rc}"
}

# The installed copy reads lib.sh of the checkout at every git command,
# and a checked-out branch decides what is at that path. Whatever it is,
# the reader returns at once and prints a version number or nothing.
test_lib_version_of_reads_a_bounded_piece_of_a_regular_file() {
	load_lib
	assert_eq "$(sgf_version_of "${SGF_TOOL_DIR}/lib.sh")" "${SGF_VERSION}" "the version line of the real lib.sh"

	printf '#!/bin/sh\nSGF_VERSION="12.34.56"\n' >plain.sh
	assert_eq "$(sgf_version_of plain.sh)" "12.34.56" "a plain file"
	assert_eq "$(sgf_version_of no-such-file)" "" "a file that is not there"

	local out rc

	# A FIFO nobody writes to: opening it would block for ever.
	mkfifo pipe.sh
	rc=0
	out="$(bounded 10 sgf_version_of pipe.sh)" || rc=$?
	assert_eq "${rc}:${out}" "0:" "a FIFO"

	# One endless line, and the version line only after it: not reached.
	{
		awk 'BEGIN { for (i = 0; i < 20000; i++) printf "x" }'
		printf '\nSGF_VERSION="9.9.9"\n'
	} >long.sh
	assert_eq "$(sgf_version_of long.sh)" "" "a version line beyond the part that is read"

	# NUL bytes do not get in the way, and nothing but a version is printed.
	printf 'a\0b\nSGF_VERSION="1.2.3"\n' >nul.sh
	assert_eq "$(sgf_version_of nul.sh)" "1.2.3" "a file with NUL bytes"
	# shellcheck disable=SC2016  # must stay unexpanded
	printf 'SGF_VERSION="$(touch PWNED)"\n' >evil.sh
	assert_eq "$(sgf_version_of evil.sh)" "" "a version line that is no version"
	[[ ! -e PWNED ]] || fail "the version line was executed"

	needs_symlinks
	# A symlink to a device that never ends.
	ln -s /dev/zero endless.sh
	rc=0
	out="$(bounded 10 sgf_version_of endless.sh)" || rc=$?
	assert_eq "${rc}:${out}" "0:" "a symlink to /dev/zero"

	# A symlink to a real file with a version line: not followed either.
	ln -s plain.sh link.sh
	assert_eq "$(sgf_version_of link.sh)" "" "a symlink to a regular file"
}

# A symlink anywhere below the root, in a directory's place or in the
# file's, is found; one above the root is not looked at (audit A-14).
test_lib_through_symlink() {
	needs_symlinks
	load_lib
	mkdir -p root/a/b elsewhere/b
	: >root/a/b/file
	: >root/top
	: >elsewhere/b/file
	ln -s ../elsewhere root/linked-dir
	ln -s ../elsewhere/b/file root/a/linked-file
	ln -s root via-link
	is_not sgf_through_symlink root a/b/file
	is_not sgf_through_symlink root top
	is_not sgf_through_symlink root a/missing/file
	is sgf_through_symlink root linked-dir/b/file
	is sgf_through_symlink root linked-dir
	is sgf_through_symlink root a/linked-file
	is_not sgf_through_symlink via-link a/b/file
	is sgf_through_symlink via-link linked-dir/b/file
	is sgf_through_symlink "${PWD}/root" 'linked-dir/b/file'
}

# ── What the clean filter remembers (issue #21) ────
# The HMAC is computed from a plain SHA-256, as RFC 2104 says, so that
# the key is never an argument of a process. It must give the HMAC-SHA256
# of the test vectors of RFC 4231 (cases 1, 2 and 4) with every tool it
# can use.
test_lib_hmac_sha256_matches_rfc_4231() {
	load_lib
	local tool tested=""
	for tool in sha256sum openssl shasum; do
		command -v "${tool}" >/dev/null 2>&1 || continue
		SGF_SHA256_TOOL="${tool}"
		tested="${tested} ${tool}"
		sgf_hmac_init 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
		assert_eq "$(sgf_hmac_sha256 printf 'Hi There')" \
			b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 "case 1 (${tool})"
		sgf_hmac_init 4a656665
		assert_eq "$(sgf_hmac_sha256 printf '%s' 'what do ya want for nothing?')" \
			5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 "case 2 (${tool})"
		sgf_hmac_init 0102030405060708090a0b0c0d0e0f10111213141516171819
		assert_eq "$(sgf_hmac_sha256 awk 'BEGIN { for (i = 0; i < 50; i++) printf "%c", 205 }')" \
			82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b "case 4 (${tool})"
	done
	[[ -n "${tested}" ]] || skip "no sha256sum, openssl or shasum on PATH"
	echo "tested with:${tested}"

	# A key that is not hex, or longer than a block, is refused.
	is_not sgf_hmac_init "not hex"
	is_not sgf_hmac_init "$(printf '%0130d' 0)"
	is_not sgf_hmac_init ""
}

# The cache directory and its key must be the user's own, not a symlink,
# and closed to the group and others. (A directory of another user can
# only be had from the system: the root directory stands in for it.)
test_lib_cache_private() {
	# chmod is the test: where the file system keeps no modes (Windows)
	# there is nothing to test.
	needs_file_modes
	load_lib
	mkdir -m 700 own
	is sgf_private own
	chmod 750 own
	is_not sgf_private own
	chmod 701 own
	is_not sgf_private own
	chmod 700 own
	(umask 077 && : >own/key)
	is sgf_private own own/key
	chmod 640 own/key
	is_not sgf_private own own/key
	chmod 600 own/key
	ln -s own link
	is_not sgf_private link
	ln -s key own/link
	is_not sgf_private own/link
	if [[ "${EUID}" -ne 0 ]]; then
		is_not sgf_private /
	fi
}

# Entries older than SGF_CACHE_TTL are not given and are removed; so are
# temporary files left behind. More than SGF_CACHE_MAX entries: all go.
test_lib_cache_sweeps_old_and_surplus_entries() {
	needs_cache
	load_lib
	local check=0123456789abcdef0123456789abcdef oid=0123456789012345678901234567890123456789 i n
	mkdir -p common
	(
		sgf_cache_open common || fail "the cache cannot be opened"
		sgf_cache_put aaaa "${check}" "${oid}" || fail "sgf_cache_put"
		assert_eq "$(sgf_cache_get aaaa "${check}")" "${oid} 0" "a fresh entry"
		is_not sgf_cache_get aaaa ffffffffffffffffffffffffffffffff
		[[ ! -e "${SGF_CACHE_DIR}/e-aaaa" ]] || fail "an entry of another question is kept"

		sgf_cache_put aaaa "${check}" "${oid}"
		printf 'sgf-cache 1 %s %s %s\n' "${check}" "$((SGF_CACHE_NOW - SGF_CACHE_TTL))" "${oid}" >"${SGF_CACHE_DIR}/e-old"
		printf 'garbage\n' >"${SGF_CACHE_DIR}/e-bad"
		: >"${SGF_CACHE_DIR}/tmp.$((SGF_CACHE_NOW - SGF_CACHE_TTL)).1.2"
		: >"${SGF_CACHE_DIR}/tmp.${SGF_CACHE_NOW}.1.2"
		is_not sgf_cache_get old "${check}"
		[[ ! -e "${SGF_CACHE_DIR}/e-old" ]] || fail "an old entry is kept after a read"
		printf 'sgf-cache 1 %s %s %s\n' "${check}" "$((SGF_CACHE_NOW - SGF_CACHE_TTL))" "${oid}" >"${SGF_CACHE_DIR}/e-old"
		sgf_cache_sweep
		assert_eq "$(cd "${SGF_CACHE_DIR}" && echo e-* tmp.*)" "e-aaaa tmp.${SGF_CACHE_NOW}.1.2" "what the sweep keeps"

		SGF_CACHE_MAX=5
		for ((i = 0; i < 9; i++)); do
			sgf_cache_put "n${i}" "${check}" "${oid}" || fail "sgf_cache_put n${i}"
		done
		n="$(cd "${SGF_CACHE_DIR}" && set -- e-* && echo $#)"
		[[ "${n}" -le 6 ]] || fail "${n} entries kept with SGF_CACHE_MAX=5"
	) || exit 1

	# The sweep runs on its own once per SGF_CACHE_TTL, when the cache is
	# opened.
	(
		sgf_cache_open common
		printf 'sgf-cache 1 %s %s %s\n' "${check}" "$((SGF_CACHE_NOW - SGF_CACHE_TTL))" "${oid}" >"${SGF_CACHE_DIR}/e-old"
		printf '%s\n' "$((SGF_CACHE_NOW - SGF_CACHE_TTL))" >"${SGF_CACHE_DIR}/swept"
	)
	(
		sgf_cache_open common
		[[ ! -e "${SGF_CACHE_DIR}/e-old" ]] || fail "the old entry is still there after the next open"
	) || exit 1
}

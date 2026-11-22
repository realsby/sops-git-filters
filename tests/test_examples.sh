#!/usr/bin/env bash
# The files under examples/ are what people copy. They must do what
# their comments say (audit N5).
# shellcheck disable=SC2154  # OUT/RC/TOOL/SGF_TOOL_DIR come from tests/lib.sh and run.sh

DOTENV_NAMES=".env .env.local .env.production prod.env deep/er/.env deep/er/.env.local deep/prod.env"

# The example patterns reach every dotenv name, at every depth, and leave
# the template alone. Before, only ".env" was covered: .env.local or
# prod.env were committed in plaintext without a word.
test_examples_gitattributes_covers_the_dotenv_names() {
	git init -q repo
	cd repo || exit 1
	cp "${SGF_TOOL_DIR}/examples/gitattributes" .gitattributes

	local name attr
	for name in ${DOTENV_NAMES}; do
		for attr in filter diff merge; do
			assert_eq "$(git check-attr "${attr}" -- "${name}")" "${name}: ${attr}: sops" "attribute of ${name}"
		done
	done
	# The template: no filter, and an ordinary text file for diff and merge
	# ("unset" would make it binary).
	for name in .env.example deep/.env.example; do
		for attr in filter diff merge; do
			assert_eq "$(git check-attr "${attr}" -- "${name}")" "${name}: ${attr}: unspecified" "attribute of ${name}"
		done
	done
	for name in README.md env environment.txt src/env.js; do
		assert_eq "$(git check-attr filter -- "${name}")" "${name}: filter: unspecified" "attribute of ${name}"
	done
}

# The creation rule of the example .sops.yaml matches the same names, or
# `git add` of such a file would fail for want of a rule.
test_examples_sops_yaml_rule_matches_the_same_names() {
	local regex name
	regex="$(sed -n 's/^ *- path_regex: //p' "${SGF_TOOL_DIR}/examples/sops.yaml" | head -1)"
	assert_ne "${regex}" "" "the first path_regex of examples/sops.yaml"
	for name in ${DOTENV_NAMES}; do
		printf '%s\n' "${name}" | grep -Eq -- "${regex}" || fail "${regex} does not match ${name}"
	done
	for name in environment.txt src/env.js; do
		if printf '%s\n' "${name}" | grep -Eq -- "${regex}"; then
			fail "${regex} matches ${name}"
		fi
	done
}

# End to end with the example patterns: the variants are encrypted, the
# template is stored as it is, and the guard agrees.
test_examples_gitattributes_end_to_end() {
	new_repo repo
	cp "${SGF_TOOL_DIR}/examples/gitattributes" .gitattributes
	printf 'TOKEN=local-secret\n' >.env.local
	printf 'TOKEN=prod-secret\n' >prod.env
	printf 'TOKEN=put-your-token-here\n' >.env.example
	git add .gitattributes .env.local prod.env .env.example
	git commit -q -m "dotenv files under other names"

	assert_contains "$(stored .env.local)" 'ENC[AES256_GCM,data:' "stored .env.local"
	assert_not_contains "$(stored .env.local)" "local-secret" "stored .env.local"
	assert_contains "$(stored prod.env)" 'ENC[AES256_GCM,data:' "stored prod.env"
	assert_not_contains "$(stored prod.env)" "prod-secret" "stored prod.env"
	assert_eq "$(stored .env.example)" "TOKEN=put-your-token-here" "the template is stored as it is"

	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "encryption-guard.sh exit status"

	printf 'TOKEN=put-your-token-here\nMORE=\n' >.env.example
	assert_contains "$(git diff -- .env.example)" "+MORE=" "git diff of the template is a text diff"
}

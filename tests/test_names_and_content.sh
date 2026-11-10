#!/usr/bin/env bash
# File names and file contents that tend to break shell tools.
# shellcheck disable=SC2154  # OUT/RC/TOOL/AGE_* come from tests/lib.sh
# shellcheck disable=SC2016  # the $(...) and backticks below are meant literally

# Names with spaces, quotes, shell syntax, glob characters, a newline, a
# leading dash, and one that looks like git's ":<stage>:<path>" syntax.
# They must be encrypted, come back byte for byte, and run nothing.
test_names_awkward_file_names_round_trip() {
	new_repo origin
	printf 'secrets/** filter=sops diff=sops\n*.secret filter=sops diff=sops\n' >.gitattributes
	git add .gitattributes
	git commit -q -m "attributes"

	mkdir secrets
	local names=(
		'with space.txt'
		"quote'single.txt"
		'quote"double.txt'
		'dollar$(touch PWNED1).txt'
		'back`touch PWNED2`tick.txt'
		'semi;touch PWNED3;.txt'
		'-rf'
		'--output=x'
		'glob*star[1]?.txt'
		$'new\nline.txt'
		$'tab\there.txt'
		'pipe|amp&.txt'
		'#hash !bang.txt'
		'%f percent %s.txt'
		'back\slash.txt'
	)
	local name i=0
	for name in "${names[@]}"; do
		i=$((i + 1))
		printf 'SECRET-%s\n' "${i}" >"secrets/${name}"
	done
	printf 'SECRET-top\n' >'2:top.secret'
	git add secrets './2:top.secret'
	git commit -q -m "awkward names"

	run "${TOOL}/encryption-guard.sh"
	assert_eq "${RC}" "0" "guard exit status"

	# Every stored blob is ciphertext.
	local record id count=0
	while IFS= read -r -d '' record; do
		id="${record%%$'\t'*}"
		id="${id#* }"
		id="${id%% *}"
		count=$((count + 1))
		if git cat-file blob "${id}" | grep -q 'SECRET-'; then
			fail "plaintext in the blob of: ${record#*$'\t'}"
		fi
	done < <(git ls-files -s -z -- secrets './2:top.secret')
	assert_eq "${count}" "16" "number of managed files"

	# Round trip: move the working copies away, check them out again.
	cp -R secrets ../expected-secrets
	cp './2:top.secret' ../expected-top
	mv secrets ../moved-secrets
	mv './2:top.secret' ../moved-top
	git checkout -- .
	diff -r secrets ../expected-secrets
	cmp './2:top.secret' ../expected-top
	assert_eq "$(git status --porcelain)" "" "git status after checkout"
	"${TOOL}/harden-permissions.sh" --quiet
	cd ..

	# The same through a fresh clone and install.sh's decrypt pass.
	fresh_clone origin clone
	run "${TOOL}/install.sh"
	assert_eq "${RC}" "0" "install.sh exit status"
	diff -r secrets ../expected-secrets
	cmp './2:top.secret' ../expected-top
	assert_eq "$(git status --porcelain)" "" "git status after install.sh"
	cd ..

	# No file name was ever run as a command.
	assert_eq "$(find . -name 'PWNED*' | wc -l | tr -d ' ')" "0" "files created by injected commands"
}

test_content_json_round_trips_byte_for_byte() {
	new_repo repo
	printf 'caf\351=latin1\n\377\376 not utf-8\n' >latin1.secret
	printf 'no trailing newline' >nonl.secret
	printf 'three trailing newlines\n\n\n' >manynl.secret
	printf 'A=1\r\nB=2\r\n' >crlf.secret
	printf '  \t \n' >blank.secret
	printf '%s\n' '-n' '-e \x41' '%s %d \\n $HOME `id` $(id)' >format.secret
	awk 'BEGIN { for (i = 0; i < 20000; i++) print "line " i " of a larger file" }' >large.secret

	mkdir ../expected ../moved
	cp ./*.secret ../expected/
	git add ./*.secret
	git commit -q -m "edge cases"
	mv ./*.secret ../moved/
	git checkout -- .

	local file
	for file in ../expected/*.secret; do
		cmp "${file}" "$(basename "${file}")" || fail "$(basename "${file}") changed in the round trip"
	done
	assert_eq "$(git status --porcelain)" "" "git status"
}

# With diff=sops, git diff and git log -p show plaintext; what leaves the
# machine (patches, objects) stays ciphertext.
test_diff_is_plaintext_but_patches_are_not() {
	new_repo repo
	printf 'TOKEN=v1\n' >.env
	git add .env
	git commit -q -m "v1"
	printf 'TOKEN=v2\n' >.env

	assert_contains "$(git diff)" "+TOKEN=v2" "git diff"
	git commit -q -am "v2"
	assert_contains "$(git log -p -1 --format=%s)" "+TOKEN=v2" "git log -p"
	assert_not_contains "$(git format-patch -1 --stdout)" "TOKEN=v2" "git format-patch"
	assert_not_contains "$(git cat-file -p HEAD:.env)" "TOKEN=v2" "the committed blob"
}

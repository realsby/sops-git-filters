#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Encryption Guard (pre-commit hook)                         ║
# ║                                                                  ║
# ║  Second line of defense behind the clean filter: blocks a        ║
# ║  commit if any file managed by the "sops" git filter is staged   ║
# ║  in plaintext. Catches the cases the filter can't: a clone       ║
# ║  where the filters were never configured, a bypassed filter,     ║
# ║  or an index entry written before the filter existed.            ║
# ║                                                                  ║
# ║  Detection: every SOPS-encrypted blob contains ENC[AES256_GCM    ║
# ║  ciphertext markers (both the values and the MAC are ENC-        ║
# ║  wrapped, in every output format), unlike metadata strings like  ║
# ║  '"sops"' which any plaintext file could contain incidentally.   ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

PROJECT_ROOT="$(git rev-parse --show-toplevel)"

# Collect staged files whose git filter attribute is "sops".
# `git check-attr` honors nested .gitattributes files and git's exact
# pattern semantics — more reliable than re-parsing .gitattributes.
STAGED_SOPS_FILES=()
while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
	if [[ "${attr}" == "filter" && "${value}" == "sops" ]]; then
		STAGED_SOPS_FILES+=("${path}")
	fi
done < <(git diff --cached --name-only -z --diff-filter=d | git check-attr --stdin -z filter)

[[ ${#STAGED_SOPS_FILES[@]} -eq 0 ]] && exit 0

# SOPS-managed files are staged — verify encryption is possible at all
if [[ ! -f "${PROJECT_ROOT}/.sops.yaml" ]]; then
	echo "========================================================" >&2
	echo " COMMIT BLOCKED: SOPS not configured" >&2
	echo "========================================================" >&2
	echo "" >&2
	echo " The following files require SOPS encryption but" >&2
	echo " .sops.yaml is missing:" >&2
	echo "" >&2
	for f in "${STAGED_SOPS_FILES[@]}"; do
		echo "   - ${f}" >&2
	done
	echo "" >&2
	echo " To fix:" >&2
	echo "   1. Create .sops.yaml with your encryption keys" >&2
	echo "   2. Run install.sh to configure the git filters" >&2
	echo "" >&2
	echo " To commit non-secret files only:" >&2
	echo "   git reset HEAD ${STAGED_SOPS_FILES[*]}" >&2
	echo "   git commit" >&2
	echo "========================================================" >&2
	exit 1
fi

# Verify staged content is actually encrypted. -F: literal match,
# '[' must not be treated as a regex bracket expression.
for file in "${STAGED_SOPS_FILES[@]}"; do
	staged_content=$(git show ":${file}" 2>/dev/null || echo "")
	if [[ -n "${staged_content}" ]] && ! printf '%s' "${staged_content}" | grep -qF 'ENC[AES256_GCM'; then
		echo "========================================================" >&2
		echo " COMMIT BLOCKED: ${file} is not encrypted" >&2
		echo "========================================================" >&2
		echo "" >&2
		echo " This file is managed by SOPS but the staged version" >&2
		echo " appears to be plaintext. Configure the filters and" >&2
		echo " re-stage it to trigger encryption:" >&2
		echo "" >&2
		echo "   ./install.sh   (from this tool's directory)" >&2
		echo "   git add ${file}" >&2
		echo "========================================================" >&2
		exit 1
	fi
done

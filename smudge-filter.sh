#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Smudge Filter for Git                                      ║
# ║                                                                  ║
# ║  Git calls this script on checkout for any file matched by the   ║
# ║  "sops" filter in .gitattributes:                                ║
# ║                                                                  ║
# ║    Git repo ──[smudge]──▶ Working dir (checkout/pull)            ║
# ║                                                                  ║
# ║  It receives the stored blob (ciphertext) on stdin and must      ║
# ║  print the plaintext. The work is one `sops decrypt`; this       ║
# ║  wrapper exists for the case where that fails.                   ║
# ║                                                                  ║
# ║  Failure policy: this filter FAILS CLOSED. When sops cannot      ║
# ║  decrypt (an expired session with the key service, a key that    ║
# ║  is not on this machine), it prints nothing on stdout and exits  ║
# ║  non-zero, and git (filter.sops.required=true) stops the         ║
# ║  checkout. It never hands git the ciphertext instead: a .env     ║
# ║  full of ciphertext still parses, and services would start with  ║
# ║  garbage values.                                                 ║
# ║                                                                  ║
# ║  What it adds under the error of sops: what to check for the     ║
# ║  kinds of key THIS file names, and what state git is in now      ║
# ║  (it removed the working copy before it called the filter).      ║
# ║                                                                  ║
# ║  The storage format is read from .sops-filter.conf on every      ║
# ║  run, so a format change needs no new git configuration.         ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Byte-wise pattern matching, whatever the caller's locale is.
export LC_ALL=C

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -r "${SCRIPT_DIR}/lib.sh" ]]; then
	echo "ERROR: lib.sh is missing next to smudge-filter.sh (${SCRIPT_DIR}) — run install.sh of sops-git-filters again" >&2
	exit 1
fi
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

# Git passes the filename as %f (configured in filter.sops.smudge).
if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <filename>" >&2
	exit 1
fi
FILENAME="$1"

PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "ERROR: not inside a git repository" >&2
	exit 1
}

if ! command -v sops >/dev/null 2>&1; then
	echo "ERROR: sops not found on PATH — cannot decrypt ${FILENAME}" >&2
	exit 1
fi

STORE_FORMAT="$(sgf_store_format "${PROJECT_ROOT}")" || exit 1
case "${STORE_FORMAT}" in
json) DECRYPT_ARGS=(--input-type json --output-type binary) ;;
dotenv) DECRYPT_ARGS=(--input-type dotenv --output-type dotenv) ;;
esac
OTHER_FORMAT="$(sgf_other_format "${STORE_FORMAT}")"

# The stored blob is held for the hint below. It is ciphertext and text.
# The PLAINTEXT never passes through a variable here: sops writes it
# straight to git, byte for byte.
if ! SGF_CAPTURED="$(sgf_cat_counting_nuls)" || ! sgf_split_counted; then
	echo "ERROR: could not read the stored version of ${FILENAME} from git" >&2
	exit 1
fi
BLOB="${SGF_CONTENT}"
if [[ "${SGF_NUL_COUNT}" != "0" ]]; then
	echo "ERROR: the version of ${FILENAME} that git holds has NUL bytes: it is not a SOPS document." >&2
	exit 1
fi

status=0
printf '%s' "${BLOB}" | sops decrypt "${DECRYPT_ARGS[@]}" \
	--filename-override "${FILENAME}" /dev/stdin || status=$?

if [[ "${status}" -eq 0 ]]; then
	sgf_warn_if_outdated "${SCRIPT_DIR}" "${PROJECT_ROOT}"
	exit 0
fi

# ── sops could not decrypt: say what to do, then fail ────
{
	echo "sops smudge filter: cannot decrypt ${FILENAME} (sops' message is above)."
	if sgf_is_sops_doc "${STORE_FORMAT}" "${BLOB}"; then
		echo "  Are your keys or credentials available?"
		# shellcheck disable=SC2046  # one word per key type
		sgf_credential_hint "    " $(printf '%s' "${BLOB}" | sgf_doc_key_types)
	elif sgf_is_sops_doc "${OTHER_FORMAT}" "${BLOB}"; then
		echo "  Git holds this file in the ${OTHER_FORMAT} format, but .sops-filter.conf says ${STORE_FORMAT}."
		echo "  A storage-format change is not finished (see the README, \"Storage formats\")."
	else
		echo "  The version git holds is not an encrypted SOPS document: it was committed"
		echo "  without the filter. install.sh lists such files and says how to fix them."
	fi
	echo "  If git was checking this file out (pull, checkout, merge, rebase), it removed the"
	echo "  working copy before it ran the filter, and it stops here: do NOT commit or stash now."
	echo "  The way back: README, \"When sops cannot decrypt\". preflight.sh tells you beforehand."
} >&2
exit 1

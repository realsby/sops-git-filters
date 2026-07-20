#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SOPS Clean Filter for Git                                       ║
# ║                                                                  ║
# ║  Git calls this script automatically during `git add` for any    ║
# ║  file matched by the "sops" filter in .gitattributes.            ║
# ║                                                                  ║
# ║  How git clean/smudge filters work:                              ║
# ║                                                                  ║
# ║    Working dir ──[clean]──▶ Git repo (staged/committed)          ║
# ║    Git repo ──[smudge]──▶ Working dir (checkout/pull)            ║
# ║                                                                  ║
# ║  This is the "clean" side: it receives plaintext on stdin and    ║
# ║  must output the encrypted version for git to store.             ║
# ║                                                                  ║
# ║  The problem: SOPS encryption is non-deterministic — encrypting  ║
# ║  the same plaintext twice produces different ciphertext (new IV  ║
# ║  each time). This means git would see every file as "changed"    ║
# ║  on every checkout, even if nothing actually changed.            ║
# ║                                                                  ║
# ║  The fix: before encrypting, we decrypt what's already in the    ║
# ║  index (or HEAD) and compare it to the new content. If it is     ║
# ║  identical, we reuse the existing ciphertext — no false diff.    ║
# ║                                                                  ║
# ║  Failure policy: this filter FAILS HARD. If sops is missing or   ║
# ║  .sops.yaml is absent, it exits non-zero and (combined with      ║
# ║  filter.sops.required=true, set by install.sh) git aborts the    ║
# ║  add/commit instead of silently staging plaintext secrets.       ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# Git passes the filename as %f (configured in filter.sops.clean).
# We need it so SOPS can look up the right .sops.yaml creation rule.
if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <filename>" >&2
	exit 1
fi

FILENAME="$1"

# Git pipes the file content (plaintext from working dir) to stdin.
# Capture it so we can compare and/or encrypt it. The trailing "x"
# trick preserves trailing newlines that $(...) would otherwise strip.
INPUT=$(cat && printf x)
INPUT="${INPUT%x}"

# Git runs clean filters from the top level of the working tree, but
# resolve the root explicitly so this also works when invoked by hand.
PROJECT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
	echo "ERROR: not inside a git repository" >&2
	exit 1
}

# ── Guards: fail hard, never pass plaintext through ────
# Exiting non-zero makes git abort the add/commit
# (filter.sops.required=true) instead of storing plaintext.
if ! command -v sops >/dev/null 2>&1; then
	echo "ERROR: sops not found on PATH — refusing to stage ${FILENAME} as plaintext" >&2
	exit 1
fi

if [[ ! -f "${PROJECT_ROOT}/.sops.yaml" ]]; then
	echo "ERROR: .sops.yaml missing — refusing to stage ${FILENAME} as plaintext" >&2
	exit 1
fi

# ── Storage format ────
# Read SOPS_STORE_FORMAT from .sops-filter.conf at the project root.
#   json   (default): encrypt binary→json  / decrypt json→binary
#   dotenv          : encrypt dotenv→dotenv / decrypt dotenv→dotenv
# The file is parsed, not sourced — no code execution.
STORE_FORMAT="json"
if [[ -f "${PROJECT_ROOT}/.sops-filter.conf" ]]; then
	conf_value=$(grep -E '^SOPS_STORE_FORMAT=' "${PROJECT_ROOT}/.sops-filter.conf" | tail -1 | cut -d= -f2 | tr -d '[:space:]')
	[[ -n "${conf_value}" ]] && STORE_FORMAT="${conf_value}"
fi

case "${STORE_FORMAT}" in
json)
	ENCRYPT_ARGS=(--input-type binary --output-type json)
	DECRYPT_ARGS=(--input-type json --output-type binary)
	;;
dotenv)
	ENCRYPT_ARGS=(--input-type dotenv --output-type dotenv)
	DECRYPT_ARGS=(--input-type dotenv --output-type dotenv)
	;;
*)
	echo "ERROR: invalid SOPS_STORE_FORMAT '${STORE_FORMAT}' in .sops-filter.conf (expected: json or dotenv)" >&2
	exit 1
	;;
esac

encrypt_input() {
	# --filename-override tells SOPS which .sops.yaml creation rule to
	# match (stdin has no filename of its own).
	printf '%s' "${INPUT}" | sops encrypt \
		"${ENCRYPT_ARGS[@]}" \
		--filename-override "${FILENAME}" \
		/dev/stdin
}

# ── New file: no previous version in the index or HEAD ────────
# git cat-file -e checks if the object exists without reading it.
# For new files there is nothing to compare — just encrypt and exit.
if ! git cat-file -e ":${FILENAME}" 2>/dev/null &&
	! git cat-file -e "HEAD:${FILENAME}" 2>/dev/null; then
	echo "sops clean filter: encrypting new file ${FILENAME}" >&2
	encrypt_input
	exit 0
fi

# ── Existing file: compare before re-encrypting ────────

# Compare against the INDEX version first (`:path`), then fall back to
# HEAD. Why index over HEAD? During pre-commit's stash/unstash cycle:
#   1. You stage the file (index has encrypted blob A)
#   2. Pre-commit stashes unstaged changes, clean filter runs again
#   3. Comparing against HEAD (old blob) → plaintext differs →
#      re-encrypt with a new IV
#   4. New-IV blob ≠ stash blob → `git stash pop` sees a conflict
# By comparing against the index we reuse blob A → stash pop is clean.
EXISTING_ENCRYPTED=$( (git cat-file -p ":${FILENAME}" 2>/dev/null ||
	git cat-file -p "HEAD:${FILENAME}" 2>/dev/null ||
	true) && printf x)
EXISTING_ENCRYPTED="${EXISTING_ENCRYPTED%x}"

# Decrypt the stored version so we can compare plaintext-to-plaintext.
# If decryption fails (corrupted, no keys), fall through to re-encrypt.
EXISTING_DECRYPTED=$( (printf '%s' "${EXISTING_ENCRYPTED}" | sops decrypt \
	"${DECRYPT_ARGS[@]}" \
	--filename-override "${FILENAME}" \
	/dev/stdin 2>/dev/null || true) && printf x)
EXISTING_DECRYPTED="${EXISTING_DECRYPTED%x}"

if [[ -n "${EXISTING_DECRYPTED}" && "${EXISTING_DECRYPTED}" == "${INPUT}" ]]; then
	# Content unchanged — reuse the existing ciphertext verbatim.
	# Same plaintext → same stored blob → no false diff.
	echo "sops clean filter: content unchanged, reusing existing encrypted blob for ${FILENAME}" >&2
	printf '%s' "${EXISTING_ENCRYPTED}"
else
	# Content actually changed — encrypt the new version.
	echo "sops clean filter: content changed, re-encrypting ${FILENAME}" >&2
	encrypt_input
fi

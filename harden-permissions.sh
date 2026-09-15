#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Tighten permissions on SOPS-managed working-tree files          ║
# ║                                                                  ║
# ║  Git stores only the executable bit, so it cannot round-trip     ║
# ║  0600. Every smudge — clone, checkout, merge, the re-smudge      ║
# ║  pass in install.sh — recreates decrypted secrets with the       ║
# ║  caller's umask, which is 0644 on a default workstation. A       ║
# ║  deploy key, an API key, a kubeconfig or a Talos secrets bundle  ║
# ║  then sits world-readable in the working tree, and OpenSSH will  ║
# ║  refuse a 0644 private key outright.                             ║
# ║                                                                  ║
# ║  This script chmods every tracked file whose git attribute is    ║
# ║  filter=sops to 0600 (override with SOPS_FILE_MODE in            ║
# ║  .sops-filter.conf). It is idempotent and safe to run often —    ║
# ║  install.sh runs it, and the post-checkout / post-merge hooks    ║
# ║  it installs run it again after every checkout and merge.        ║
# ║                                                                  ║
# ║  Usage:                                                          ║
# ║    harden-permissions.sh [--root <repo>] [--quiet]               ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

TARGET_ROOT=""
QUIET=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--root)
		if [[ $# -lt 2 ]]; then
			echo "Error: --root requires a path." >&2
			exit 2
		fi
		TARGET_ROOT="$2"
		shift 2
		;;
	--quiet | -q)
		QUIET=1
		shift
		;;
	--help | -h)
		echo "Usage: harden-permissions.sh [--root <repo>] [--quiet]"
		exit 0
		;;
	*)
		# Ignore anything else (pre-commit may pass file names).
		shift
		;;
	esac
done

if [[ -z "${TARGET_ROOT}" ]]; then
	TARGET_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
		echo "Error: not inside a git repository, and no --root given." >&2
		exit 1
	}
fi

# ── Target mode (override in .sops-filter.conf) ────
# Default 0600. A repo whose decrypted files must be readable by a
# second local account (a deploy daemon, say) can widen it — but that
# is the exception, and it is recorded in a tracked file.
FILE_MODE="600"
if [[ -f "${TARGET_ROOT}/.sops-filter.conf" ]]; then
	conf_mode=$({ grep -E '^SOPS_FILE_MODE=' "${TARGET_ROOT}/.sops-filter.conf" || true; } |
		tail -1 | cut -d= -f2 | tr -d '[:space:]')
	[[ -n "${conf_mode}" ]] && FILE_MODE="${conf_mode}"
fi

if [[ ! "${FILE_MODE}" =~ ^[0-7]{3,4}$ ]]; then
	echo "Error: invalid SOPS_FILE_MODE '${FILE_MODE}' in .sops-filter.conf (expected octal, e.g. 600)." >&2
	exit 1
fi

# ── Walk every tracked path carrying filter=sops ────
# check-attr -z emits NUL-separated <path> <attr> <value> triples, so
# paths with spaces or newlines survive intact.
hardened=0
failed=0

while IFS= read -r -d '' path && IFS= read -r -d '' attr && IFS= read -r -d '' value; do
	[[ "${attr}" == "filter" && "${value}" == "sops" ]] || continue
	f="${TARGET_ROOT}/${path}"
	# Regular files only: never chmod through a symlink, and skip paths
	# deleted or not yet checked out.
	[[ -f "${f}" && ! -L "${f}" ]] || continue

	if chmod "${FILE_MODE}" "${f}" 2>/dev/null; then
		hardened=$((hardened + 1))
	else
		failed=$((failed + 1))
		echo "⚠  Could not chmod ${FILE_MODE} ${path}" >&2
	fi
done < <(git -C "${TARGET_ROOT}" ls-files -z | git -C "${TARGET_ROOT}" check-attr --stdin -z filter)

if [[ "${QUIET}" -eq 0 ]]; then
	echo "Permissions: ${hardened} SOPS-managed file(s) set to ${FILE_MODE}."
fi

[[ "${failed}" -eq 0 ]] || exit 1

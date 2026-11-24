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
# ║  .sops-filter.conf). A file tracked as executable (100755) gets  ║
# ║  the owner execute bit too (0700), so git sees no mode change.   ║
# ║  SOPS_FILE_MODE may hold owner and group bits only; a refused    ║
# ║  value still leaves the files at 0600 (0700) and exits 1.        ║
# ║  It is idempotent and safe to run often —                        ║
# ║  install.sh runs it, and the hooks it installs (post-checkout,   ║
# ║  post-merge, post-rewrite, post-applypatch, post-commit) run it  ║
# ║  again after a checkout, merge, rebase, `git am` and commit.     ║
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

# No setuid/setgid/sticky digit and no bits for "other". A refused value
# must not leave the files at their umask mode: the hooks and install.sh
# ignore this script's exit status. So harden to the safe default 0600
# first, and only then report the error through the exit status.
INVALID_MODE=""
if [[ ! "${FILE_MODE}" =~ ^0?[0-7][0-7]0$ ]]; then
	INVALID_MODE="${FILE_MODE}"
	FILE_MODE="600"
	echo "Error: invalid SOPS_FILE_MODE '${INVALID_MODE}' in .sops-filter.conf (expected octal owner/group bits only, e.g. 600 or 640; no setuid, setgid, sticky or 'other' bits). Applying the safe default 600 instead; fix the setting." >&2
fi

# A file tracked as 100755 keeps its owner execute bit: chmod 600 would
# drop it, and git would then show the file as modified for ever.
# Take the last three digits: stripping a leading 0 would also eat the
# owner digit of a mode such as 060.
plain_mode="${FILE_MODE: -3}"
EXEC_MODE="$((${plain_mode:0:1} | 1))${plain_mode:1}"

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

	mode="${FILE_MODE}"
	entry="$(git -C "${TARGET_ROOT}" ls-files -s -- ":(literal)${path}")"
	[[ "${entry:0:6}" == "100755" ]] && mode="${EXEC_MODE}"

	if chmod "${mode}" "${f}" 2>/dev/null; then
		hardened=$((hardened + 1))
	else
		failed=$((failed + 1))
		echo "⚠  Could not chmod ${mode} ${path}" >&2
	fi
done < <(git -C "${TARGET_ROOT}" ls-files -z | git -C "${TARGET_ROOT}" check-attr --stdin -z filter)

if [[ "${QUIET}" -eq 0 ]]; then
	echo "Permissions: ${hardened} SOPS-managed file(s) set to ${FILE_MODE}."
fi

# The hooks run this script from the copy under .git/. When the checkout
# of the tool holds a newer version, say that install.sh has to run again
# (lib.sh; also with --quiet, because nothing else would tell). The script
# works without lib.sh, so a copy that came without it stays silent.
SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -r "${SCRIPT_DIR}/INSTALLED" && -r "${SCRIPT_DIR}/lib.sh" ]]; then
	# shellcheck source=lib.sh
	. "${SCRIPT_DIR}/lib.sh"
	sgf_warn_if_outdated "${SCRIPT_DIR}" "${TARGET_ROOT}"
fi

[[ "${failed}" -eq 0 && -z "${INVALID_MODE}" ]] || exit 1

#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Fetch sops and age for the test run                             ║
# ║                                                                  ║
# ║    tests/ci-install-tools.sh <sops version> <destination dir>    ║
# ║                                                                  ║
# ║  Downloads the release binaries of sops and age from GitHub and  ║
# ║  puts sops, age and age-keygen into <destination dir>.           ║
# ║                                                                  ║
# ║  Every file is checked against a SHA-256 pinned in this script   ║
# ║  BEFORE it is made executable or unpacked. A release tag is a    ║
# ║  mutable pointer; the checksum is what pins the content.         ║
# ║                                                                  ║
# ║  To add a version: add its checksums below. For sops take them   ║
# ║  from sops-v<version>.checksums.txt in the release; age ships    ║
# ║  no checksum file, so download each tarball and run sha256sum.   ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "Usage: $0 <sops version> <destination dir>" >&2
	exit 2
fi
SOPS_VERSION="$1"
DEST="$2"
AGE_VERSION="1.3.2"

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) OS=linux ARCH=amd64 ;;
Linux-aarch64 | Linux-arm64) OS=linux ARCH=arm64 ;;
Darwin-arm64) OS=darwin ARCH=arm64 ;;
Darwin-x86_64) OS=darwin ARCH=amd64 ;;
*)
	echo "ci-install-tools: unsupported platform $(uname -s)-$(uname -m)" >&2
	exit 1
	;;
esac

# pinned_sha256 <tool>-<version>-<os>-<arch>
pinned_sha256() {
	case "$1" in
	sops-3.11.0-linux-amd64) echo 775f1384d55decfad228e7196a3f683791914f92a473f78fc47700531c29dfef ;;
	sops-3.11.0-linux-arm64) echo c71d32f74b3a73ce283affe6ed36e221a8f1476c3d37963f60bd962fb1676681 ;;
	sops-3.11.0-darwin-arm64) echo 45e7562b1f5d022c4d7a4e4c3d1b7b1a7ee6c328356629286cfd18a394b00e7c ;;
	sops-3.11.0-darwin-amd64) echo c36583e178f7e83b947044b292e106e79615f7725f75cb147045fb0c81953e2b ;;
	sops-3.13.3-linux-amd64) echo e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b ;;
	sops-3.13.3-linux-arm64) echo 53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77 ;;
	sops-3.13.3-darwin-arm64) echo b97c0d434aab577dc40310e8d22ff9e45eef4c80638ab978daae9b4681c59286 ;;
	sops-3.13.3-darwin-amd64) echo 42162d5cef10b74fcf80a045a70e658d7ce6e63d6ea1be6f347e44015714468d ;;
	age-1.3.2-linux-amd64) echo cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10 ;;
	age-1.3.2-linux-arm64) echo 6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4 ;;
	age-1.3.2-darwin-arm64) echo e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5 ;;
	age-1.3.2-darwin-amd64) echo 1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539 ;;
	*) return 1 ;;
	esac
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# fetch <url> <file> <pin name> : download, then verify or stop
fetch() {
	local url="$1" file="$2" pin="$3" expected actual
	if ! expected="$(pinned_sha256 "${pin}")"; then
		echo "ci-install-tools: no checksum pinned for ${pin}" >&2
		exit 1
	fi
	curl --fail --silent --show-error --location --retry 3 --output "${file}" "${url}"
	actual="$(sha256_of "${file}")"
	if [[ "${actual}" != "${expected}" ]]; then
		echo "ci-install-tools: CHECKSUM MISMATCH for ${url}" >&2
		echo "  expected ${expected}" >&2
		echo "  got      ${actual}" >&2
		exit 1
	fi
	echo "verified ${pin} (${actual})"
}

mkdir -p "${DEST}"
DOWNLOADS="$(mktemp -d)"
trap 'rm -rf "${DOWNLOADS}"' EXIT

fetch "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.${OS}.${ARCH}" \
	"${DOWNLOADS}/sops" "sops-${SOPS_VERSION}-${OS}-${ARCH}"
install -m 0755 "${DOWNLOADS}/sops" "${DEST}/sops"

fetch "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-${OS}-${ARCH}.tar.gz" \
	"${DOWNLOADS}/age.tar.gz" "age-${AGE_VERSION}-${OS}-${ARCH}"
tar -xzf "${DOWNLOADS}/age.tar.gz" -C "${DOWNLOADS}" age/age age/age-keygen
install -m 0755 "${DOWNLOADS}/age/age" "${DEST}/age"
install -m 0755 "${DOWNLOADS}/age/age-keygen" "${DEST}/age-keygen"

"${DEST}/sops" --disable-version-check --version | head -1
"${DEST}/age" --version

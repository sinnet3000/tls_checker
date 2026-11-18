#!/bin/bash
# tls_checker installer
# Usage: curl -fsSL https://raw.githubusercontent.com/sinnet3000/tls_checker/main/scripts/install.sh | bash

set -e

REPO="sinnet3000/tls_checker"
BINARY_NAME="tls_checker"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}$1${NC}"; }
warn() { echo -e "${YELLOW}$1${NC}"; }
error() { echo -e "${RED}$1${NC}" >&2; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux) echo "linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7*|armhf) echo "arm" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac
}

find_install_dir() {
    if [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    else
        mkdir -p "$HOME/.local/bin"
        echo "$HOME/.local/bin"
    fi
}

download() {
    local url="$1"
    local output="$2"
    case "$url" in
        https://*) ;;
        *) error "Refusing non-HTTPS download URL: $url" ;;
    esac
    if command -v curl &>/dev/null; then
        curl -fsSL --proto '=https' --proto-redir '=https' "$url" -o "$output"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$output"
    else
        error "Neither curl nor wget found"
    fi
}

get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    if command -v curl &>/dev/null; then
        curl -fsSL --proto '=https' --proto-redir '=https' "$url" | grep '"tag_name"' | head -1 | cut -d'"' -f4
    elif command -v wget &>/dev/null; then
        wget -qO- "$url" | grep '"tag_name"' | head -1 | cut -d'"' -f4
    fi
}

sha256_of_file() {
    local file="$1"
    local output
    if command -v sha256sum &>/dev/null; then
        output=$(sha256sum < "$file") || error "Could not compute SHA-256 for $file"
    elif command -v shasum &>/dev/null; then
        output=$(shasum -a 256 < "$file") || error "Could not compute SHA-256 for $file"
    else
        error "Neither sha256sum nor shasum found"
    fi
    printf '%s\n' "${output%%[[:space:]]*}"
}

verify_archive_checksum() {
    local archive="$1"
    local sums_file="$2"
    local filename="$3"

    [ -f "$sums_file" ] || error "SHA256SUMS is missing: $sums_file"
    [ -r "$sums_file" ] || error "SHA256SUMS is not readable: $sums_file"
    [ -f "$archive" ] || error "Release archive is missing: $archive"

    local line lineno=0 expected_hash="" matches=0 entry_hash entry_name
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        line="${line%$'\r'}"
        [ -n "$line" ] || continue

        if [[ ! "$line" =~ ^([0-9A-Fa-f]{64})[[:space:]]+\*?(.+)$ ]]; then
            error "Malformed checksum entry on line ${lineno} of SHA256SUMS"
        fi

        entry_hash="${BASH_REMATCH[1]}"
        entry_name="${BASH_REMATCH[2]}"
        if [ "$entry_name" = "$filename" ]; then
            matches=$((matches + 1))
            expected_hash=$(printf '%s' "$entry_hash" | tr '[:upper:]' '[:lower:]')
        fi
    done < "$sums_file"

    if [ "$matches" -eq 0 ]; then
        error "No checksum entry for ${filename} in SHA256SUMS"
    fi
    if [ "$matches" -gt 1 ]; then
        error "Duplicate checksum entries for ${filename} in SHA256SUMS"
    fi

    local actual_hash
    actual_hash=$(sha256_of_file "$archive")
    actual_hash=$(printf '%s' "$actual_hash" | tr '[:upper:]' '[:lower:]')
    if [ "$actual_hash" != "$expected_hash" ]; then
        error "Checksum verification failed for ${filename}"
    fi
}

main() {
    info "Installing ${BINARY_NAME}..."
    echo

    local os arch install_dir
    os=$(detect_os)
    arch=$(detect_arch)
    install_dir=$(find_install_dir)

    info "Platform: ${os}/${arch}"
    info "Install directory: ${install_dir}"
    echo

    info "Fetching latest release..."
    local ver
    ver=$(get_latest_version)

    if [ -z "$ver" ]; then
        error "Could not determine latest version"
    fi

    info "Found version: $ver"

    local version="${ver#v}"
    local filename="${BINARY_NAME}_${version}_${os}_${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${ver}/${filename}"
    local sums_url="https://github.com/${REPO}/releases/download/${ver}/SHA256SUMS"
    local tmpdir sums_file
    tmpdir=$(mktemp -d)
    # Capture the shell-quoted path while tmpdir is still in scope.
    # shellcheck disable=SC2064
    trap "$(printf 'rm -rf -- %q' "$tmpdir")" EXIT
    sums_file="$tmpdir/SHA256SUMS"

    info "Downloading ${filename}..."
    if ! download "$url" "$tmpdir/release.tar.gz"; then
        error "Download failed. Check https://github.com/${REPO}/releases for available binaries."
    fi

    info "Downloading SHA256SUMS..."
    if ! download "$sums_url" "$sums_file"; then
        error "Could not download SHA256SUMS for ${ver}"
    fi

    info "Verifying checksum..."
    verify_archive_checksum "$tmpdir/release.tar.gz" "$sums_file" "$filename"

    info "Extracting..."
    tar -xzf "$tmpdir/release.tar.gz" -C "$tmpdir"

    if [ -w "$install_dir" ]; then
        mv "$tmpdir/${BINARY_NAME}" "$install_dir/"
    else
        sudo mv "$tmpdir/${BINARY_NAME}" "$install_dir/"
    fi
    chmod +x "$install_dir/${BINARY_NAME}"

    if [ "$os" = "darwin" ]; then
        codesign -s - "$install_dir/${BINARY_NAME}" 2>/dev/null || true
    fi

    echo
    info "Installation complete! ${BINARY_NAME} ${ver}"
    echo

    if ! echo "$PATH" | grep -q "$install_dir"; then
        warn "Add this to your shell profile:"
        echo "  export PATH=\"\$PATH:$install_dir\""
        echo
    fi

    echo "Run it:"
    echo "  ${BINARY_NAME} -i urls.txt"
    echo "  ${BINARY_NAME} -version    # show version"
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    main "$@"
fi

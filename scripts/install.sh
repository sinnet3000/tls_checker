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
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$output"
    else
        error "Neither curl nor wget found"
    fi
}

get_latest_version() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" | grep '"tag_name"' | head -1 | cut -d'"' -f4
    elif command -v wget &>/dev/null; then
        wget -qO- "$url" | grep '"tag_name"' | head -1 | cut -d'"' -f4
    fi
}

main() {
    info "Installing ${BINARY_NAME}..."
    echo

    local os=$(detect_os)
    local arch=$(detect_arch)
    local install_dir=$(find_install_dir)

    info "Platform: ${os}/${arch}"
    info "Install directory: ${install_dir}"
    echo

    info "Fetching latest release..."
    local ver=$(get_latest_version)

    if [ -z "$ver" ]; then
        error "Could not determine latest version"
    fi

    info "Found version: $ver"

    local version="${ver#v}"
    local filename="${BINARY_NAME}_${version}_${os}_${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${ver}/${filename}"

    local tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    info "Downloading ${filename}..."
    if ! download "$url" "$tmpdir/release.tar.gz"; then
        error "Download failed. Check https://github.com/${REPO}/releases for available binaries."
    fi

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

main "$@"

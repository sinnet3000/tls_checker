#!/bin/bash
# Offline tests for the release checksum verification in scripts/install.sh.
# Uses inert fixtures and a temporary install directory; never touches the network
# or a real install location.
# shellcheck disable=SC2329 # Functions below are invoked indirectly through main.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091 # Source path is resolved at runtime.
source "${SCRIPT_DIR}/install.sh"
set +eu

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'ok - %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'not ok - %s\n' "$1" >&2; }

expect_success() {
    local name="$1"
    shift
    if ( "$@" ) >/dev/null 2>&1; then
        pass "$name"
    else
        fail "$name"
    fi
}

expect_failure() {
    local name="$1"
    shift
    if ( "$@" ) >/dev/null 2>&1; then
        fail "$name (expected failure)"
    else
        pass "$name"
    fi
}

ARCHIVE_NAME="tls_checker_9.9.9_linux_amd64.tar.gz"
OTHER_NAME="tls_checker_9.9.9_darwin_arm64.tar.gz"
ARCHIVE="$WORK/$ARCHIVE_NAME"
ZERO_HASH="0000000000000000000000000000000000000000000000000000000000000000"

mkdir -p "$WORK/source"
printf '#!/bin/sh\nexit 0\n' > "$WORK/source/tls_checker"
tar -czf "$ARCHIVE" -C "$WORK/source" tls_checker
GOOD_HASH="$(sha256_of_file "$ARCHIVE")"

# Verification accepts a well-formed entry for the exact archive filename.
printf '%s  %s\n' "$GOOD_HASH" "$ARCHIVE_NAME" > "$WORK/valid.sums"
expect_success "accepts exact matching checksum" \
    verify_archive_checksum "$ARCHIVE" "$WORK/valid.sums" "$ARCHIVE_NAME"

# Unrelated entries may be present; the target entry is still found exactly.
printf '%s  %s\n%s  %s\n' "$ZERO_HASH" "$OTHER_NAME" "$GOOD_HASH" "$ARCHIVE_NAME" > "$WORK/mixed.sums"
expect_success "accepts matching entry among other archives" \
    verify_archive_checksum "$ARCHIVE" "$WORK/mixed.sums" "$ARCHIVE_NAME"

# Absent target entry.
printf '%s  %s\n' "$GOOD_HASH" "$OTHER_NAME" > "$WORK/absent.sums"
expect_failure "rejects absent checksum entry" \
    verify_archive_checksum "$ARCHIVE" "$WORK/absent.sums" "$ARCHIVE_NAME"

# Malformed checksum file.
printf 'not-a-checksum  %s\n' "$ARCHIVE_NAME" > "$WORK/malformed.sums"
expect_failure "rejects malformed checksum entry" \
    verify_archive_checksum "$ARCHIVE" "$WORK/malformed.sums" "$ARCHIVE_NAME"

printf 'garbage line\n%s  %s\n' "$GOOD_HASH" "$ARCHIVE_NAME" > "$WORK/malformed-other.sums"
expect_failure "rejects malformed unrelated checksum line" \
    verify_archive_checksum "$ARCHIVE" "$WORK/malformed-other.sums" "$ARCHIVE_NAME"

# Duplicate target entries, even when one hash matches.
printf '%s  %s\n%s  %s\n' "$GOOD_HASH" "$ARCHIVE_NAME" "$GOOD_HASH" "$ARCHIVE_NAME" > "$WORK/duplicate.sums"
expect_failure "rejects duplicate checksum entries" \
    verify_archive_checksum "$ARCHIVE" "$WORK/duplicate.sums" "$ARCHIVE_NAME"

# Mismatched hash.
printf '%s  %s\n' "$ZERO_HASH" "$ARCHIVE_NAME" > "$WORK/mismatch.sums"
expect_failure "rejects mismatched checksum" \
    verify_archive_checksum "$ARCHIVE" "$WORK/mismatch.sums" "$ARCHIVE_NAME"

# Missing checksum file.
expect_failure "rejects missing SHA256SUMS file" \
    verify_archive_checksum "$ARCHIVE" "$WORK/does-not-exist.sums" "$ARCHIVE_NAME"

# Download URLs must not downgrade to plain HTTP.
expect_failure "refuses non-HTTPS download URL" \
    download "http://example.invalid/$ARCHIVE_NAME" "$WORK/insecure.out"

# curl backend keeps its HTTPS-only protocol restrictions.
CURL_BIN="$WORK/curl-bin"
mkdir -p "$CURL_BIN"
cat > "$CURL_BIN/curl" <<'CURL_STUB'
#!/bin/sh
for arg in "$@"; do
    printf '%s\n' "$arg" >> "$STUB_LOG"
done
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
        : > "$2"
        break
    fi
    shift
done
exit 0
CURL_STUB
chmod +x "$CURL_BIN/curl"
CURL_LOG="$WORK/curl.args"
STUB_LOG="$CURL_LOG" PATH="$CURL_BIN" download "https://example.invalid/$ARCHIVE_NAME" "$WORK/curl.out" >/dev/null 2>&1
if [ "$(grep -Fxc -- '=https' "$CURL_LOG" 2>/dev/null)" = "2" ] &&
   grep -Fxq -- '--proto' "$CURL_LOG" 2>/dev/null &&
   grep -Fxq -- '--proto-redir' "$CURL_LOG" 2>/dev/null; then
    pass "curl backend restricts download and redirect protocols to HTTPS"
else
    fail "curl backend restricts download and redirect protocols to HTTPS"
fi

# wget remains available as a fallback downloader.
WGET_BIN="$WORK/wget-bin"
mkdir -p "$WGET_BIN"
cat > "$WGET_BIN/wget" <<'WGET_STUB'
#!/bin/sh
for arg in "$@"; do
    printf '%s\n' "$arg" >> "$STUB_LOG"
done
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-O" ]; then
        if [ "$2" != "-" ]; then
            : > "$2"
        fi
        break
    fi
    shift
done
exit 0
WGET_STUB
chmod +x "$WGET_BIN/wget"
WGET_LOG="$WORK/wget.args"
STUB_LOG="$WGET_LOG" PATH="$WGET_BIN" download "https://example.invalid/$ARCHIVE_NAME" "$WORK/wget.out" >/dev/null 2>&1
if [ -f "$WORK/wget.out" ] && grep -Fxq -- "https://example.invalid/$ARCHIVE_NAME" "$WGET_LOG"; then
    pass "wget fallback downloads the requested archive"
else
    fail "wget fallback downloads the requested archive"
fi

# End-to-end installer flow against fixtures. Main is run in a subshell with the
# platform, release lookup, download, and install-directory functions replaced.
run_install() {
    local sums="$1"
    local target_dir="$2"
    local download_log="$3"
    (
        sudo() { exit 1; }
        detect_os() { printf 'linux\n'; }
        detect_arch() { printf 'amd64\n'; }
        find_install_dir() { printf '%s\n' "$target_dir"; }
        get_latest_version() { printf 'v9.9.9\n'; }
        download() {
            printf '%s\n' "$1" >> "$download_log"
            case "$1" in
                */SHA256SUMS) cp "$sums" "$2" ;;
                *) cp "$ARCHIVE" "$2" ;;
            esac
        }
        main
    ) >/dev/null 2>&1
}

INSTALL_OK="$WORK/install-ok"
mkdir -p "$INSTALL_OK"
printf '%s  %s\n' "$GOOD_HASH" "$ARCHIVE_NAME" > "$WORK/install-ok.sums"
run_install "$WORK/install-ok.sums" "$INSTALL_OK" "$WORK/downloads-ok.log"
if [ -x "$INSTALL_OK/tls_checker" ]; then
    pass "installs verified archive into the temporary install directory"
else
    fail "installs verified archive into the temporary install directory"
fi
if grep -Fxq "https://github.com/sinnet3000/tls_checker/releases/download/v9.9.9/SHA256SUMS" "$WORK/downloads-ok.log" 2>/dev/null; then
    pass "fetches SHA256SUMS from the same release tag"
else
    fail "fetches SHA256SUMS from the same release tag"
fi

INSTALL_BAD="$WORK/install-bad"
mkdir -p "$INSTALL_BAD"
printf '%s  %s\n' "$ZERO_HASH" "$ARCHIVE_NAME" > "$WORK/install-bad.sums"
EXTRACT_LOG="$WORK/extract.log"
(
    sudo() { exit 1; }
    detect_os() { printf 'linux\n'; }
    detect_arch() { printf 'amd64\n'; }
    find_install_dir() { printf '%s\n' "$INSTALL_BAD"; }
    get_latest_version() { printf 'v9.9.9\n'; }
    download() {
        case "$1" in
            */SHA256SUMS) cp "$WORK/install-bad.sums" "$2" ;;
            *) cp "$ARCHIVE" "$2" ;;
        esac
    }
    tar() { printf 'tar invoked\n' >> "$EXTRACT_LOG"; return 0; }
    main
) >/dev/null 2>&1
if [ ! -e "$INSTALL_BAD/tls_checker" ] && [ ! -e "$EXTRACT_LOG" ]; then
    pass "rejects a bad checksum before extraction or installation"
else
    fail "rejects a bad checksum before extraction or installation"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]

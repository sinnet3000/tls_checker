# TLS Checker

A Go-based command-line tool for concurrent TLS diagnostics, designed to check a list of hosts for their TLS configuration, ALPN support, HTTP/2 readiness, and ASN information. It provides clear, idiomatic Go features such as focused helpers, error handling, context timeouts, and simple flags.

## Features

-   **DNS Resolution & TLS Handshake:** Performs DNS lookups and establishes TLS connections to extract Common Name (CN) and Subject Alternative Names (SANs) from certificates.
-   **ALPN & HTTP/2 Probe:** Detects Application-Layer Protocol Negotiation (ALPN) and probes for HTTP/2 readiness.
-   **TLS Version Bucketing:** Categorizes TLS outcomes into four types:
    -   🔵 **Full:** TLS1.3 + ALPN=h2 + H2 OK
    -   🟢 **Success:** TLS1.3 (ALPN/H2 optional)
    -   🟡 **Partial:** TLS reachable but < TLS1.3
    -   ❌ **Failure:** Any error (DNS, timeout, TLS, etc.)
-   **ASN Lookup:** Optionally performs Team Cymru WHOIS (ASN) lookups with an in-memory cache.
-   **Resilience:** Includes retries with exponential backoff and jitter for robust checking.
-   **Output:** Provides text-only output to stdout or a specified file.

## Build

To build the `tls_checker` executable, use the provided `Makefile`:

```bash
make build
```

This will create platform-specific binaries in the `bin/` directory.

## Usage

The tool expects an input file with a list of hosts or URLs. By default, it looks for `urls.txt`.

```bash
./bin/tls_checker_[OS]_[ARCH] -i urls.txt -t 16 --timeout 5s --retries 2
./bin/tls_checker_[OS]_[ARCH] -i urls.txt --no-asn -o output.txt
```

### Flags:

-   `-i <file>`: Input file with hosts/URLs (default: `urls.txt`).
-   `-t <int>`: Concurrent workers (default: `12`).
-   `--timeout <duration>`: Per-connection timeout (default: `5s`).
-   `--retries <int>`: Retries per host on failure (default: `3`).
-   `-o <file>`: Output file (optional).
-   `-v`: Verbose/debug output.
-   `--no-asn`: Disable ASN lookups.
-   `--port <port>`: TCP port to connect (default: `443`).

## Legacy Python Version

A legacy Python version of a similar tool can be found in the `legacy/` folder. This Go version aims to provide improved performance and concurrency.

## License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Luis Colunga (@sinnet3000)

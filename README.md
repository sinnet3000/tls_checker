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

## Installation

### Quick Install (macOS / Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/sinnet3000/tls_checker/main/scripts/install.sh | bash
```

### Build from Source

```sh
git clone https://github.com/sinnet3000/tls_checker.git
cd tls_checker
make install
```

Requires **Go** 1.26.1 or newer. Installs to `~/.local/bin/`.

---

## Usage

```bash
tls_checker -i example_urls.txt -t 16 --timeout 5s --retries 2
tls_checker -i example_urls.txt --no-asn -o output.txt
```

### Example Output (Simulated)

```text
📋 Found 4 unique host:port targets to check.
🔒 TLS Checker → 4 targets, 12 workers, timeout=5s, retries=2, ASN:true, default port:443
---------------------- RESULTS ----------------------
🔵 cloudflare.com:443 (104.16.132.229) - RTT:41ms | CN:cloudflare.com | SANs:[cloudflare.com, sni.cloudflaressl.com] | ASN:13335 (CLOUDFLARENET) | TLS:TLS1.3 | ALPN:h2 | H2:ok | Cert:ok
🟢 example.com:443 (93.184.216.34) - RTT:58ms | CN:*.example.com | SANs:[*.example.com, example.com] | ASN:15133 (EDGECAST) | TLS:TLS1.3 | ALPN:http/1.1 | H2:n/a | Cert:ok
🟡 legacy.example.net:443 (198.51.100.20) - RTT:77ms | CN:legacy.example.net | SANs:[legacy.example.net] | ASN:64500 (LEGACY-NET) | TLS:TLS1.2 | ALPN:http/1.1 | H2:n/a | Cert:ok
❌ broken.example.org:443 - FAILED (TLS_HANDSHAKE_FAILED)

-------------------- SUMMARY --------------------
Hosts Checked: 4/4
🔵 Full: 1 | 🟢 Success: 1 | 🟡 Partial: 1 | ❌ Failure: 1
-------------------------------------------------
```

### Flags:

-   `-i <file>`: Input file with hosts/URLs (default: `example_urls.txt`).
-   `-t <int>`: Concurrent workers (default: `12`).
-   `--timeout <duration>`: Per-connection timeout (default: `5s`).
-   `--retries <int>`: Retries per host on failure (default: `3`).
-   `-o <file>`: Output file (optional).
-   `-v`: Verbose/debug output.
-   `--no-asn`: Disable ASN lookups.
-   `--port <port>`: TCP port to connect (default: `443`).

### Other Flags

```sh
tls_checker -version   # Show version
tls_checker -update    # Self-update to latest release
```

---

## License

This project is licensed under the AGPL-3.0 License; see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Luis Colunga (@sinnet3000)

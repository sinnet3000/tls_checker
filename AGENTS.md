# Agents Guide

This repository contains a single Go CLI (`tls_checker`) that performs concurrent TLS diagnostics for a list of hosts. The codebase is intentionally small; most logic lives in `tls_checker.go`.

## Quick Context
- Primary entrypoint: `main()` in `tls_checker.go`.
- Core workflow: parse flags -> load hosts -> run concurrent checks -> print results -> exit status.
- External dependencies: DNS, TLS, optional WHOIS to Team Cymru, optional HTTP/2 probe.

## Key Modules (by function)
- Input parsing: `loadHosts`, `extractHost`, `isComment`.
- Diagnostics: `checkHost`, `diagnose`, `resolveOne`, `dialTLS`, `dialTLSWithFallback`, `h2Probe`.
- ASN lookup: `queryASN` with in-memory cache.
- Output: `formatResult`, `printSummary`, `classify`.

## Invariants and Expectations
- Each target is unique by `host:port`.
- `Result.Success` implies TLS handshake completed; failures populate `Result.Error`.
- `H2OK` is only set when ALPN `h2` is negotiated.
- Output is deterministic by sorting results.

## Trust Boundaries
- Input file lines are untrusted and may be malformed.
- Network calls (DNS/TLS/WHOIS) can fail or hang; timeouts and retries are critical.

## Known Pitfalls
- Long input lines can exceed `bufio.Scanner` defaults.
- Outbound network access is required for real diagnostics and WHOIS.

## Preferred Validation
- `go test ./...`
- `go run . -i urls.txt --no-asn -t 2 --timeout 5s --retries 0`

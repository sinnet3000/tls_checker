# Agent Instructions

## Project

A Go CLI for TLS, ALPN, HTTP/2, and ASN diagnostics. See `README.md` for flags and `go.mod` for the Go version.

## Development and Verification

- Format changed Go files with `gofmt -w <paths>`.
- Run `go test ./...` and `go vet ./...` for Go changes. Add focused regression tests using the existing Go test conventions.
- Use `make build` when checking release builds across the supported platforms.
- Choose live checks based on the changed behavior and report which DNS, TLS, HTTP/2, or ASN paths were exercised.

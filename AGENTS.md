# Agent Instructions

## Project

A Go CLI for TLS, ALPN, HTTP/2, and ASN diagnostics. See `README.md` for flags and `go.mod` for the Go version.

## Working Guidelines

- Inspect the repository to resolve uncertainty before asking the user.
- Make reasonable, reversible assumptions and state those that affect the result. Ask when an unresolved decision materially affects scope, correctness, or an irreversible action.
- Prefer the smallest clear implementation that meets the requirements. Add abstractions, configuration, and defensive handling when justified by actual behavior or requirements.
- Keep changes within the requested scope and match existing style. Avoid unrelated refactoring, formatting, or cleanup.
- Remove imports, variables, and functions made unused by your changes. Mention unrelated issues without expanding the task to fix them.
- For multi-step work, state a brief plan with verifiable outcomes. Verify the changed behavior and report any checks you could not complete.

## Development and Verification

- Format changed Go files with `gofmt -w <paths>`.
- Run `go test ./...` and `go vet ./...` for Go changes. Add focused regression tests using the existing Go test conventions.
- Use `make build` when checking release builds across the supported platforms.
- Choose live checks based on the changed behavior and report which DNS, TLS, HTTP/2, or ASN paths were exercised.

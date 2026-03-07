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
- `go run . -i example_urls.txt --no-asn -t 2 --timeout 5s --retries 0`
## Coding Guidelines

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

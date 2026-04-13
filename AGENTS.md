# Code Agent Instructions for teep

Teep is a secure LLM inference API proxy (Go, stdlib `testing`, no frameworks):

- Teep verifies that API endpoints are running expected docker images in a CVM.
- Teep ensures requests and responses are encrypted at all times.
- Teep ensures this encryption is fully authenticated by TEE attestation.

Teep is designed to BLOCK REQUEST ACTIVITY when enforced validation factors fail.

## Data Flow

The Teep proxy receives an OpenAI-compatible chat request → resolves model to provider →
fetches and validates TEE attestation per policy → forwards (or blocks) the request.

The proxy receives concurrent API inference requests to multiple providers and models from multiple client API consumers simultaneously. All code paths from the HTTP handler inward must be safe for concurrent use. All attestation caches, key pinning, connection pinning, supply chain validation, and supply chain caches must also be safe for concurrent use via multiple clients performing simultaneous access of multiple providers and models.

## Core Commands

- Run local tests: `make check` (quick: fmt + vet + lint + unit tests).
- Run full integration tests: `make integration` (slow; optional API keys or config).
- Generate provider verification reports: `make reports` (requires API keys or config).

## Git Workflow

This repository is managed by git and hosted on github.

### Development Workflow

- For multi-phase plans, use one commit per phase.
- Ensure new code has unit test coverage before committing.
  - Run `make check` before each commit.
  - Stage only specific files you modified. Do not use `git add .` or `git add -A`.
- Ensure major features have integration test coverage upon plan completion.
  - Run `make integration` and `make reports` when finishing a plan or any major change.
- Do not mention audit identifiers in code or commit messages.

## TOP PRIORITY: Data Privacy and Correctness

Teep is *critical infrastructure security software* for handling *highly confidential data*.

**The measure of this software's correctness is how strictly it evaluates providers, not how many providers pass.**

It is more important to protect confidential traffic than it is to provide service. Provider verification failures are not bugs. A provider that fails enforced factors does not meet security requirements. Never modify verification logic to accommodate a non-compliant provider.

This means failing closed is a FEATURE, not a BUG.

## Repository Rules

To ensure data privacy and integrity, adhere to the following rules:

### Follow Go Conventions

- Follow Effective Go idioms and best practices.
- When uncertain, prefer DEFENSE IN DEPTH validation.
- Bound all reads from untrusted sources (HTTP bodies, JSON arrays).
- Use `Connection: close` to prevent TLS connection reuse across attestation boundaries.
- ALWAYS add regression test coverage for audit findings.

### Ensure Concurrency Safety

- **No mutable package-level variables.** State that varies per-request or per-provider must live on a struct or be passed as a parameter. A global that is written during request handling will race under concurrent load.
- Prefer dependency injection (constructor parameters, struct fields, function arguments) over globals for anything that could differ between callers.
- Add concurrent test cases (`sync.WaitGroup` + parallel goroutines) when introducing shared state. Ensure integration-level coverage of these cases.

### Ensure Low Cyclomatic Complexity

Functions must not exceed cyclomatic complexity 32 (enforced by `gocyclo` via golangci-lint). **Plan the decomposition before writing code** — do not write a monolithic function and refactor after.

Each function should do one thing at one level of abstraction. When a function handles multiple verification steps, network I/O, or branching logic, extract named helpers. The orchestrator should read like a checklist:

```go
// Good: orchestrator calls named helpers
func (h *Handler) attestOnConn(...) (*Report, error) {
    raw, err := h.sendAttestationRequest(...)
    tdxResult := h.verifyTDX(ctx, raw, nonce)
    nvidiaResult, nrasResult := h.verifyNVIDIA(ctx, raw, nonce)
    // ... TLS fingerprint check (inline — fatal trust anchor) ...
    compose, repos, digests, sig, rekor := h.verifySupplyChain(ctx, raw, tdxResult)
    return buildReport(...)
}
```

Reference implementations to mirror when adding providers or verification logic:
- **Attestation verification:** `internal/provider/nearcloud/pinned.go:attestOnConn` and `internal/provider/neardirect/pinned.go:attestOnConn`
- **Proxy handler:** `internal/proxy/proxy.go:handleChat`

### Ensure Cryptographic Safety

- All cryptographic comparisons MUST be constant-time (`subtle.ConstantTimeCompare`). Never use `==`, `!=`, `bytes.Equal`, or `strings.EqualFold` on secrets, keys, fingerprints, nonces, or hashes.
- ALWAYS authenticate encryption keys via attestation binding.
- ALWAYS use authenticated encryption. No plaintext fallback.
- Nonce generation MUST use `crypto/rand`. Fail on error; never use a weak source.
- Zero ephemeral key material after use.

### Ensure Attestation Integrity

- Attestation MUST be verified before any request is forwarded.
- Nonces MUST originate from the client, not the server response.
- Never trust provider-asserted "verified" fields without independent cryptographic verification.
- Cache misses MUST trigger full re-attestation, never pass-through.
- Cache eviction MUST NOT allow unattested connections.

### Protect Sensitive Data

- NEVER log or print API keys, inference request data, or inference response data.
- Redact API keys in logs to first few characters only.
- Config files containing secrets should have permission checks.

### Always Fail-Closed

- Validation issues of any kind must FAIL LOUDLY AND FAIL CLOSED.
- Failed validation MUST block requests unless specifically whitelisted by allow_fail or command line switch.
- Error paths MUST only return or propagate errors. Any other behavior is a defect.
- Reject malformed input entirely; never silently drop malformed elements.
- Unknown or misspelled config values MUST be rejected at startup.
- JSON unmarshalling MUST use strict mode (warn on unknown fields, and reject failures).
- If you can't make development progress due to a failing validation, STOP and ask for advice.

### No Fallbacks or Backwards Compatibility

- NEVER weaken or bypass validation behavior unless it has been explicitly disabled.
- NO WORKAROUNDS.
- NO ERROR FALLBACKS.
- NO BACKWARDS COMPATIBILITY.

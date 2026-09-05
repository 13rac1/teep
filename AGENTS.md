# Code Agent Instructions for teep

Teep is a secure LLM inference API proxy (Go, stdlib `testing`, no frameworks):

- Teep verifies that API endpoints are running expected docker images in a CVM.
- Teep ensures requests and responses are encrypted at all times.
- Teep ensures this encryption is fully authenticated by TEE attestation.

Teep is designed to BLOCK REQUEST ACTIVITY when enforced validation factors fail.

## Data Flow

The Teep proxy receives an OpenAI-compatible chat request → resolves model to provider →
fetches and validates TEE attestation per policy → forwards (or blocks) the request.

The proxy receives concurrent API inference requests to multiple models from multiple client API consumers simultaneously, and should support expansion to handle multiple concurrent providers. All code paths from the HTTP handler inward must be safe for concurrent use. All attestation caches, key pinning, connection pinning, supply chain validation, and supply chain caches must also be safe for concurrent use via multiple clients performing simultaneous access of multiple providers and models.

## Key Code Directories

- `cmd/teep/` — CLI entry point, subcommands (`serve`, `verify`), flag definitions.
- `internal/proxy/` — HTTP handler that accepts OpenAI-compatible requests and routes to providers.
- `internal/provider/` — Per-provider attestation and connection logic (subdirs: `nearcloud/`, `neardirect/`, `chutes/`, `venice/`, `nanogpt/`, `phalacloud/`, `tinfoil/`).
- `internal/attestation/` — TDX, NVIDIA, sigstore, Rekor, and supply-chain verification.
- `internal/e2ee/` — End-to-end encryption sessions and relay logic.
- `internal/config/` — Configuration parsing and strict validation.
- `internal/jsonstrict/` — Wrapper around github.com/13rac1/jsonstrict for strict JSON decoding with unknown/missing field detection.
- `internal/tlsct/` — TLS helpers, SPKI fingerprinting, and certificate-transparency-aware HTTP clients.
- `internal/verify/` — Orchestrates multi-factor verification and report generation.
- `internal/multi/` — Concurrent multi-provider verification.
- `internal/integration/` — Live and captured integration coverage, including provider replay testdata.
- `internal/capture/` — HTTP capture/replay support for deterministic attestation tests.

## Core Commands

- Run local tests: `make check` (quick: fmt + vet + lint + unit tests).
- Run full integration tests: `make integration` (slow; optional API keys or config).
- Generate provider verification reports: `make reports` (requires API keys or config).

## Git Workflow

This repository is managed by Git and hosted on GitHub.

- For multi-phase plans, use one commit per phase.
- Ensure new code has unit test coverage before committing.
  - Run `make check` before each commit.
  - Stage only specific files you modified. Do not use `git add .` or `git add -A`.
- Ensure major features have integration test coverage upon plan completion.
  - Run `make integration` and `make reports` when finishing a plan or any major change.
- Do not mention audit identifiers in code or commit messages.

## Repository Rules

Teep is *critical infrastructure security software* for handling *highly confidential data*.

**The measure of this software's correctness is how strictly it evaluates and authenticates providers, not how many providers pass factor authentication checks or provide service.**

To ensure data confidentiality and integrity, adhere to the following rules:

### Always Fail-Closed

Failing closed is a FEATURE, not a BUG. It is more important to protect confidential traffic than it is to provide service. Provider verification failures are not bugs.

- Validation issues of any kind must FAIL LOUDLY AND FAIL CLOSED.
- Reject malformed input entirely; never silently drop malformed elements.
- Unknown, misspelled, ambiguous, or semantically invalid config values MUST be rejected at startup.
- JSON unmarshalling MUST use the internal/jsonstrict parser.
- All low-level parsers MUST return unknown field names to callers instead of logging or deduplicating them internally. Callers own the policy decision to fail, warn once per logical operation, or use lower-severity logging in hot paths.
- Error paths MUST fail closed. They may also log, clean up, zero key material, invalidate caches, and record metrics, but must never silently continue or return success.
- Return errors for request-time and untrusted-input failures. Panics are acceptable for startup failures and violated internal invariants after validated construction (such as nil values for required parameters and members).
- Fail loudly, not silently: when an expected factor or verification step is skipped or fails because prerequisites are missing, malformed, or unexpectedly unavailable, emit a clear non-secret diagnostic at warn level or stronger.
- Failed factor validation MUST block requests unless specifically whitelisted by `allow_fail`, by `--force` (debug builds only: bypasses all enforced factors), or by `--offline` (skips network-dependent checks such as Intel PCS, NRAS, sigstore, and Proof of Cloud).
- Positive-path integration tests MUST use the same factor enforcement as `teep verify` and `teep serve`. Unit and negative-path tests may select an explicit policy only when that policy behavior is itself under test.
- If you can't make development progress due to a failing factor or other validation, STOP and ask for advice.

### Always Ensure Attestation Integrity

- Every forwarded request MUST be covered by a currently valid attestation for its provider, model or route, cryptographic identity, and key epoch.
- Nonces MUST originate from the client, not the server response.
- Never trust provider-asserted "verified" fields without independent cryptographic verification.
- Provider and model routing MUST ensure uniqueness and determinism.
- Every inference TLS handshake must use TLS-1.3, pass WebPKI, and CT validation must remain enforced, before sending the request.
- Connection reuse MUST remain within the currently valid attestation scope:
  - Key any TLS connection pools by provider, authority, and applicable attestation scope.
  - **TLS-SPKI providers:**
    - TLS reuse attestation scope is the SPKI pin.
    - Perform the currently attested SPKI fingerprint check *before* any request bytes are sent.
    - Disable TLS session resumption for TLS-SPKI pools. Elsewhere, resumption MUST NOT bypass attestation-bound identity checks.
  - **E2EE/router providers:**
    - Attestation scope is the attested backend model endpoint and E2EE key.
    - Relay TLS connections may be reused independently, but every request must use a currently attested model/route E2EE key.
    - Invalidate and re-attest on key expiry, rejection, or change.
  - Attestation or key cache eviction MUST prevent later use of stale attestation, pin, or key material. Rotate only connection pools whose trust depends on that epoch.
  - We prefer HTTP/2 usage and associated request multiplexing where possible, within these constraints.
  - `Connection: close` is a last-resort HTTP/1.1 boundary mechanism, never a per-request default; HTTP/2 forbids it.
- An attestation cache miss MUST initiate or join full re-attestation; never pass through unverified.

### Always Ensure Cryptographic Safety

- All cryptographic comparisons MUST be constant-time (`subtle.ConstantTimeCompare`). Never use `==`, `!=`, `bytes.Equal`, or `strings.EqualFold` on secrets, keys, fingerprints, nonces, or hashes.
- ALWAYS authenticate encryption keys via attestation binding.
- ALWAYS use authenticated encryption. No plaintext fallback.
- Tests that exercise TLS clients or network trust MUST use a TLS test server, normally `httptest.NewTLSServer()`.
  - Plain HTTP is permitted only when plaintext behavior is the subject of the test and the existing lint policy allows it.
  - When a production client must retain system WebPKI configuration, use `testtls.RunWithFallbackRoot` and `authority.NewTLSServer`.
  - Never set custom roots or `InsecureSkipVerify` on the production transport.
- Tests of cryptographic behavior MUST exercise the production cryptographic pathway rather than replacing it with plaintext or unauthenticated mocks.
- Nonce generation MUST use `crypto/rand`. Fail on error; never use a weak source.
- Zero ephemeral key material after use.

### Always Ensure Concurrency Safety

- **No package-level variables written after init.** State that varies per-request or per-provider must live on a struct or be passed as a parameter.
- Exported package-level `var` declarations holding security policy or runtime state are forbidden unless they are truly immutable and callers cannot mutate the underlying value. Do not expose maps, slices, or pointers that callers can modify.
- Prefer dependency injection (constructor parameters, struct fields, function arguments) over globals for anything that could differ between callers.
- Use `sync.Mutex`/`sync.RWMutex` for protecting shared data structures (caches, maps). Prefer channels for coordination between goroutines. Use `sync.Once` for safe lazy initialization.
- Add concurrent test cases (`sync.WaitGroup` + parallel goroutines) when manipulating shared state. Ensure integration-level coverage of these cases.
- Always run `make check` and `make integration` to ensure new and existing concurrency tests pass (all tests use `go test -race`).

### Always Protect Sensitive Data

- NEVER log or print API keys, inference request data, or inference response data.
- Redact API keys in logs to first few characters only.
- Config files containing secrets should have permission checks.

### Always Ensure Low Cyclomatic Complexity

Functions must not exceed cyclomatic complexity 32 (enforced by `gocyclo` via golangci-lint). **Plan the decomposition before writing code** — do not write a monolithic function and refactor after.

Each function should do one thing at one level of abstraction. When a function handles multiple verification steps, network I/O, or branching logic, extract named helpers. The orchestrator should read like a checklist:

```go
// Good: orchestrator calls named helpers
func (h *Handler) attestOnConn(...) (*Report, error) {
    raw, err := h.sendAttestationRequest(...)
    tdxResult := h.verifyTDX(ctx, raw, nonce)
    nvidiaResult, nrasResult := h.verifyNVIDIA(ctx, raw, nonce)
    // ... TLS fingerprint check (inline — fatal trust root) ...
    compose, repos, digests, sig, rekor := h.verifySupplyChain(ctx, raw, tdxResult)
    return buildReport(...)
}
```

Reference implementations to mirror when adding providers or verification logic:

- **Attestation verification:** `internal/proxy/proxy.go:fetchVerified` and `internal/verify/verify.go:runEvidence`
- **Proxy handler:** `internal/proxy/proxy.go:handleChat`

### Follow Go Conventions

- Follow Effective Go idioms and best practices.
- When uncertain, prefer DEFENSE IN DEPTH validation: a check of a different kind, not the same property re-checked in a second place (SEE: `docs/writing_style.md` § Security).
- Bound all reads from untrusted sources (HTTP bodies, JSON arrays).
- Prefer mocks over live tests: any live-network test must require the `TEEP_LIVE_TESTS` environment variable or API keys.
- ALWAYS add regression test coverage for code review issues and audit findings.

### Writing Style

Use ASD-STE100 (Simplified Technical English) as the basis for style decisions in comments, commit messages, and user-visible strings: active voice, one meaning per word, no metaphors or idioms, no invented compound words.

#### Allowed metaphors

A metaphor is allowed when it is the name of the thing. It is not allowed when it decorates a name that already exists.

A metaphor is a name when it has a definition that people outside this project share, and a reader who does not know it can look it up and find that definition. Test: could it be the title of a section in a reference book about the subject?

Replace a metaphor when any of these is true:

1. A plain word has the same meaning. A `gate` is a check. Code is not `wired`, it is connected, invoked, enabled, or configured — use the one that states what happened. You do not `hit` an endpoint, you send a request to it.
2. The word rates the code instead of describing it. A `sanity check` says how much the author trusts the check, not what the check does. `quick`, `simple`, and `best` fail the same way.
3. The word is less exact than the thing it names. `byte-level surgery` does not say which bytes change. A `generous` timeout does not say how long.
4. The word is borrowed from another field and a common word means the same thing. A `gloss` is a definition. A `corpus` is a set of files.

A term that is a name can still be wrong in one place. Use it only where its definition holds.

SEE: `docs/writing_style.md` for the approved terms. Check that list before you replace a word.

The word "gate" refers only to a physical fence. Do not use it for checks, conditions, or enforcement.

### No Fallbacks or Backwards Compatibility

- NEVER weaken or bypass factor validation, unless it has been explicitly disabled via `--offline`, `--force`, or an `allow_fail` policy.
- NEVER fall back to plaintext, accept or use empty keys, or perform unauthenticated cryptography.
- NEVER convert an error into successful or less strictly validated behavior through a fallback path.
- NEVER add exemptions to teeplint for new code.
- Tests MUST NOT special-case production code to bypass security behavior.
- Teep does NOT preserve compatibility with previous code revisions, prior provider API versions, prior config file formats, prior cli commands, or previous internal API behaviors. Do NOT add backwards compatibility code in these or any similar scenarios.

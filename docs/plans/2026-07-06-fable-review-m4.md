# Plan: Fable review M4 — DNS rebinding against the localhost API and dashboard

Source: `docs/2026-07-02-fable-review.md`, finding M4. Verified still present
on main @ 4152307. Pairs with M5 (dashboard XSS) — fix together; M4's Host
check also removes M5's cross-origin amplification.

## Current state

- All routes — dashboard (`GET /{$}`), `/events`, `/metrics`, `/explore`,
  `POST /explore/attest`, `POST /explore/infer`, and all `/v1/*` — are
  registered with no Host-header check (`internal/proxy/proxy.go:534-551`);
  the comment at :531-533 explicitly relies on loopback binding for access
  control.
- No `Content-Security-Policy`, `X-Frame-Options`, or
  `X-Content-Type-Options` is set on any response (grep confirms none in
  `internal/proxy`).
- `internal/config/config.go:652-667` (`warnNonLoopback`) only WARNs on a
  non-loopback `TEEP_LISTEN_ADDR` (see fable-review L11).

Failure scenario: an operator's browser visits a malicious page; the
attacker rebinds their DNS name to `127.0.0.1`, becoming same-origin with
`http://attacker.com:8337`. Loopback binding is defeated; the page can
enumerate models, trigger attestations, run inference on the operator's
paid API keys, and scrape `/metrics` and the dashboard.

## Design

### 1. Host allowlist middleware (the actual fix)

- Add a `hostGuard(next http.Handler)` middleware wrapping the entire mux
  (single wrap in `registerRoutes`, not per-route). Allowed authorities:
  `127.0.0.1:<port>`, `[::1]:<port>`, `localhost:<port>`, plus the exact
  configured listen host when the operator deliberately binds
  non-loopback. Compare host and port both; use `net.SplitHostPort` +
  `net.ParseIP` (no substring matching), treat a missing port as the
  configured one.
- Mismatch → `403` with a short non-secret body naming the rejected Host
  value (fail loudly), plus a rate-limited WARN log — a rebinding attempt
  is a security event worth surfacing.
- Applies to **all** routes including `/v1/*`: OpenAI SDK clients send
  `Host: 127.0.0.1:8337` or `localhost:8337` naturally, so legitimate
  clients are unaffected. Reject unknown Hosts outright — no config knob to
  disable the guard, only the allowlist extension via the configured
  listen address (no bypass fallback per AGENTS.md).

### 2. Security headers on all responses (defense in depth)

Set in the same middleware:

- Dashboard/HTML routes: `Content-Security-Policy: default-src 'self';
  script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors
  'none'` — tighten `unsafe-inline` later by moving inline scripts in
  `internal/proxy/templates/` to hashed/static assets; the M5 fix reduces
  what inline injection can do meanwhile. Plus `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- API routes: `X-Content-Type-Options: nosniff` and
  `Cache-Control: no-store`.

### 3. Cross-origin request hardening

- Reject state-changing dashboard endpoints (`POST /explore/*`) when
  `Sec-Fetch-Site` is present and not `same-origin`/`none`; keep the
  existing JSON-content-type preflight barrier. (Host check already
  defeats classic rebinding; this covers future browser edge cases
  cheaply.)

## Files

- `internal/proxy/proxy.go` — middleware, `registerRoutes` wrap; thread the
  configured listen authority into `Server`.
- `internal/config/config.go` — expose the resolved listen host/port to the
  proxy (it already parses `TEEP_LISTEN_ADDR`).
- `internal/proxy/templates/` — no change required for M4 itself (CSP is
  header-side), but see M5.

## Tests

- Host guard table: allowed (`127.0.0.1:port`, `[::1]:port`,
  `localhost:port`, configured host) → 200; rebound hostname
  (`attacker.example:port` resolving anywhere) → 403; empty/garbage Host →
  403; port mismatch → 403; IPv6 bracket forms.
- Every response carries the expected headers (walk the route table).
- `POST /explore/infer` with `Sec-Fetch-Site: cross-site` → rejected.
- Regression: OpenAI-SDK-shaped request with default Host header still
  works end-to-end (integration).
- Concurrent access through the middleware (`-race`), since it wraps the
  hot path.

## Verification

- `make check`; `go test -race ./internal/proxy/...`; `make integration`;
  manual: `curl -H 'Host: evil.example:8337' http://127.0.0.1:8337/` → 403.

## Constraints (AGENTS.md)

- Fail closed: unknown Host is rejected, not warned. No disable flag.
- The 403 body and logs contain no secrets (Host value only).
- Middleware must be allocation-light on the `/v1/*` hot path (string
  compares against a precomputed set; no per-request parsing beyond
  SplitHostPort).

## Open questions

- Should a non-loopback bind (L11) *require* an explicit
  `--allow-non-loopback` style opt-in at the same time? Recommended yes —
  do it in the same PR as this middleware since both touch listen-address
  policy.

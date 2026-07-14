# Plan: Fable review M5 — esc() does not escape quotes → attribute-injection XSS

Source: `docs/2026-07-02-fable-review.md`, finding M5. Verified still present
on main @ 4152307. Pairs with M4 (Host allowlist + CSP) — land together.

## Current state

- The helper (`internal/proxy/templates/_base_js.html:10`):
  `function esc(s){ var d=document.createElement("div"); d.textContent = s==null?"":s; return d.innerHTML; }`
  — escapes `&`, `<`, `>` but **not** `"` or `'`.
- Attribute-context sinks (double-quoted attributes concatenated with
  `esc(...)`):
  - `internal/proxy/templates/explore.html`: `data-model` (:196),
    `data-attest`/`data-infer` (:206-207), `id="attest-…"`/`id="infer-…"`
    (:209-210), `data-prov-toggle` (:252).
  - `internal/proxy/templates/dashboard.html`: `data-key` (:383),
    `data-toggle` (:384).
- Values flow verbatim from each provider's `/v1/models` response
  (`prefixModelID` rewrites only the id prefix, `proxy.go:3377-3395`), so a
  malicious/compromised provider — or a MITM of a non-attested model-listing
  endpoint — controls them.
- No CSP to contain an injected handler (see M4).

Failure scenario: a provider returns a model id like
`x" autofocus onfocus="fetch('/explore/infer',…)` — the unescaped `"`
breaks out of the attribute and executes attacker JS in the dashboard
origin, chaining into M4's actions (drive inference on the operator's
keys).

## Design

Fix the sink class, not just the character list:

1. **Build DOM via APIs, not string concatenation (primary fix).** Convert
   the row/button construction in `explore.html` and `dashboard.html` from
   `innerHTML += '<button data-model="'+esc(id)+'">…'` to
   `document.createElement` + `el.setAttribute('data-model', id)` +
   `el.textContent = …`. `setAttribute`/`textContent` are injection-proof
   for both attribute and text contexts, remove every current sink, and
   make future template edits safe by default. The templates are small;
   this is a bounded rewrite of the two render functions.
2. **Harden `esc()` anyway (defense in depth).** Replace the
   textContent/innerHTML trick with an explicit replacer covering
   `& < > " '` (and backtick for safety), so any remaining or future
   string-concatenated use is still attribute-safe. Keep the helper name
   and location (`_base_js.html`).
3. **CSP from M4** (`script-src 'self' 'unsafe-inline'` initially,
   `frame-ancestors 'none'`) contains anything that slips through; the
   longer-term `unsafe-inline` removal belongs to M4's follow-up.
4. **Server-side validation of model ids (optional, recommended).**
   `prefixModelID` currently accepts any string id from providers. Reject
   ids containing characters outside `[A-Za-z0-9._:/-]` at the proxy
   boundary (fail loudly per provider entry — reject the malformed element
   set entirely, i.e. fail the provider's model list, not silently drop
   one element, per AGENTS.md "never silently drop malformed elements").
   This turns dashboard safety into a data invariant instead of a
   rendering concern.

## Files

- `internal/proxy/templates/_base_js.html` — new `esc()`.
- `internal/proxy/templates/explore.html`, `dashboard.html` — DOM-API
  rendering.
- `internal/proxy/proxy.go` — model-id character validation in
  `prefixModelID`/`fetchModels` (step 4).

## Tests

- Go-side: template rendering is client-side JS, so the enforceable tests
  are step 4's: `prefixModelID` with a quote/angle-bracket/backtick id →
  provider list rejected with a loud error; valid ids pass.
- Add a small JS-free regression: serve the dashboard via `httptest`, fetch
  `/v1/models` with a hostile-id fixture provider, assert the proxy
  rejected the list (the hostile id never reaches the browser).
- Manual/browser check: hostile model id from a stub provider renders as
  inert text with steps 1-2 applied (documented in the PR, since there is
  no headless-browser harness in this repo).

## Verification

- `make check`; `go test -race ./internal/proxy/...`; `make integration`;
  manual dashboard smoke test against a stub provider returning a
  quote-bearing model id.

## Constraints (AGENTS.md)

- Reject malformed input entirely; never silently drop malformed elements
  (step 4's list-level rejection).
- Defense in depth: all four layers (DOM APIs, esc(), CSP, server-side
  validation) are cheap; do them all rather than picking one.

# Plan: Tinfoil-Specific Endpoints

Extracted from `tinfoil_support.md`. These are Tinfoil-proprietary API
surfaces that no other provider implements. They can be added after the
core Tinfoil proxy and verification support is complete.

## `/v1/convert/file` (Document/File Conversion)

Tinfoil's `doc-upload` model converts documents (PDF, etc.) to
text/vision tokens for use by inference models.

### Request format
- Method: `POST`
- Content-Type: `multipart/form-data`
- Multipart fields:
   - `files`: one or more uploaded file parts
   - `to_format`: set to `md` for markdown extraction compatibility
- Query parameter: optional `mode` in `{text, vision, images, raw, vlm}`
- Model routing:
   - cloud: model `doc-upload` required in request
   - direct: resolve `doc-upload` enclave domain when available

### Response format (successful)
- JSON object with `document` payload containing:
   - `md_content` (string)
   - `pages` (array of page objects)
      - `page` (number)
      - `text` (string)
      - `image` (string; optional depending on mode)
      - `is_scanned` (boolean)

### Encryption
- Request and response bodies are EHBP-protected (non-empty body exchange).
- Preserve multipart framing and part headers exactly across EHBP
  encryption/decryption; do not normalize or re-order multipart parts.
- Missing/invalid EHBP response nonce is fail-closed.

### Tests
- Verify multipart file upload behavior and mode query handling.
- Verify EHBP body encryption and response authentication.
- Unsupported conversion mode fails closed.
- Encrypted conversion request missing `Ehbp-Response-Nonce` fails closed.
- (direct) Verify routing to `doc-upload` enclave domain when available.
- (direct) Fails closed when doc-upload enclave is unavailable or
  attestation fails.

---

## `/v1/realtime` (WebSocket)

OpenAI-compatible realtime API over WebSocket. Unlike all other inference
endpoints, WebSocket connections have no EHBP body-layer encryption —
confidentiality relies solely on attested TLS (SPKI pinning).

### Handshake/routing
- Transport: WebSocket over attested TLS (no EHBP framing).
- Model source:
   - model subdomain if present, else
   - required query parameter `?model=<name>`.
- Authentication:
   - preferred: `Authorization: Bearer <api-key>`
   - browser compatibility: websocket subprotocol
      `openai-insecure-api-key.<api-key>` when Authorization cannot be set.

### Message compatibility
- Proxy should transparently relay OpenAI-compatible realtime event frames.
- Do not rewrite event payload schemas except for strict security checks
  (attestation/TLS binding/auth).

### Security properties
- Confidentiality/integrity comes from attested TLS + SPKI binding.
- No EHBP headers, no EHBP decryptors.
- `e2ee_usable` emits `Skip` for this path — users should understand
  that `/v1/realtime` has no second encryption layer.

### Tests
- Verify attestation/SPKI before upgrade.
- Verify model routing via subdomain or `?model=` query.
- Verify browser subprotocol auth compatibility.
- Missing websocket model parameter fails with explicit error.
- Invalid websocket auth/subprotocol fails closed.
- (direct) Verify direct websocket connection to realtime-capable model
  enclave with attested TLS/SPKI binding.
- (direct) Fails closed on model/domain mismatch.

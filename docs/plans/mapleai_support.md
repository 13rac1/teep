# Plan: MapleAI Provider Support

## TL;DR

Add MapleAI as a new teep provider. MapleAI runs LLM inference through an AWS Nitro
Enclave proxy at `https://enclave.trymaple.ai`, using COSE_Sign1 attestation documents
with ECDSA P-384 signatures chaining to the AWS Nitro root certificate, X25519 key
exchange, and ChaCha20-Poly1305 end-to-end encryption. This requires: a new Nitro
attestation parsing/verification library, generalized `tee_*` attestation factors, an
E2EE session implementation, provider wiring, and comprehensive test coverage.

## Architecture Decision: Non-Pinned with Session Caching

MapleAI's security model binds the E2EE key exchange to the attestation document: the
server's X25519 public key is embedded in the COSE_Sign1-signed attestation payload.
TLS pinning is unnecessary because:

- Nitro attestation documents do not include TLS certificate fingerprints
- E2EE provides equivalent channel security — only the attested enclave holds the
  X25519 private key corresponding to the `public_key` in the signed attestation doc
- The key exchange is cryptographically bound to the attestation via the signed
  `public_key` field

This matches the Chutes provider pattern (non-pinned, E2EE-secured) rather than
nearcloud/neardirect (TLS-pinned).

**Session lifecycle:**
- Attestation report cached per `(provider, model)` key with 1h TTL (existing
  `attestation.Cache`, already model-scoped via `cacheKey{provider, model}`)
- E2EE session `(session_id, session_key)` cached alongside attestation on the
  provider's E2EE struct, keyed by the attested `public_key`
- On session failure (HTTP 400, decryption error): re-attest + new key exchange
- On attestation cache miss/expiry: full attestation + key exchange

**Investigation findings:**
- MapleAI's backend at `enclave.trymaple.ai` serves all models from a single Nitro
  Enclave, so the X25519 public key is stable across models and requests within an
  enclave lifecycle
- The Nitro enclave acts as a router/proxy; actual GPU inference runs on NVIDIA GPU
  TEEs via a third party (per OpenSecret technical blog). This means Nitro attestation
  covers the frontend enclave only — **GPU-side attestation is not currently exposed
  through the MapleAI attestation endpoint**, which is a known gap
- A session key is generated per key exchange, tied to a server-issued `session_id`;
  the server may timeout sessions independently

## Protocol Specifications

All protocols below are described from publicly documented standards and the public
OpenSecret SDK documentation (https://docs.opensecret.cloud/). No proprietary source
code is referenced.

### 1. AWS Nitro Attestation Document Format

**Reference:** [AWS Nitro Enclaves — Verifying the Root of Trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

The attestation document is a **COSE_Sign1** structure (RFC 9052 §4.2), encoded in
**CBOR** (RFC 8949), structured as a 4-element CBOR array:

| Index | Name        | Type  | Content                                          |
|-------|-------------|-------|--------------------------------------------------|
| 0     | protected   | bstr  | CBOR-encoded protected headers map `{1: -35}` (algorithm: ECDSA-384) |
| 1     | unprotected | map   | Empty map `{}`                                   |
| 2     | payload     | bstr  | CBOR-encoded attestation document (see below)    |
| 3     | signature   | bstr  | ECDSA P-384 raw signature (r‖s, 96 bytes)        |

The tagged COSE_Sign1 structure uses CBOR tag 18.

**Attestation payload** (CBOR map, per AWS documentation):

| Field        | CBOR Type          | Description                                    |
|--------------|--------------------|------------------------------------------------|
| `module_id`  | text string        | Enclave module identifier                      |
| `timestamp`  | uint (.size 8)     | UTC milliseconds since UNIX epoch              |
| `digest`     | text string        | Always `"SHA384"`                              |
| `pcrs`       | map<uint → bstr>   | Platform Configuration Registers (48 bytes each, SHA-384) |
| `certificate`| bstr               | DER-encoded leaf X.509 certificate             |
| `cabundle`   | array<bstr>        | DER-encoded certificate chain (root first)     |
| `public_key` | bstr or nil        | Server's **X25519 public key** (32 bytes) for E2EE |
| `user_data`  | bstr or nil        | Application-specific data                      |
| `nonce`      | bstr or nil        | Client nonce (UTF-8 encoded string as bytes)   |

### 2. COSE_Sign1 Signature Verification

**Reference:** RFC 9052 §4.4 — Signing and Verification Process

1. CBOR-decode the outer 4-element array
2. Extract `protected` (index 0), `payload` (index 2), `signature` (index 3)
3. Construct `Sig_structure`: CBOR array `["Signature1", protected, b"", payload]`
4. CBOR-encode the `Sig_structure` → this is the signed message
5. Parse the leaf certificate (from payload's `certificate` field) as X.509 DER
6. Extract the P-384 public key from the leaf certificate
7. Verify the ECDSA-P384-SHA384 signature over the `Sig_structure` bytes
8. **Signature format**: Raw r‖s (96 bytes total: 48 bytes r + 48 bytes s), NOT ASN.1
   DER. Must convert to ASN.1 for Go's `ecdsa.VerifyASN1`, or use
   `crypto/ecdsa.Verify` with `r, s *big.Int` parsed from the raw bytes.

### 3. Certificate Chain Validation

**Reference:** [AWS Nitro Enclaves Root of Trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)

The AWS Nitro root certificate is available from:
`https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`

Root certificate fingerprint (SHA-256):
```
64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
```

Root certificate subject: `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`
Root certificate lifetime: 30 years. Algorithm: ECDSA P-384.

**Validation steps:**

1. `cabundle` is ordered `[ROOT_CERT, INTERM_1, INTERM_2, ..., INTERM_N]` (root first)
2. `cabundle[0]` must be **byte-identical** to the embedded AWS Nitro root cert DER
3. Each certificate in `cabundle` parsed as X.509 DER; check time validity
   (`NotBefore ≤ now ≤ NotAfter`)
4. Chain validation: root → intermediate(s). Each cert's signature verified against
   parent cert's public key
5. The leaf `certificate` from the payload: its issuer must match the last cabundle
   cert's subject, and its signature must verify against that cert's public key
6. Leaf cert time validity check
7. **Algorithms**: ECDSA P-384/SHA-384 (OID `1.2.840.10045.4.3.3`) primary, with
   fallback to P-256/SHA-256 (OID `1.2.840.10045.4.3.2`)

### 4. PCR Validation

**Reference:** [AWS Nitro Enclaves Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md), [OpenSecret Remote Attestation Guide](https://docs.opensecret.cloud/docs/guides/remote-attestation/)

AWS Nitro PCR semantics:

| PCR | Size     | Description                                          |
|-----|----------|------------------------------------------------------|
| 0   | 48 bytes | Enclave image file hash (primary measurement)        |
| 1   | 48 bytes | Linux kernel and bootstrap hash                      |
| 2   | 48 bytes | Application code hash                                |
| 3   | 48 bytes | IAM role assigned to parent instance (not for attestation) |
| 4   | 48 bytes | Instance ID of parent instance (changes per instance) |
| 8   | 48 bytes | Enclave image signing certificate hash               |

**Debug mode detection**: When an enclave runs in debug mode, **PCR0 is all zeros**
(48 zero bytes). This must be detected and cause `tee_debug_disabled` to FAIL.

**PCR0 is the primary measurement** for MapleAI. The default measurement policy should
contain known-good PCR0 values. These can be obtained by:
1. Fetching a live attestation document from the production endpoint
2. Consulting OpenSecret's published PCR history at:
   - Production: `https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrProdHistory.json`
   - Development: `https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrDevHistory.json`

PCR1/PCR2 should be validated when known-good values are available, but may be in
`allow_fail` initially.

### 5. Attestation Fetch Endpoint

```
GET /attestation/{nonce}
Host: enclave.trymaple.ai
```

- `{nonce}`: Client-generated UUID v4 string (e.g., `"550e8400-e29b-41d4-a716-446655440000"`)
- Response: `{"attestation_document": "<base64-encoded COSE_Sign1 binary>"}`
- Content-Type: `application/json`

**Nonce verification**: After parsing the attestation payload, the `nonce` field
(UTF-8 decoded) must match the client-generated nonce. Mismatch → FAIL CLOSED.

**NOTE**: Unlike teep's existing providers which use a 32-byte hex nonce
(`attestation.Nonce`), MapleAI uses a UUID v4 string nonce. The MapleAI attester must
generate a UUID v4 rather than using `attestation.NewNonce()`. However, the nonce
still serves the same anti-replay purpose.

### 6. Key Exchange Protocol

After successful attestation verification:

```
POST /key_exchange
Host: enclave.trymaple.ai
Content-Type: application/json

{
  "client_public_key": "<base64 of 32-byte X25519 public key>",
  "nonce": "<same UUID nonce used for attestation>"
}
```

Response:
```json
{
  "encrypted_session_key": "<base64 of nonce(12) || ciphertext>",
  "session_id": "<uuid>"
}
```

**Key exchange steps** (all using Go stdlib + `golang.org/x/crypto`):

1. Generate ephemeral X25519 keypair (RFC 7748): `curve25519.ScalarBaseMult` or
   `ecdh.X25519().GenerateKey(crypto/rand)`
2. Extract server's X25519 public key from verified attestation document's
   `public_key` field
3. **CRITICAL**: Verify the server public key used for ECDH matches the `public_key`
   from the verified attestation document using `subtle.ConstantTimeCompare`.
   This is the attestation-to-encryption binding.
4. Compute shared secret: `X25519(client_private_key, server_public_key)` → 32 bytes
5. Base64-decode `encrypted_session_key`
6. Split: first 12 bytes = nonce, remainder = ciphertext
7. Decrypt with **ChaCha20-Poly1305** (RFC 8439) using the shared secret as the
   symmetric key
8. Decrypted result: 32-byte session key
9. Store `(session_id, session_key)` for subsequent API calls
10. **Zero the ephemeral X25519 private key and shared secret after use**

### 7. Encrypted API Request Format

All API requests after key exchange use the session:

```
POST /v1/chat/completions
Host: enclave.trymaple.ai
Content-Type: application/json
x-session-id: <session_id UUID>
Authorization: Bearer <api_key>

{"encrypted": "<base64 of nonce(12) || ciphertext>"}
```

**Encryption steps:**
1. JSON-serialize the OpenAI-compatible request body
2. Generate random 12-byte nonce via `crypto/rand`
3. Encrypt with ChaCha20-Poly1305 using `session_key` → ciphertext (includes 16-byte
   Poly1305 tag)
4. Concatenate: `nonce(12) || ciphertext`
5. Base64-encode
6. Wrap in JSON: `{"encrypted": "<base64>"}`

### 8. Encrypted Response Format (Non-Streaming)

```json
{"encrypted": "<base64 of nonce(12) || ciphertext>"}
```

**Decryption steps:**
1. Parse JSON, extract `encrypted` field
2. Base64-decode → binary blob
3. Split: first 12 bytes = nonce, remainder = ciphertext
4. ChaCha20-Poly1305 decrypt with `session_key`
5. Parse decrypted bytes as OpenAI-compatible JSON response

### 9. Encrypted SSE Streaming Format

For `stream: true` requests:

1. Request encrypted identically to non-streaming
2. Response is an SSE event stream (`Content-Type: text/event-stream`)
3. Each `data:` line contains a **base64-encoded encrypted chunk** (raw base64 string,
   NOT wrapped in JSON)
4. Per-chunk decryption:
   - Base64-decode the `data:` line value
   - Split: first 12 bytes = nonce, remainder = ciphertext
   - ChaCha20-Poly1305 decrypt with `session_key`
   - Parse decrypted bytes as `ChatCompletionChunk` JSON
5. `data: [DONE]` signals end of stream (not encrypted, pass through)
6. Non-base64 data lines (heartbeats, empty lines) are silently skipped

**This is whole-body encryption** (entire chunk encrypted), unlike NearCloud/Venice
(per-field encryption within JSON). This requires a dedicated SSE relay function
similar to `relay_chutes.go`, NOT the generic per-field `RelayStream` from `relay.go`.

### 10. Available API Endpoints

| Method | Path                    | Purpose                            | Encrypted |
|--------|-------------------------|------------------------------------|-----------|
| GET    | /health                 | Health check                       | No        |
| GET    | /v1/models              | List models (OpenAI-compatible)    | No        |
| GET    | /attestation/{nonce}    | Fetch attestation document         | No        |
| POST   | /key_exchange           | Establish E2EE session             | No (but uses ECDH) |
| POST   | /v1/chat/completions    | Chat completions                   | Yes       |
| POST   | /v1/embeddings          | Create embeddings                  | Yes       |

### 11. Session Retry Protocol

On session or decryption errors (HTTP 400, ChaCha20-Poly1305 authentication failure):
1. Invalidate the cached session for this model
2. Invalidate the cached attestation report for this model
3. Re-perform full attestation handshake (attestation fetch → verify → key exchange)
4. Retry the original request with the new session
5. If retry also fails, return error to client (do NOT retry indefinitely)

## Attestation Factor Design

### Factor Rename: `tdx_*` → `tee_*`

This plan uses generalized `tee_*` factor names throughout. The tinfoil support plan
(`docs/plans/tinfoil_support.md`) proposes an atomic rename of existing `tdx_*` factors
to `tee_*` to support multiple TEE hardware platforms (Intel TDX, AMD SEV-SNP, AWS
Nitro). The rename mapping:

| Current (TDX-specific)    | Generalized            | Applies To             |
|---------------------------|------------------------|------------------------|
| `tdx_quote_present`       | `tee_quote_present`    | TDX, SEV-SNP, Nitro   |
| `tdx_quote_structure`     | `tee_quote_structure`  | TDX, SEV-SNP, Nitro   |
| `tdx_cert_chain`          | `tee_cert_chain`       | TDX, Nitro             |
| `tdx_quote_signature`     | `tee_quote_signature`  | TDX, SEV-SNP, Nitro   |
| `tdx_debug_disabled`      | `tee_debug_disabled`   | TDX, Nitro             |
| `tdx_mrseam_mrtd`         | `tee_mrseam_mrtd`      | TDX (MRTD/MRSEAM), Nitro (PCR0) |
| `tdx_hardware_config`     | `tee_hardware_config`  | TDX (RTMR0), Nitro (PCR1) |
| `tdx_boot_config`         | `tee_boot_config`      | TDX (RTMR1/2), Nitro (PCR2) |
| `tdx_reportdata_binding`  | `tee_reportdata_binding` | TDX, Nitro (public_key binding) |
| `intel_pcs_collateral`    | `intel_pcs_collateral` | TDX only (unchanged)   |
| `tdx_tcb_current`         | `tdx_tcb_current`      | TDX only (unchanged)   |
| `tdx_tcb_not_revoked`     | `tdx_tcb_not_revoked`  | TDX only (unchanged)   |

**Implementation note**: If the `tee_*` rename has not yet been performed when MapleAI
implementation begins, the implementer should either (a) perform the rename as Phase 1
of this plan, or (b) use `nitro_*` prefixed names initially and participate in the
rename later. Option (a) is preferred for consistency.

### MapleAI Enforced Factor Set

**Enforced factors** (must pass or request is blocked):

| Factor                   | What It Verifies (Nitro)                          |
|--------------------------|---------------------------------------------------|
| `nonce_match`            | Client UUID nonce matches attestation doc nonce    |
| `tee_quote_present`      | COSE_Sign1 attestation document received           |
| `tee_quote_structure`    | Valid CBOR structure, all required payload fields  |
| `tee_cert_chain`         | Certificate chain validates to AWS Nitro root      |
| `tee_quote_signature`    | COSE_Sign1 ECDSA-P384 signature verifies           |
| `tee_debug_disabled`     | PCR0 is NOT all-zeros (not debug mode)             |
| `tee_mrseam_mrtd`        | PCR0 matches measurement allowlist                 |
| `signing_key_present`    | X25519 `public_key` present in attestation doc     |
| `tee_reportdata_binding` | Attested public_key matches key exchange public_key |
| `e2ee_capable`           | E2EE material (session key) successfully derived   |
| `e2ee_usable`            | Successful E2EE round-trip (post-relay check)      |

**MapleAI DefaultAllowFail** (factors that Skip or are allowed to fail):

```go
var MapleAIDefaultAllowFail = []string{
    "tee_hardware_config",      // PCR1 — kernel hash, TBD
    "tee_boot_config",          // PCR2 — app hash, TBD
    "intel_pcs_collateral",     // Intel-only, N/A
    "tdx_tcb_current",          // Intel-only, N/A
    "tdx_tcb_not_revoked",      // Intel-only, N/A
    "nvidia_payload_present",   // No GPU attestation exposed
    "nvidia_signature",         // No GPU attestation exposed
    "nvidia_claims",            // No GPU attestation exposed
    "nvidia_nonce_client_bound",// No GPU attestation exposed
    "nvidia_nras_verified",     // No GPU attestation exposed
    "tls_key_binding",          // No TLS pinning (E2EE instead)
    "cpu_gpu_chain",            // No GPU binding exposed
    "measured_model_weights",   // No weight hashes
    "build_transparency_log",   // No Rekor
    "cpu_id_registry",          // No Proof of Cloud
    "compose_binding",          // No Docker compose
    "sigstore_verification",    // No Sigstore
    "event_log_integrity",      // No event log
    // All gateway_* factors — no gateway architecture
}
```

### NitroVerifyResult Type

New type in `internal/attestation/`:

```go
type NitroVerifyResult struct {
    Parsed          bool       // COSE_Sign1 + CBOR successfully decoded
    CertChainValid  bool       // Certificate chain validates to AWS root
    SignatureValid  bool       // COSE_Sign1 signature verifies
    DebugMode       bool       // PCR0 is all-zeros
    NonceMatch      bool       // Attestation nonce matches client nonce
    PCRs            map[uint][]byte // All PCR values (48 bytes each)
    PublicKey       []byte     // X25519 public key (32 bytes) from attestation
    ModuleID        string     // Enclave module identifier
    Timestamp       int64      // Attestation timestamp (Unix ms)
    CertChainDetail string     // Human-readable cert chain status
    SignatureDetail string     // Human-readable signature status
    ParseDetail     string     // Human-readable parse status
    Error           error      // First fatal error encountered
}
```

New field in `ReportInput`: `Nitro *NitroVerifyResult`

### Evaluator Generalization

Existing TDX evaluator functions (after rename to `tee_*`) must become TEE-generic,
checking whichever hardware result is present. Pattern:

```
evalTEEQuotePresent:
  if in.TDX != nil → check TDX quote present
  else if in.Nitro != nil → check Nitro doc present
  else → Skip("no TEE attestation available")

evalTEEQuoteStructure:
  if in.TDX != nil → check TDX parsed
  else if in.Nitro != nil → check Nitro parsed
  (similar pattern for cert_chain, signature, debug_disabled, etc.)

evalTEEMrseamMrtd:
  if in.TDX != nil → check MRTD/MRSEAM against policy
  else if in.Nitro != nil → check PCR0 against policy.PCR0Allow
```

The `MeasurementPolicy` struct needs a new field: `PCR0Allow []string` (hex-encoded
48-byte SHA-384 hashes). Existing MRTD/MRSEAM fields remain for TDX.

## Implementation Phases

### Phase 1: Nitro Attestation Core (`internal/attestation/nitro.go`)

**New dependency**: `fxamacker/cbor/v2` (add to go.mod)

**New files:**
- `internal/attestation/nitro.go` — Nitro COSE_Sign1 parsing and verification
- `internal/attestation/nitro_test.go` — Unit tests
- `internal/attestation/certs/aws_nitro_root.der` — Embedded AWS root certificate

**Functions to implement:**

1. `ParseNitroDocument(docBase64 string) (*NitroDocument, error)` — Base64-decode →
   CBOR-decode COSE_Sign1 → extract all fields
2. `VerifyNitroCertChain(doc *NitroDocument, now time.Time) error` — Validate chain
   from cabundle[0] (must match embedded root) through intermediates to leaf cert
3. `VerifyNitroSignature(doc *NitroDocument) error` — Construct Sig_structure, verify
   ECDSA-P384-SHA384 with leaf cert's public key
4. `VerifyNitroDocument(docBase64, clientNonce string) (*NitroVerifyResult, error)` —
   Orchestrator: parse → verify chain → verify signature → check nonce → check
   debug mode → extract public_key → return result
5. `IsNitroDebugMode(pcrs map[uint][]byte) bool` — Check PCR0 all-zeros
6. `NitroPCRMatchesPolicy(pcrs map[uint][]byte, policy *MeasurementPolicy) (bool, string)` —
   Check PCR0/1/2/8 against allowlists

**Internal types:**
```go
type NitroDocument struct {
    Protected   []byte          // Raw protected headers
    Payload     []byte          // Raw payload bytes (for Sig_structure)
    Signature   []byte          // Raw signature (96 bytes)
    ModuleID    string
    Timestamp   uint64
    Digest      string
    PCRs        map[uint][]byte
    Certificate []byte          // DER leaf cert
    CABundle    [][]byte        // DER cert chain
    PublicKey   []byte          // X25519 (32 bytes) or nil
    UserData    []byte          // or nil
    Nonce       []byte          // UTF-8 encoded nonce or nil
}
```

**AWS root certificate embedding:**
- Download from `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`
- Extract DER file, embed via `//go:embed certs/aws_nitro_root.der`
- Verify SHA-256 fingerprint matches published value at build time
- Reject chains where `cabundle[0]` is not byte-identical to embedded root

**Test plan:**
- Valid COSE_Sign1 round-trip: construct a self-signed test attestation doc with known
  values, verify parsing extracts all fields correctly
- Invalid signature: tamper with payload after signing, verify signature check fails
- Invalid cert chain: use wrong root cert, verify chain validation fails
- Expired certificate: use cert with NotAfter in the past
- Missing nonce: verify nonce check fails when nonce field is nil
- Wrong nonce: verify nonce mismatch is detected
- Debug mode: PCR0 all-zeros → `IsNitroDebugMode` returns true
- Missing public_key: verify detection
- Malformed CBOR: truncated, wrong types, extra fields
- Fuzz tests: `fuzz_test.go` with `ParseNitroDocument` on random base64 inputs
- **Bound reads**: CBOR arrays/maps must be bounded (reject docs with >64 PCRs,
  >32 cabundle certs, fields >1 MiB)

**Reference patterns:**
- `internal/attestation/tdx.go` for TDX quote parsing structure
- `internal/attestation/nvidia_eat.go` for external token parsing + verification
- Use `internal/jsonstrict` for any JSON parsing (attestation fetch response)

### Phase 2: Attestation Report Integration

**Depends on**: Phase 1

**Modified files:**
- `internal/attestation/report.go` — Add `NitroVerifyResult`, `Nitro` field in
  `ReportInput`, update evaluator functions, add `MapleAIDefaultAllowFail`
- `internal/attestation/report_test.go` — Tests for Nitro factors
- `internal/attestation/attestation.go` — Add `FormatNitro` to `BackendFormat`,
  add Nitro-related fields to `RawAttestation`
- `internal/attestation/measurement_policy.go` — Add `PCR0Allow`, `PCR1Allow`,
  `PCR2Allow`, `PCR8Allow` fields to `MeasurementPolicy`
- `internal/attestation/export_test.go` — Export new test helpers

**Factor implementation approach (two options):**

*If `tee_*` rename is done first:* Update existing `eval*` functions to check for
Nitro results alongside TDX results. Each evaluator becomes a dispatcher:
`in.TDX` present → existing TDX logic; `in.Nitro` present → new Nitro logic.

*If `tee_*` rename is deferred:* Add parallel `nitro_*` factors and evaluators.
Add them to `KnownFactors`. The rename folds them into `tee_*` later.

**Test plan:**
- `TestBuildReportNitroFactorCount` — Assert correct factor count with Nitro input
- `TestBuildReportNitroEnforcedFlags` — Verify enforcement for MapleAI allow-fail
- `TestBuildReportNitroBlocked` — Verify `Blocked()` when Nitro signature fails
- `TestBuildReportNitroPass` — Verify all Nitro factors pass with valid input
- `TestBuildReportNitroDebugMode` — Verify `tee_debug_disabled` fails
- `TestBuildReportNitroPCRMismatch` — Verify `tee_mrseam_mrtd` fails
- `TestBuildReportMixedTDXNitro` — Verify only one TEE type evaluated (mutual exclusion)
- Counter consistency: `Passed + Failed + Skipped == len(Factors)`

### Phase 3: MapleAI E2EE Session (`internal/e2ee/mapleai.go`)

**Depends on**: None (can parallel with Phases 1-2)

**New files:**
- `internal/e2ee/mapleai.go` — `MapleAISession` E2EE implementation
- `internal/e2ee/mapleai_test.go` — Unit tests
- `internal/e2ee/relay_mapleai.go` — SSE relay for MapleAI encrypted streams
- `internal/e2ee/relay_mapleai_test.go` — Relay tests

**`MapleAISession` struct:**
```go
type MapleAISession struct {
    clientPrivate  *ecdh.PrivateKey  // X25519 ephemeral private key
    clientPublic   []byte            // 32 bytes
    serverPublic   []byte            // 32 bytes (from attestation)
    sessionKey     []byte            // 32 bytes (from key exchange)
    sessionID      string            // UUID from server
}
```

**Methods:**
- `NewMapleAISession() (*MapleAISession, error)` — Generate X25519 keypair via
  `ecdh.X25519().GenerateKey(crypto/rand)`. Fail if RNG fails.
- `SetServerPublicKey(pubKey []byte) error` — Store the attested server public key.
  Validate length == 32 bytes.
- `ClientPublicKeyBase64() string` — Base64-encode client public key for key exchange
- `EstablishSession(encryptedSessionKey []byte, sessionID string) error`:
  1. Compute shared secret: `clientPrivate.ECDH(serverPublicKey)`
  2. Split `encryptedSessionKey`: nonce(12) || ciphertext
  3. ChaCha20-Poly1305 Open with shared secret as key, nonce, ciphertext
  4. Validate decrypted key is 32 bytes
  5. Store `sessionKey` and `sessionID`
  6. **Zero shared secret immediately after deriving session key**
- `EncryptRequest(plaintext []byte) ([]byte, error)`:
  1. Generate 12-byte random nonce
  2. ChaCha20-Poly1305 Seal with sessionKey
  3. Return `nonce || ciphertext`
- `DecryptResponse(encrypted []byte) ([]byte, error)`:
  1. Validate length ≥ 12 + 16 (nonce + min ciphertext with tag)
  2. Split nonce(12), ciphertext
  3. ChaCha20-Poly1305 Open with sessionKey
  4. Return plaintext
- `SessionID() string` — Return session_id for header injection
- `IsEncryptedChunk(val string) bool` — Check if value is base64 and decodes to ≥28
  bytes (12 nonce + 16 tag minimum)
- `Decrypt(ciphertext string) ([]byte, error)` — Base64-decode → `DecryptResponse`
- `Zero()` — Zero sessionKey bytes, nil all key references

**Implements `Decryptor` interface** (for type assertion in proxy relay dispatch).

**Relay functions:**

`RelayStreamMapleAI(ctx, w http.ResponseWriter, body io.ReadCloser, session *MapleAISession) (*StreamStats, error)`:
1. Set response headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`
2. Read SSE lines via `newSSEScanner(body)`
3. For each `data:` line:
   - If value is `[DONE]` → write `data: [DONE]\n\n`, return
   - Base64-decode the value
   - If base64 decode fails → skip (heartbeat/non-data)
   - Decrypt via `session.DecryptResponse(decoded)`
   - Write decrypted JSON as `data: <json>\n\n`
   - Flush
4. Track `StreamStats` (chunk count, timing)
5. On decryption failure → return `ErrDecryptionFailed`

`RelayNonStreamMapleAI(body io.ReadCloser, session *MapleAISession) ([]byte, error)`:
1. Read full response body (bounded read, e.g., 32 MiB max)
2. Parse as `{"encrypted": "<base64>"}`
3. Base64-decode the `encrypted` field
4. Decrypt via `session.DecryptResponse(decoded)`
5. Return decrypted JSON bytes

**Test plan:**
- Round-trip: generate keypair → encrypt → decrypt → assert plaintext matches
- Wrong session key: encrypt with key A, decrypt with key B → must fail
- Empty plaintext: encrypt empty bytes → decrypt → empty bytes
- Large payload: encrypt 1 MiB JSON → decrypt → verify
- Nonce uniqueness: encrypt same plaintext twice → ciphertexts must differ
- Zero cleanup: all key references nil after `Zero()`
- Interface compliance: `var _ Decryptor = (*MapleAISession)(nil)`
- Relay streaming: mock SSE server with encrypted chunks, verify decrypted output
- Relay `[DONE]`: verify pass-through
- Relay decryption failure: verify `ErrDecryptionFailed` returned
- Relay non-streaming: mock `{"encrypted": "..."}` response, verify decryption
- Pre-header error: verify no partial HTTP response written on early failure

**Reference patterns:**
- `internal/e2ee/chutes.go` for session structure and `Zero()` pattern
- `internal/e2ee/nearcloud.go` for X25519 key exchange pattern
- `internal/e2ee/relay_chutes.go` for custom SSE relay pattern
- `internal/e2ee/relay_test.go` and `relay_chutes_test.go` for test helpers

### Phase 4: MapleAI Provider (`internal/provider/mapleai/`)

**Depends on**: Phases 1, 2, 3

**New files:**
- `internal/provider/mapleai/mapleai.go` — Attester, Preparer, ParseAttestationResponse
- `internal/provider/mapleai/e2ee.go` — RequestEncryptor with key exchange + session cache
- `internal/provider/mapleai/reportdata.go` — Key binding verifier
- `internal/provider/mapleai/policy.go` — Default PCR measurement policy
- `internal/provider/mapleai/mapleai_test.go`
- `internal/provider/mapleai/e2ee_test.go`
- `internal/provider/mapleai/reportdata_test.go`
- `internal/provider/mapleai/policy_test.go`
- `internal/provider/mapleai/export_test.go`
- `internal/provider/mapleai/fuzz_test.go`

**Attester (`mapleai.go`):**

```go
type Attester struct {
    baseURL string
    client  *http.Client
    apiKey  string
}
```

- `NewAttester(baseURL, apiKey string, client *http.Client) *Attester`
- `FetchAttestation(ctx, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error)`:
  1. Generate UUID v4 nonce (not from `attestation.Nonce` — different format)
  2. `GET {baseURL}/attestation/{uuid}` via `provider.FetchAttestationJSON`
  3. Parse JSON response: `{"attestation_document": "<base64>"}`
     (use `internal/jsonstrict` for parsing)
  4. Call `attestation.VerifyNitroDocument(docBase64, uuid)` → `NitroVerifyResult`
  5. Populate `RawAttestation`:
     - `BackendFormat`: `attestation.FormatNitro` (new constant)
     - `SigningKey`: hex-encode the X25519 public key from NitroVerifyResult
     - `TEEProvider`: `"nitro"`
     - `Model`: model
     - `Nonce`: store UUID as nonce string
     - Store `NitroVerifyResult` in a new field (or use `RawBody` for the doc)
  6. Return `RawAttestation`

**NOTE on nonce format**: The existing `attestation.Nonce` is a 32-byte value
rendered as 64-char hex. MapleAI expects a UUID v4 string. The attester must
generate its own UUID v4 nonce and store it alongside the standard `Nonce` field.
Add a `NitroNonce string` field to `RawAttestation` for the UUID nonce, or
repurpose `NonceSource` field.

**Preparer (`mapleai.go`):**

```go
type Preparer struct{}
```

- `PrepareRequest(req *http.Request, e2eeHeaders http.Header, meta *provider.RequestMeta, stream bool, path string) error`:
  1. Set `Authorization: Bearer <apiKey>` (from req or meta)
  2. Set `Content-Type: application/json`
  3. If E2EE headers present (from EncryptRequest):
     - Set `x-session-id` from e2eeHeaders

**RequestEncryptor (`e2ee.go`):**

```go
type E2EE struct {
    baseURL string
    client  *http.Client
    mu      sync.Mutex
    sessions map[string]*sessionEntry // keyed by hex(serverPublicKey)
}

type sessionEntry struct {
    session   *e2ee.MapleAISession
    createdAt time.Time
}
```

- `NewE2EE(baseURL string, client *http.Client) *E2EE`
- `EncryptRequest(body []byte, raw *attestation.RawAttestation, endpointPath string) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error)`:
  1. Extract server public key from `raw.SigningKey` (hex-decode to 32 bytes)
  2. Lock mutex, check for cached session with matching server public key
  3. If no session or expired: perform key exchange:
     a. Create `e2ee.NewMapleAISession()`
     b. `session.SetServerPublicKey(serverPubKey)` — constant-time compare against
        attested key
     c. `POST {baseURL}/key_exchange` with `{"client_public_key": "<base64>", "nonce": "<uuid>"}`
     d. Parse response: `{"encrypted_session_key": "<base64>", "session_id": "<uuid>"}`
     e. Base64-decode encrypted_session_key
     f. `session.EstablishSession(encSessionKey, sessionID)`
     g. Cache the session
  4. Encrypt request body: `session.EncryptRequest(body)`
  5. Wrap: `{"encrypted": "<base64>"}`
  6. Set e2ee headers: `x-session-id: <sessionID>`
  7. Return `(wrappedBody, session, nil, nil)` — `ChutesE2EE` is nil
  8. Unlock mutex

**Key binding verifier (`reportdata.go`):**

For the `tee_reportdata_binding` factor, MapleAI's binding is: the X25519 `public_key`
in the verified attestation document is the same key used in the ECDH key exchange.
This is verified implicitly during `EncryptRequest` (step 3b above). The
`ReportDataVerifier` interface (`VerifyReportData(reportData [64]byte, raw, nonce)`)
doesn't fit Nitro (no TDX REPORTDATA). Options:

- Implement a Nitro-specific verifier that returns Pass with detail "public_key bound
  via COSE_Sign1 signature" (the binding is verified by the attestation signature,
  not by a separate REPORTDATA check)
- Or: the `tee_reportdata_binding` evaluator handles Nitro by checking
  `in.Nitro.PublicKey != nil && in.Nitro.SignatureValid` directly

**Default measurement policy (`policy.go`):**

```go
func DefaultMeasurementPolicy() attestation.MeasurementPolicy {
    return attestation.MeasurementPolicy{
        PCR0Allow: []string{
            // Known-good PCR0 values obtained from live attestation
            // or OpenSecret's published PCR history
        },
    }
}
```

PCR0 values must be obtained from the production endpoint before implementation
(fetch live attestation, extract PCR0, add as hex string). Multiple values may be
needed if the enclave image has been updated. Consult:
`https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/pcrProdHistory.json`

**Test plan:**
- Attester: mock HTTP server returning canned attestation JSON, verify parsing
- Attester: invalid JSON response → error
- Attester: HTTP error → error
- Preparer: verify headers set correctly
- E2EE: mock key exchange endpoint, verify session establishment
- E2EE: session reuse — second call uses cached session
- E2EE: session invalidation — different server public key → new session
- E2EE: concurrent access — `sync.WaitGroup` + parallel goroutines verify mutex safety
- Key binding: constant-time comparison verified (test with timing-safe assertions)
- Policy: PCR0 match/mismatch
- Fuzz: `ParseAttestationResponse` with random inputs

**Reference patterns:**
- `internal/provider/chutes/chutes.go` for non-pinned Attester pattern
- `internal/provider/chutes/e2ee.go` for RequestEncryptor with E2EE material
- `internal/provider/chutes/reportdata.go` for ReportDataVerifier
- `internal/provider/chutes/policy.go` for measurement policy
- `internal/provider/neardirect/neardirect.go` for Preparer pattern

### Phase 5: Wiring & Configuration

**Depends on**: Phases 1-4

**Modified files:**

`internal/proxy/proxy.go:fromConfig()` — Add `"mapleai"` case:
```
case "mapleai":
    p.ChatPath = "/v1/chat/completions"
    p.EmbeddingsPath = "/v1/embeddings"
    p.E2EE = true  // Always E2EE
    p.Attester = mapleai.NewAttester(cp.BaseURL, cp.APIKey, s.attestClient)
    p.Preparer = mapleai.NewPreparer()
    p.Encryptor = mapleai.NewE2EE(cp.BaseURL, s.attestClient)
    p.ReportDataVerifier = mapleai.ReportDataVerifier{}
    p.SupplyChainPolicy = nil  // No supply chain attestation
    p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, s.upstreamClient)
```

**Proxy relay dispatch**: The proxy's `handleChat` function needs to detect MapleAI
E2EE for both streaming and non-streaming responses. Since `EncryptRequest` returns
`(body, Decryptor, nil, nil)` with `Decryptor` being a `*e2ee.MapleAISession`, the
proxy can use a type assertion:
```
switch dec := decryptor.(type) {
case *e2ee.MapleAISession:
    // Use RelayStreamMapleAI / RelayNonStreamMapleAI
default:
    // Use existing per-field RelayStream / DecryptNonStreamResponse
}
```
This is analogous to the existing `if chutesE2EE != nil` check for Chutes.

`internal/config/config.go:applyEnvOverrides()` — Add:
```
"mapleai" → env: "MAPLEAI_API_KEY", base: "https://enclave.trymaple.ai", e2ee: true
```

`internal/defaults/defaults.go` — Add to registry:
```
"mapleai": { model: mapleai.DefaultMeasurementPolicy() }
```

`internal/verify/factory.go` — Add `"mapleai"` case to all switch functions:
- `newAttester` → `mapleai.NewAttester`
- `newReportDataVerifier` → `mapleai.ReportDataVerifier{}`
- `supplyChainPolicy` → `nil`
- `e2eeEnabledByDefault` → `true`
- `chatPathForProvider` → `"/v1/chat/completions"`

`internal/attestation/report.go` — Add `MapleAIDefaultAllowFail` (listed above)

`internal/attestation/attestation.go`:
- Add `FormatNitro BackendFormat = "nitro"`
- Add to `RawAttestation`: `NitroNonce string` (UUID nonce), consider
  `NitroDocument *NitroDocument` or `NitroVerifyResult *NitroVerifyResult`

**Test plan:**
- Config parsing: TOML with `[providers.mapleai]` section parses correctly
- Config env override: `MAPLEAI_API_KEY` env var creates provider
- Unknown provider rejection: verify `fromConfig` still errors on unknown names
- Verify command: `teep verify mapleai` with mock transport

### Phase 6: Integration Tests

**Depends on**: Phase 5

**New files:**
- `internal/integration/mapleai_test.go` — Integration tests

**Mock integration tests** (run without API key):
- Fixture-based replay: capture real attestation from live endpoint, save as testdata
  fixture, replay through full verification pipeline
- `loadFixture(t, "mapleai")` pattern matching existing fixtures
- Assert all Nitro factors evaluate correctly
- Assert report is not blocked with MapleAI allow-fail list
- Assert E2EE session establishment succeeds with mock key exchange

**Live integration tests** (gated behind `TEEP_LIVE_TESTS` + `MAPLEAI_API_KEY`):
- `TestMapleAIModels` — GET /v1/models returns valid model list
- `TestMapleAIAttestation` — Full attestation fetch + verify cycle
- `TestMapleAIChatNonStreaming` — Non-streaming chat completion with E2EE
- `TestMapleAIChatStreaming` — Streaming chat completion with E2EE
- `TestMapleAIEmbeddings` — Embeddings endpoint with E2EE
- `TestMapleAIVerifyReport` — Full verification report (all factors evaluated)
- `TestMapleAIInvalidAPIKey` — Verify rejection with bad API key
- `TestMapleAIConcurrent` — 10 parallel requests verify cache and session safety
  (`sync.WaitGroup` + goroutines, all tests use `-race`)

**Capture tests:**
- Capture mode: record live API interactions for replay
- Self-verify: captured data replays identically

**Reference patterns:**
- `internal/integration/nearcloud_test.go` for fixture-based replay
- `internal/integration/neardirect_test.go` for live test gating
- `internal/integration/helpers_test.go` for shared test helpers

## Verification

1. `make check` passes (fmt, vet, lint, unit tests with `-race`)
2. `make integration` passes with `MAPLEAI_API_KEY` and `TEEP_LIVE_TESTS` set
3. `make reports` generates MapleAI verification report
4. Report shows: all enforced `tee_*` factors Pass; non-applicable factors correctly
   in allow-fail
5. E2EE round-trip succeeds (`e2ee_usable` = Pass)
6. Manual: `teep verify mapleai` produces correct human-readable report
7. Manual: `teep serve` with mapleai provider routes chat requests correctly
8. Manual: concurrent load test — 10+ parallel requests verify no races
9. `gocyclo` — all new functions ≤ complexity 32

## Relevant Files

**New:**
- `internal/attestation/nitro.go`, `nitro_test.go` — Nitro COSE_Sign1 verification
- `internal/attestation/certs/aws_nitro_root.der` — Embedded AWS root certificate
- `internal/e2ee/mapleai.go`, `mapleai_test.go` — E2EE session
- `internal/e2ee/relay_mapleai.go`, `relay_mapleai_test.go` — SSE relay
- `internal/provider/mapleai/*.go` — Provider implementation
- `internal/integration/mapleai_test.go` — Integration tests

**Modified:**
- `go.mod` — Add `fxamacker/cbor/v2`
- `internal/attestation/attestation.go` — `FormatNitro`, `RawAttestation` fields
- `internal/attestation/report.go` — `NitroVerifyResult`, evaluators, `MapleAIDefaultAllowFail`, `KnownFactors`
- `internal/attestation/report_test.go` — Nitro factor tests
- `internal/attestation/measurement_policy.go` — `PCR0Allow` etc. fields
- `internal/proxy/proxy.go` — `fromConfig()` mapleai case, relay dispatch
- `internal/config/config.go` — `applyEnvOverrides()` for MAPLEAI_API_KEY
- `internal/defaults/defaults.go` — Registry entry
- `internal/verify/factory.go` — All switch blocks

**Reference (read, do not modify):**
- `internal/provider/chutes/` — Non-pinned provider pattern
- `internal/provider/nearcloud/pinned.go` — `attestOnConn` orchestration pattern
- `internal/e2ee/chutes.go` — Session + Zero() pattern
- `internal/e2ee/relay_chutes.go` — Custom SSE relay pattern
- `internal/proxy/proxy.go:handleChat` — Request routing and E2EE dispatch

## Decisions

- **Non-pinned architecture**: E2EE provides channel security; no TLS pinning needed
  (Nitro attestation doesn't include TLS fingerprints)
- **CBOR library**: `fxamacker/cbor/v2` for COSE_Sign1 parsing
- **Session caching**: Cache session alongside attestation (same 1h TTL), re-establish
  on failure. Session keyed by server public key hex.
- **UUID nonce**: MapleAI uses UUID v4 nonces, not 32-byte hex. Provider generates its
  own nonce format.
- **Factor naming**: Plan uses `tee_*` names. If rename hasn't occurred, implementer
  may use `nitro_*` initially.
- **No supply chain attestation**: MapleAI does not expose compose hashes, Sigstore,
  Rekor, or event logs. These factors are in allow-fail.
- **GPU attestation gap**: MapleAI's backend uses NVIDIA GPU TEEs (per public blog),
  but GPU attestation is not exposed through the MapleAI attestation endpoint. All
  NVIDIA and GPU-related factors are in allow-fail. This should be documented as a
  known limitation.
- **No Maple source code referenced**: All protocol descriptions derived from public
  AWS Nitro documentation, OpenSecret SDK documentation, and RFC specifications.

## Public References

- [AWS Nitro Enclaves — Verifying Root of Trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- [AWS Nitro Enclaves NSM API — Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)
- [OpenSecret SDK — Remote Attestation Guide](https://docs.opensecret.cloud/docs/guides/remote-attestation/)
- [OpenSecret SDK — Maple AI Integration](https://docs.opensecret.cloud/docs/maple-ai/)
- [OpenSecret Technical Blog](https://blog.opensecret.cloud/opensecret-technicals/)
- [RFC 9052 — CBOR Object Signing and Encryption (COSE)](https://datatracker.ietf.org/doc/html/rfc9052)
- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://datatracker.ietf.org/doc/html/rfc8949)
- [RFC 7748 — Elliptic Curves for Security (X25519)](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8439 — ChaCha20 and Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)

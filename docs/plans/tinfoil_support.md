# Plan: Tinfoil Provider Support

## Overview

Add Tinfoil as a teep provider with full attestation verification and E2EE
support. Tinfoil runs OpenAI-compatible inference in secure enclaves
(TDX and SEV-SNP). Attestation is fetched from a well-known HTTP endpoint on
the enclave, verified against hardware roots of trust and Sigstore supply-chain
attestations, and bound to TLS via the enclave's certificate fingerprint. E2EE
uses the EHBP protocol (HPKE-based full-body encryption).

Reference providers for implementation patterns: **nearcloud**, **neardirect**,
**chutes**.

## Provider Characteristics

| Property | Value |
|---|---|
| Name | `tinfoil` |
| Base URL | `https://inference.tinfoil.sh` |
| API key env | `TINFOIL_API_KEY` |
| E2EE | Yes (EHBP: HPKE + AES-256-GCM full-body encryption) |
| Connection model | Standard TLS with SPKI pinning (not connection-pinned) |
| Attestation endpoint | `GET /.well-known/tinfoil-attestation` on the enclave |
| HPKE key endpoint | `GET /.well-known/hpke-keys` on the enclave |
| Nonce model | No client-supplied nonces — keys are embedded in attestation |
| PinnedHandler | No — uses standard HTTP client with SPKI verification |
| Supply chain | Sigstore DSSE bundles from GitHub attestations API |
| Hardware platforms | Intel TDX and AMD SEV-SNP (multi-platform code measurements) |

## Supported Endpoints

| Endpoint | Upstream Path | E2EE | Notes |
|---|---|---|---|
| Chat completions | `/v1/chat/completions` | Yes (EHBP) | Multiple models: llama3-3-70b, gemma4-31b, glm-5-1, gpt-oss-120b, kimi-k2-5, etc. |
| Embeddings | `/v1/embeddings` | Yes (EHBP) | Model: nomic-embed-text |
| Audio transcriptions | `/v1/audio/transcriptions` | Yes (EHBP) | Models: whisper-large-v3-turbo, voxtral-small-24b. Multipart form data. |
| TTS (text-to-speech) | `/v1/audio/speech` | Yes (EHBP) | Models: qwen3-tts, whisper-large-v3-turbo |
| Models list | `/v1/models` | No | GET request; EHBP only encrypts bodies on POST requests |

Vision models (qwen3-vl-30b, gemma4-31b, kimi-k2-5) use the chat completions
endpoint with multimodal content arrays — no separate vision endpoint is needed.

Note: EHBP encrypts the entire HTTP body as a single AEAD stream. There are
**no field-level gaps**. All request and response fields are encrypted by
construction, like Chutes.

## Architecture Comparison with Existing Providers

### Similarities to Chutes

- Full-body encryption (no field-level dispatch needed)
- Standard TLS (not connection-pinned like neardirect/nearcloud)
- No client-supplied nonces in attestation
- No PinnedHandler needed
- TDX attestation verification reuses `attestation.VerifyTDXQuote()`

### Key Differences from All Existing Providers

1. **Attestation format**: Tinfoil uses its own format — a JSON object with
   `format` (predicate type URI) and `body` (base64-gzipped hardware quote).
   Not dstack, not chutes, not NEAR.
2. **Supply chain**: Sigstore verification of GitHub Actions build attestations
   (DSSE in-toto bundles), checked against code image digests published in
   GitHub Releases. This is independent of the compose-hash / IMA supply chain
   used by other providers.
3. **REPORTDATA binding**: `ReportData[0:32]` = SHA-256 of TLS public key
   (PKIX DER encoding); `ReportData[32:64]` = 32-byte HPKE public key. No
   nonce or signing address in REPORTDATA.
4. **E2EE protocol**: EHBP (RFC 9180 HPKE + AES-256-GCM), not
   Ed25519/XChaCha20-Poly1305 or ML-KEM-768/ChaCha20-Poly1305.
5. **Key discovery**: HPKE public key fetched from `/.well-known/hpke-keys`
   (RFC 9458 key config format), not from attestation signing key or nonce pool.
6. **Hardware measurement verification**: TDX hardware platforms (MRTD, RTMR0)
   matched against a separate Sigstore-attested hardware measurements registry
   (`tinfoilsh/hardware-measurements`).
7. **Multi-platform code measurements**: Code attestation uses a unified
   `snp-tdx-multiplatform/v1` predicate that cross-matches SEV-SNP and TDX
   measurements from a single Sigstore bundle.
8. **SEV-SNP support**: Tinfoil enclaves can run on AMD SEV-SNP (not just TDX).
   The attestation format field determines which hardware verification path to
   take.

---

## Protocol Descriptions

### Tinfoil Attestation Protocol

#### Attestation Document Format

The enclave serves its attestation at `GET /.well-known/tinfoil-attestation`.
The response is a JSON object:

```json
{
  "format": "<predicate_type_uri>",
  "body": "<base64(gzip(hardware_attestation_report))>"
}
```

**Format values** (predicate type URIs):
- `https://tinfoil.sh/predicate/sev-snp-guest/v2` — AMD SEV-SNP attestation
- `https://tinfoil.sh/predicate/tdx-guest/v2` — Intel TDX attestation

The `body` field is base64 standard encoding of gzip-compressed raw hardware
attestation report bytes.

#### Decompression

1. Base64-decode the `body` string.
2. Gzip-decompress. Bound the decompressed size (10 MiB max) to prevent
   decompression bombs.
3. The result is a raw binary attestation report:
   - For TDX: a TDX QuoteV4 structure (min 1020 bytes).
   - For SEV-SNP: an SEV attestation report (1184 bytes).

#### REPORTDATA Layout (64 bytes)

Both TDX and SEV-SNP reports contain a 64-byte `report_data` field:

| Offset | Size | Content |
|---|---|---|
| 0–31 | 32 bytes | SHA-256 fingerprint of the enclave's TLS certificate public key (PKIX DER encoding) |
| 32–63 | 32 bytes | HPKE X25519 public key (raw 32 bytes) |

The TLS fingerprint binds the attestation to the enclave's TLS identity. The
HPKE key enables E2EE.

### TDX Verification (Reuse Existing)

For TDX-format attestation, hex-encode the decompressed binary and call the
existing `attestation.VerifyTDXQuote()`. Extract measurements:

- Register 0: MRTD (48 bytes hex)
- Register 1: RTMR0 (48 bytes hex)
- Register 2: RTMR1 (48 bytes hex)
- Register 3: RTMR2 (48 bytes hex)
- Register 4: RTMR3 (48 bytes hex) — must be all zeros

#### TDX Additional Policy Checks (Tinfoil-Specific)

After the standard TDX quote verification, apply these additional checks:

1. **TD Attributes**: Must equal `0x0000001000000000` (SEPT_VE_DISABLE=1).
2. **XFAM**: Must equal `0xe702060000000000`.
3. **Minimum TEE TCB SVN**: Must be >= `0x03010200000000000000000000000000`.
4. **MR_SEAM**: Must be in the accepted firmware whitelist (see Measurement
   Policy section).
5. **MR_CONFIG_ID, MR_OWNER, MR_OWNER_CONFIG**: Must be all zeros.
6. **RTMR3**: Must be all zeros (96 hex chars of '0').

### SEV-SNP Verification (New)

For SEV-SNP-format attestation:

1. Parse the binary as an AMD SEV-SNP attestation report.
2. Fetch the VCEK certificate from AMD KDS (or cache). The AMD KDS can be
   accessed via the proxy at `kds-proxy.tinfoil.sh` or directly from AMD.
3. Verify the report signature against the VCEK cert chain (AMD Genoa root).
4. Validate guest policy:
   - SMT: true
   - Debug: false
   - SingleSocket: false
   - MinimumBuild: 21
   - MinimumVersion: 1.55
5. Validate TCB:
   - BlSpl >= 0x07
   - TeeSpl >= 0x00
   - SnpSpl >= 0x0e
   - UcodeSpl >= 0x48
6. Extract measurement: `report.Measurement` (single 48-byte hex register).

The SEV-SNP verification is new code — teep currently only verifies TDX
quotes. However, go-sev-guest (google/go-sev-guest) provides the verification
primitives, similar to how go-tdx-guest is used for TDX.

### Supply Chain Verification (Sigstore)

Tinfoil's supply chain verification uses GitHub Actions build attestations
verified through Sigstore.

#### Step 1: Fetch Code Image Digest

For a given configuration repo (e.g. `tinfoilsh/confidential-model-router`):

```
GET https://github-proxy.tinfoil.sh/repos/{repo}/releases/latest
```

Parse `tag_name` from the response. Then fetch the digest:

```
GET https://github-proxy.tinfoil.sh/repos/{repo}/releases/download/{tag}/tinfoil.hash
```

Returns a plain-text SHA-256 hex digest.

#### Step 2: Fetch Sigstore DSSE Bundle

```
GET https://github-proxy.tinfoil.sh/repos/{repo}/attestations/sha256:{digest}
```

Returns JSON with `attestations[0].bundle` containing a Sigstore DSSE
envelope.

#### Step 3: Verify Bundle

Verify the DSSE bundle using Sigstore's verification library:

- **OIDC issuer**: `https://token.actions.githubusercontent.com`
- **Workflow pattern**: `^https://github.com/{repo}/.github/workflows/.*@refs/tags/*`
- **Artifact digest**: Must match the `sha256:{digest}` from Step 1.
- **Require**: At least 1 signed certificate timestamp, 1 transparency log
  entry, 1 observer timestamp.

#### Step 4: Extract Code Measurements

The verified DSSE bundle contains an in-toto statement with a predicate. The
predicate type determines the measurement format:

- **`https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1`**: Three registers:
  - Register 0: `snp_measurement` (SEV-SNP launch measurement)
  - Register 1: `tdx_measurement.rtmr1` (TDX RTMR1)
  - Register 2: `tdx_measurement.rtmr2` (TDX RTMR2)

#### Step 5: Compare Code vs. Enclave Measurements

Cross-platform comparison logic:

**Multi-platform code vs. TDX enclave:**
- Compare code register 1 (RTMR1) == enclave register 2 (RTMR1).
- Compare code register 2 (RTMR2) == enclave register 3 (RTMR2).
- Verify enclave register 4 (RTMR3) is all zeros.

**Multi-platform code vs. SEV-SNP enclave:**
- Compare code register 0 (snp_measurement) == enclave register 0 (measurement).

All comparisons MUST be constant-time (`subtle.ConstantTimeCompare`).

### Hardware Measurement Verification (TDX Only)

For TDX enclaves, verify that the hardware platform (MRTD, RTMR0) matches a
known trusted platform:

1. Fetch latest hardware measurements from
   `tinfoilsh/hardware-measurements` repo via GitHub Releases + Sigstore
   (same flow as code measurements above).
2. The predicate type is
   `https://tinfoil.sh/predicate/hardware-measurements/v1`.
3. Each entry has: `id` (platform identifier), `mrtd`, `rtmr0`.
4. Match the enclave's MRTD (register 0) and RTMR0 (register 1) against the
   hardware measurement entries.
5. If no match is found, the hardware platform is unknown — record as a
   verification factor failure.

### TLS Certificate Fingerprint Verification

After attestation verification:

1. Extract the TLS fingerprint from REPORTDATA bytes [0:32].
2. The proxy already has the upstream TLS certificate (from the HTTP
   connection).
3. Compute SHA-256 of the certificate's PKIX-encoded public key.
4. Constant-time compare the computed fingerprint with the attested
   fingerprint.
5. On mismatch: fail closed.

This binding ensures the TLS connection terminates inside the attested enclave.

### HPKE Key Verification

The HPKE public key from REPORTDATA bytes [32:64] must match the key served
at `/.well-known/hpke-keys`:

1. Fetch `GET /.well-known/hpke-keys` from the enclave.
2. Parse the response as an RFC 9458 Section 3 key configuration:
   - Format: `key_id(1) || kem_id(2) || public_key_length(2) || public_key(32) || cipher_suites_length(2) || kdf_id(2) || aead_id(2)`
   - Expected: key_id=0, kem_id=0x0020 (X25519_HKDF_SHA256), kdf_id=0x0001
     (HKDF_SHA256), aead_id=0x0002 (AES_256_GCM).
3. Extract the 32-byte X25519 public key from the key config.
4. Constant-time compare with REPORTDATA bytes [32:64].
5. On mismatch: fail closed. Store the verified key config for EHBP.

### E2EE: Encrypted HTTP Body Protocol (EHBP)

EHBP is documented at https://docs.tinfoil.sh/resources/ehbp and specified at
https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/main/SPEC.md

The protocol encrypts entire HTTP request and response bodies using HPKE
(RFC 9180) while leaving headers in cleartext for routing.

#### HPKE Parameters

| Parameter | Value |
|---|---|
| KEM | X25519_HKDF_SHA256 (0x0020) |
| KDF | HKDF_SHA256 (0x0001) |
| AEAD | AES_256_GCM (0x0002) |

#### Request Encryption

1. Fetch the server's HPKE public key from `/.well-known/hpke-keys` (already
   fetched and verified against attestation REPORTDATA during attestation).
2. Establish an HPKE encryption context (`SetupBaseS`) using the server's
   public key and a fresh ephemeral keypair.
3. Encrypt the request body as a stream of length-prefixed chunks:
   - Each chunk: `[4-byte big-endian uint32 length] [AES-256-GCM ciphertext]`
   - Length counts ciphertext bytes only (not the 4-byte header).
   - AAD is empty. The HPKE sealer's internal nonce counter auto-increments.
   - Zero-length chunks may appear and should be skipped by receivers.
   - End of message is indicated by HTTP stream termination (no sentinel).
4. Set request header `Ehbp-Encapsulated-Key` to the lowercase hex encoding
   of the HPKE encapsulated key (32 bytes → 64 hex chars for X25519).
5. Use chunked transfer encoding; omit Content-Length.
6. Retain the HPKE sender context for response decryption.

#### Response Decryption

1. Read the `Ehbp-Response-Nonce` header (lowercase hex, 64 chars = 32 bytes).
   If absent, fail closed — do not treat the response as authenticated.
2. Derive response keys (following OHTTP / RFC 9458):
   ```
   secret = context.Export("ehbp response", 32)
   salt = concat(encapsulated_key, response_nonce)
   prk = HKDF-Extract(salt, secret)
   aead_key = HKDF-Expand(prk, "key", 32)    // AES-256 key
   aead_nonce = HKDF-Expand(prk, "nonce", 12) // GCM nonce
   ```
3. Decrypt response body chunks:
   - Same framing as request: `[4-byte length] [ciphertext]`.
   - Each chunk decrypted with AES-256-GCM using `aead_key`.
   - Nonce for chunk `i` (zero-indexed): `aead_nonce XOR i`.
   - AAD is empty.
4. On any decryption failure: fail closed, abort the response.

#### Bodyless Requests (GET /v1/models)

EHBP does not encrypt responses for bodyless requests (GET, HEAD, DELETE,
OPTIONS without a body). The `/v1/models` endpoint is a GET request, so it
transits in plaintext over the TLS connection pinned to the attested enclave.
This is acceptable because the models list is not user data.

#### Audio Transcription (Multipart)

For `/v1/audio/transcriptions`, the request body is `multipart/form-data`.
EHBP encrypts the entire multipart body as-is — the server middleware
decrypts it and reconstructs the multipart stream before passing to the
inference handler.

---

## Implementation Phases

### Phase 1: Attestation Document Parsing and Verification

**Goal**: Fetch and verify Tinfoil attestation documents (TDX path only;
SEV-SNP deferred to Phase 3).

**Files to create**:
- `internal/provider/tinfoil/tinfoil.go` — Attester and Preparer
- `internal/provider/tinfoil/attestation.go` — Attestation document parsing
- `internal/provider/tinfoil/reportdata.go` — REPORTDATA verifier
- `internal/provider/tinfoil/policy.go` — TDX additional policy checks +
  MR_SEAM whitelist

**Implementation**:

1. **Attester** (`tinfoil.NewAttester(baseURL, apiKey, offline)`):
   - `FetchAttestation(ctx, model, nonce)` fetches
     `GET {baseURL}/.well-known/tinfoil-attestation`.
   - Parse the JSON response `{format, body}`.
   - Reject unknown format URIs — only accept
     `https://tinfoil.sh/predicate/sev-snp-guest/v2` and
     `https://tinfoil.sh/predicate/tdx-guest/v2`.
   - Decode and decompress: base64 → gzip → binary. Bound decompressed size
     to 10 MiB.
   - For TDX: hex-encode the binary, set `raw.IntelQuote`.
   - Set `raw.BackendFormat = attestation.FormatTinfoil`.
   - Extract REPORTDATA from the parsed quote: `raw.TLSFingerprint` =
     hex(REPORTDATA[0:32]), and store the HPKE key
     hex(REPORTDATA[32:64]) in a new field or via `raw.SigningKey`.
   - The `nonce` parameter is not sent to the server (Tinfoil does not use
     client-supplied nonces). It is stored in the RawAttestation for
     report building.

2. **REPORTDATA Verifier** (`tinfoil.ReportDataVerifier{}`):
   - `VerifyReportData(reportData [64]byte, raw, nonce)`:
     - Extract `tlsFP = hex(reportData[0:32])`.
     - Extract `hpkeKey = hex(reportData[32:64])`.
     - Verify `tlsFP` matches `raw.TLSFingerprint` (constant-time).
     - Return detail string: `"tls_fp={first8}... hpke_key={first8}..."`.
   - Note: Nonce is not verified in REPORTDATA (Tinfoil doesn't embed
     client nonces). Set the `nonce_in_reportdata` factor to advisory.

3. **Tinfoil TDX Policy** (additional checks beyond `VerifyTDXQuote`):
   - After standard TDX verification, apply Tinfoil-specific policy:
     - Validate TD_ATTRIBUTES == `0x0000001000000000`.
     - Validate XFAM == `0xe702060000000000`.
     - Validate MR_SEAM is in the accepted set.
     - Validate MR_CONFIG_ID, MR_OWNER, MR_OWNER_CONFIG are all zeros.
     - Validate RTMR3 is all zeros.
     - Validate TEE_TCB_SVN >= minimum.
   - Store results as additional verification factors in the report.

4. **MR_SEAM Whitelist** (initial values):
   ```
   TDX 2.0.08: 476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c
   TDX 1.5.16: 7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d
   TDX 2.0.02: 685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04
   TDX 1.5.08: 49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6
   ```
   These should go in `tinfoil/policy.go` as a hardcoded set, matching the
   pattern used for other provider measurement allowlists.

**Unit tests**:
- Test document parsing with captured attestation responses (save a real
  response as testdata).
- Test decompression: valid gzip, truncated gzip, oversized gzip (>10 MiB).
- Test format rejection: unknown format URI.
- Test REPORTDATA extraction: verify correct byte offsets.
- Test MR_SEAM whitelist matching.

**Commit**: Phase 1 — Tinfoil attestation document parsing and TDX verification.

---

### Phase 2: Supply Chain Verification (Sigstore)

**Goal**: Verify Tinfoil code measurements via Sigstore DSSE bundles from
GitHub Releases.

**Files to create**:
- `internal/provider/tinfoil/sigstore.go` — Sigstore bundle fetching and
  verification
- `internal/provider/tinfoil/measurements.go` — Measurement comparison logic

**Implementation**:

1. **GitHub Release Fetcher**:
   - Fetch latest release tag from GitHub API (via `github-proxy.tinfoil.sh`
     or directly from `api.github.com`).
   - Fetch `tinfoil.hash` artifact from the release.
   - Fetch Sigstore attestation bundle from
     `repos/{repo}/attestations/sha256:{digest}`.

2. **Sigstore Bundle Verifier**:
   - Use `sigstore-go` library (same as used by teep's existing
     `attestation/sigstore.go`) to verify the DSSE bundle.
   - Certificate identity: OIDC issuer =
     `https://token.actions.githubusercontent.com`.
   - Workflow regex: `^https://github.com/{repo}/.github/workflows/.*@refs/tags/*`.
   - Require SCT, transparency log entry, observer timestamp.
   - Extract the in-toto predicate after verification.

3. **Code Measurement Extraction**:
   - Parse predicateType from the verified statement.
   - For `https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1`:
     Extract `snp_measurement`, `tdx_measurement.rtmr1`,
     `tdx_measurement.rtmr2` as 3-register measurement.

4. **Hardware Measurement Fetcher** (TDX only):
   - Same GitHub + Sigstore flow, but for repo
     `tinfoilsh/hardware-measurements`.
   - Predicate type: `https://tinfoil.sh/predicate/hardware-measurements/v1`.
   - Extract list of `{id, mrtd, rtmr0}` entries.
   - Match enclave's MRTD (register 0) and RTMR0 (register 1) against entries.

5. **Measurement Comparison**:
   - Implement cross-platform comparison:
     - Multi-platform vs. TDX: compare RTMR1 and RTMR2; verify RTMR3 == 0.
     - Multi-platform vs. SEV-SNP: compare snp_measurement.
   - All comparisons constant-time.
   - Record results as verification factors.

6. **Configuration Repo Mapping**:
   - Per-model Sigstore repo (from Tinfoil's published docs):
     - Chat router: `tinfoilsh/confidential-model-router`
     - Embeddings: `tinfoilsh/confidential-nomic-embed-text`
     - Audio (whisper): `tinfoilsh/confidential-audio-processing`
     - Audio (voxtral): `tinfoilsh/confidential-voxtral-small-24b`
     - Vision (qwen3-vl): `tinfoilsh/confidential-qwen3-vl-30b`
     - TTS (qwen3-tts): `tinfoilsh/confidential-qwen3-tts` (inferred)
   - Store this mapping in config or as defaults. The router handles model
     routing, so the proxy may only need to verify the router's attestation
     (which covers all models routed through it). Verify this during
     integration testing.

**Unit tests**:
- Test Sigstore bundle verification with a captured bundle (testdata).
- Test measurement extraction for multi-platform predicate.
- Test cross-platform comparison: TDX match, TDX mismatch, SEV-SNP match.
- Test hardware measurement matching: found, not found.
- Test RTMR3 zero validation.

**Commit**: Phase 2 — Tinfoil supply chain verification via Sigstore.

---

### Phase 3: SEV-SNP Attestation Verification

**Goal**: Support Tinfoil enclaves running on AMD SEV-SNP.

**Files to create**:
- `internal/attestation/sev.go` — SEV-SNP report parsing and verification
- `internal/attestation/sev_test.go` — Unit tests
- `internal/attestation/certs/genoa_cert_chain.pem` — AMD Genoa ARK+ASK certs

**Implementation**:

1. **Add `google/go-sev-guest` dependency** (analogous to `go-tdx-guest` for
   TDX).

2. **Parse SEV-SNP Report**:
   - Use `abi.ReportToProto()` to parse the binary report.
   - Extract: `Measurement` (48 bytes), `ReportData` (64 bytes), TCB
     version, guest policy.

3. **Verify SEV-SNP Attestation**:
   - Fetch VCEK certificate from AMD KDS (cache with filesystem caching).
   - Verify report signature against VCEK chain rooted at AMD Genoa ARK.
   - Validate guest policy (SMT=true, Debug=false, etc.).
   - Validate TCB minimums (BlSpl=0x07, TeeSpl=0x00, SnpSpl=0x0e,
     UcodeSpl=0x48).

4. **Return `SEVVerifyResult`**: analogous to `TDXVerifyResult`, with
   measurement, REPORTDATA, parse error, signature error, policy error.

5. **Integration into Tinfoil Attester**: In `FetchAttestation`, detect the
   format URI. For SEV-SNP, call the new SEV verifier instead of TDX.

**Unit tests**:
- Test SEV-SNP report parsing with captured attestation (testdata).
- Test VCEK chain validation.
- Test policy validation: valid, debug=true rejection, low TCB rejection.
- Test REPORTDATA extraction.

**Commit**: Phase 3 — AMD SEV-SNP attestation verification.

---

### Phase 4: EHBP E2EE Implementation

**Goal**: Implement the Encrypted HTTP Body Protocol for full-body request
encryption and response decryption.

**Files to create**:
- `internal/e2ee/ehbp.go` — EHBP client transport (encrypt request, decrypt
  response)
- `internal/e2ee/ehbp_test.go` — Unit tests
- `internal/e2ee/hpkekeys.go` — RFC 9458 key config parser
- `internal/e2ee/hpkekeys_test.go` — Key config parser tests
- `internal/provider/tinfoil/e2ee.go` — Tinfoil RequestEncryptor

**Go dependency**: Use `github.com/cloudflare/circl/hpke` or the standard
`crypto/hpke` (available in Go 1.24+) for HPKE operations.

**Implementation**:

1. **RFC 9458 Key Config Parser** (`hpkekeys.go`):
   - Parse binary key config from `/.well-known/hpke-keys`.
   - Wire format (RFC 9458 Section 3):
     ```
     key_id       (1 byte)
     kem_id       (2 bytes, big-endian)
     public_key   (Npk bytes, preceded by 2-byte length)
     cipher_suites_length (2 bytes, big-endian)
     [kdf_id (2 bytes) || aead_id (2 bytes)] × N
     ```
   - Validate: key_id=0, kem_id=0x0020, kdf_id=0x0001, aead_id=0x0002.
   - Extract the 32-byte X25519 public key.
   - Reject unknown KEM/KDF/AEAD — fail closed.

2. **EHBP Encryption** (`ehbp.go`):
   - `EncryptRequest(body []byte, serverPubKey [32]byte) (encBody []byte, encapKey [32]byte, senderCtx, error)`:
     - Call HPKE `SetupBaseS` with X25519_HKDF_SHA256 / HKDF_SHA256 /
       AES_256_GCM and the server's public key.
     - Encrypt the body as a single chunk:
       `[4-byte len] [AES-256-GCM ciphertext]`.
       (Or stream multiple chunks if the body is large.)
     - Return the encrypted body bytes, the encapsulated key, and the
       retained HPKE sender context for response decryption.

3. **EHBP Decryption** (`ehbp.go`):
   - `DecryptResponse(encBody io.Reader, responseNonce [32]byte, encapKey [32]byte, senderCtx) ([]byte, error)`:
     - Export secret: `secret = senderCtx.Export("ehbp response", 32)`.
     - Construct salt: `salt = encapKey || responseNonce`.
     - Derive PRK: `prk = HKDF-Extract(salt, secret)`.
     - Derive key: `aead_key = HKDF-Expand(prk, "key", 32)`.
     - Derive nonce: `aead_nonce = HKDF-Expand(prk, "nonce", 12)`.
     - Read chunks: `[4-byte len] [ciphertext]`.
     - Decrypt each chunk with AES-256-GCM:
       nonce = `aead_nonce XOR chunk_index`.
     - On any auth failure: fail closed, return error immediately.

4. **Streaming Response Decryption**:
   - `DecryptResponseStream(body io.Reader, nonce, encapKey, ctx) (io.Reader, error)`:
     - Wraps response body in a reader that decrypts chunks on-the-fly.
     - Used for SSE streaming responses.
     - Each read returns one decrypted chunk.

5. **Tinfoil RequestEncryptor** (`tinfoil/e2ee.go`):
   - Implements `provider.RequestEncryptor`.
   - `EncryptRequest(body, raw, endpointPath)`:
     - Extract HPKE public key from raw attestation (REPORTDATA[32:64]).
     - Optionally, also verify against `/.well-known/hpke-keys`.
     - Call `ehbp.EncryptRequest(body, pubKey)`.
     - Return encrypted body bytes and a Decryptor for the response.
   - Return a `Decryptor` that reads `Ehbp-Response-Nonce` from the response
     headers and calls `ehbp.DecryptResponse`.

6. **Proxy Integration**:
   - The existing proxy E2EE flow calls `Encryptor.EncryptRequest()` and then
     uses the returned Decryptor. The EHBP encryptor follows this same pattern.
   - Set `Ehbp-Encapsulated-Key` header on the outgoing request.
   - On response: read `Ehbp-Response-Nonce` header, pass to Decryptor.
   - If `Ehbp-Response-Nonce` is missing: fail closed.

**Unit tests**:
- Test key config parsing: valid config, wrong KEM, wrong AEAD, truncated.
- Test encryption round-trip: encrypt with a test key, decrypt with known
  private key.
- Test chunked framing: single chunk, multiple chunks, zero-length chunks.
- Test response key derivation: verify against known test vectors (derive key
  from a known HPKE context and nonce, compare expected output).
- Test fail-closed: missing Ehbp-Response-Nonce, corrupted ciphertext.

**Commit**: Phase 4 — EHBP E2EE implementation.

---

### Phase 5: Provider Wiring and Configuration

**Goal**: Wire the Tinfoil provider into the proxy, config, and endpoint
dispatch.

**Files to modify**:
- `internal/proxy/proxy.go` — Add `case "tinfoil"` to `fromConfig()`
- `internal/config/config.go` — Add `TINFOIL_API_KEY` env resolution
- `teep.toml.example` — Add Tinfoil provider example
- `internal/defaults/defaults.go` — Add Tinfoil default allow-fail factors
- `docs/api_support.md` — Update endpoint and E2EE support matrices

**Implementation**:

1. **Config** (`config.go`):
   - Env var: `TINFOIL_API_KEY`.
   - Default base URL: `https://inference.tinfoil.sh`.
   - E2EE default: `true`.

2. **Provider Construction** (`proxy.go:fromConfig`):
   ```go
   case "tinfoil":
       p.ChatPath = "/v1/chat/completions"
       p.EmbeddingsPath = "/v1/embeddings"
       p.AudioPath = "/v1/audio/transcriptions"
       // TTS: /v1/audio/speech — add if proxy supports TTS endpoint
       p.Attester = tinfoil.NewAttester(cp.BaseURL, cp.APIKey, offline)
       p.Preparer = tinfoil.NewPreparer(cp.APIKey)
       p.ReportDataVerifier = tinfoil.ReportDataVerifier{}
       p.Encryptor = tinfoil.NewE2EE(cp.BaseURL, config.NewAttestationClient(offline))
       p.SupplyChainPolicy = nil // Sigstore-based, not compose-based
       p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
   ```

3. **SPKI Caching**: Tinfoil uses a single inference gateway, so
   `SPKIDomainForModel` returns the base URL host for all models:
   ```go
   p.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) {
       return "inference.tinfoil.sh", true
   }
   ```

4. **TLS Fingerprint Verification**: Since Tinfoil is not connection-pinned
   (no PinnedHandler), the proxy must extract the upstream TLS certificate
   fingerprint during the HTTP request and compare against the attested value.
   This may require a custom `http.Transport` with a `VerifyPeerCertificate`
   callback that checks the fingerprint. Follow the `TLSBoundRoundTripper`
   pattern from the Tinfoil Go SDK.

5. **Allow-Fail Defaults**: Create `attestation.TinfoilDefaultAllowFail`
   with factors that may initially be advisory:
   - `tinfoil_sigstore_verified` — supply chain (non-blocking initially)
   - `tinfoil_hardware_measured` — hardware platform matching
   - `sev_snp_verified` — SEV path (until Phase 3 complete)
   - Standard TDX, NVIDIA factors that don't apply to Tinfoil

6. **TTS Endpoint**: If TTS (`/v1/audio/speech`) is not yet a proxy endpoint,
   add it to `proxy.go` following the pattern of other endpoints.

**Unit tests**:
- Test provider construction from config.
- Test SPKI domain resolution.
- Test that unknown Tinfoil config fields are rejected (strict TOML).

**Commit**: Phase 5 — Tinfoil provider wiring and configuration.

---

### Phase 6: Integration Tests

**Goal**: Full API-key-based integration tests for all Tinfoil endpoints.

**Files to create**:
- `internal/integration/tinfoil_test.go` — Integration tests
- `internal/integration/testdata/tinfoil/` — Captured attestation fixtures

**Tests** (all require `TINFOIL_API_KEY`):

1. **Attestation Fetch and Verify**:
   - Fetch attestation from `inference.tinfoil.sh`.
   - Verify TDX quote (or SEV-SNP depending on which platform serves).
   - Verify REPORTDATA binding.
   - Log all verification results.

2. **Supply Chain Verification**:
   - Fetch code measurements from `tinfoilsh/confidential-model-router`.
   - Verify Sigstore bundle.
   - Compare against enclave measurements.

3. **TLS Fingerprint Binding**:
   - Fetch attestation, extract TLS fingerprint.
   - Connect to enclave, extract TLS certificate fingerprint.
   - Verify match.

4. **Chat Completions (non-streaming)**:
   - Send a simple chat request through the proxy.
   - Verify response contains expected fields.
   - Verify request and response were E2EE encrypted/decrypted.

5. **Chat Completions (streaming)**:
   - Send a streaming chat request.
   - Verify SSE events are received and decrypted.

6. **Embeddings**:
   - Send an embedding request with model `nomic-embed-text`.
   - Verify response contains embedding vectors.
   - Verify E2EE.

7. **Audio Transcription**:
   - Send a multipart audio transcription request.
   - Verify response contains transcription text.
   - Verify E2EE (entire multipart body encrypted).

8. **TTS (text-to-speech)**:
   - Send a TTS request.
   - Verify response contains audio data.

9. **Models List**:
   - Send GET /v1/models.
   - Verify response contains expected model IDs.
   - Verify response is plaintext (EHBP does not encrypt GET responses).

10. **Vision (via chat completions)**:
    - Send a chat completion with image content array.
    - Verify response describes the image.

11. **Negative Tests**:
    - Verify that a request with a corrupted `Ehbp-Encapsulated-Key` is
      rejected by the server.
    - Verify that a response with a missing `Ehbp-Response-Nonce` is
      rejected by the proxy (fail closed).

**Fixture Tests** (offline, no API key):
- Capture a real attestation response and save as testdata.
- Test the full verification pipeline against the fixture.

**Commit**: Phase 6 — Tinfoil integration tests.

---

### Phase 7: Verification Report and Documentation

**Goal**: Update verification report generation and documentation.

**Files to modify**:
- `internal/attestation/report.go` — Add Tinfoil-specific verification
  factors
- `docs/api_support.md` — Add Tinfoil provider section
- `docs/measurement_allowlists.md` — Add Tinfoil MR_SEAM values

**New Verification Factors**:
- `tinfoil_attestation_format` — Document format is recognized
- `tinfoil_tdx_policy` — TDX policy checks (attributes, XFAM, MR_SEAM, etc.)
- `tinfoil_sev_policy` — SEV-SNP policy checks (guest policy, TCB)
- `tinfoil_sigstore_verified` — Code measurement verified via Sigstore
- `tinfoil_hardware_measured` — Hardware platform matched (TDX only)
- `tinfoil_hpke_key_binding` — HPKE key from attestation matches key endpoint
- `ehbp_encrypted` — Request was encrypted via EHBP
- `ehbp_response_authenticated` — Response was decrypted and authenticated

**Documentation updates**:
- Add Tinfoil to the endpoint support matrix in `api_support.md`.
- Add Tinfoil E2EE details (EHBP, HPKE, full-body encryption).
- Document that Tinfoil has **no field-level encryption gaps** (full-body).

**Commit**: Phase 7 — Verification report factors and documentation.

---

## Verification Factors Summary

| Factor | Enforced | Description |
|---|---|---|
| `tdx_quote_verified` | Yes | TDX quote cryptographic verification (reusing existing) |
| `sev_snp_verified` | Yes (when implemented) | SEV-SNP report verification |
| `tinfoil_attestation_format` | Yes | Attestation format is recognized |
| `tinfoil_tdx_policy` | Yes | TDX attributes, XFAM, MR_SEAM, RTMR3 zero |
| `tinfoil_sev_policy` | Yes (when implemented) | SEV-SNP guest policy, TCB minimums |
| `tls_key_binding` | Yes | TLS fingerprint matches REPORTDATA |
| `tinfoil_hpke_key_binding` | Yes | HPKE key matches attestation and key endpoint |
| `tinfoil_sigstore_verified` | Advisory initially | Code measurement verified via Sigstore |
| `tinfoil_hardware_measured` | Advisory initially | Hardware platform matched |
| `ehbp_encrypted` | Yes | Request body encrypted via EHBP |
| `ehbp_response_authenticated` | Yes | Response decrypted and AEAD-authenticated |

## Dependencies

New Go module dependencies:
- `github.com/google/go-sev-guest` — AMD SEV-SNP verification (Phase 3)
- `github.com/cloudflare/circl/hpke` or `crypto/hpke` (Go 1.24+) — HPKE
  operations for EHBP (Phase 4)
- `github.com/sigstore/sigstore-go` — Sigstore bundle verification (Phase 2;
  already a dependency via existing `attestation/sigstore.go`)

## Public Documentation References

- Tinfoil attestation specification: https://docs.tinfoil.sh/verification/predicate
- Tinfoil verification overview: https://docs.tinfoil.sh/verification/how-to-verify
- EHBP spec: https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/main/SPEC.md
- EHBP documentation: https://docs.tinfoil.sh/resources/ehbp
- EHBP Go reference: https://pkg.go.dev/github.com/tinfoilsh/encrypted-http-body-protocol
- Tinfoil model catalog: https://docs.tinfoil.sh/models/overview
- RFC 9180 (HPKE): https://www.rfc-editor.org/rfc/rfc9180
- RFC 9458 (OHTTP key config): https://www.rfc-editor.org/rfc/rfc9458

## Risk Assessment

1. **SEV-SNP is new attestation hardware for teep**: No existing SEV-SNP
   verification code. Phase 3 adds this. Can proceed with TDX-only initially
   since the router currently serves TDX attestation (as observed from live
   API).

2. **EHBP is a new E2EE protocol**: Unlike existing field-level or ML-KEM
   protocols, EHBP uses HPKE (RFC 9180). The protocol is well-specified with
   reference implementations in Go, JS, and Swift.

3. **No client nonces**: Tinfoil does not use client-supplied nonces in
   attestation. Freshness comes from the enclave's ephemeral TLS key (rotated
   on reboot). The proxy must re-attest on TLS certificate rotation (SPKI
   cache miss). The `nonce_in_reportdata` verification factor should be
   advisory for Tinfoil, not enforced.

4. **Supply chain model differs**: Tinfoil uses Sigstore/GitHub Actions
   attestations rather than compose-hash/IMA. This is a stronger model (code
   measurement signed by transparent CI) but requires new verification code.

5. **Router architecture**: Tinfoil uses a confidential model router that
   handles multiple models. The attestation covers the router, not individual
   models. This is similar to nearcloud's gateway model.

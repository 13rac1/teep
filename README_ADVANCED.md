# Teep — Technical Reference

Detailed cryptographic and attestation documentation for security engineers. For an overview, see [README.md](README.md).

## Attestation Architecture

Most providers use Intel TDX for CPU attestation and NVIDIA confidential computing for GPU attestation. Tinfoil uses AMD SEV-SNP. Providers differ in how the secure channel between client and TEE is established.

### Venice AI (E2EE)

Venice returns an ECDH public key (`signing_key`) generated inside the TEE. The proxy:

1. Verifies the TDX quote and NVIDIA attestation.
2. Confirms the public key is bound to the TDX REPORTDATA via `keccak256(uncompressed_secp256k1_pubkey)` — the last 20 bytes of the keccak256 hash are placed in REPORTDATA alongside the nonce.
3. Derives a shared secret using ECDH (secp256k1).
4. Encrypts the request body with AES-256-GCM using the shared secret.
5. Decrypts the streaming response using the same shared secret.

The provider's infrastructure never sees plaintext — only the TEE enclave can decrypt.

### NEAR AI Direct (TLS Pinning)

NEAR AI Direct connects to model-specific inference nodes and binds the TLS certificate to the attestation. The proxy:

1. Resolves the model's subdomain via `completions.near.ai/endpoints`.
2. Connects to the model-specific subdomain.
3. Fetches attestation on the same TLS connection.
4. Extracts `tls_cert_fingerprint` from the attestation response.
5. Verifies the server's TLS certificate SPKI matches the attested fingerprint.
6. Confirms the fingerprint is bound to the TDX REPORTDATA via `sha256(signing_address ‖ tls_cert_fingerprint)` in the first 32 bytes, with the nonce in bytes 32–64.
7. Sends the chat request on the same verified connection.

Verified SPKI hashes are cached per-domain to avoid repeated attestation for subsequent requests.

### NEAR AI Cloud (Gateway TLS Pinning)

NEAR AI Cloud routes all traffic through a single TEE-attested API gateway (`cloud-api.near.ai`) that itself runs in an Intel TDX enclave. The proxy:

1. Connects to `cloud-api.near.ai`.
2. Fetches attestation on the same TLS connection — the response includes both model attestation and gateway attestation.
3. Verifies the gateway's TLS certificate SPKI matches the attested fingerprint (same binding scheme as Direct).
4. Verifies the gateway's own TDX quote, event log, and compose binding (Tier 4 factors).
5. Sends the chat request on the same verified connection.

The gateway adds 13 additional verification factors (Tier 4) covering gateway nonce, TDX quote, cert chain, debug mode, measurement allowlists, REPORTDATA binding, compose binding, CPU registry, and event log integrity.

### NanoGPT (TLS, dStack Format)

NanoGPT runs inference nodes using the dStack TEE framework. The proxy:

1. Fetches attestation in dStack format. NanoGPT uses `signing_public_key` (not `signing_key`) and allows the event log to be either a JSON array or a JSON-encoded string (`eventLogFlexible`).
2. Verifies the TDX quote and event log against the dStack measurement policy.
3. Forwards the request over a standard TLS connection.

There is no E2EE and no explicit REPORTDATA binding for the TLS key — channel security relies on TLS alone.

### Chutes (E2EE, Multi-Instance, ML-KEM-768)

Chutes runs multiple confidential compute instances per model. The proxy uses a two-step protocol:

1. **Discovery**: `GET /e2e/instances/{chute}` returns a list of available instances, each with an ML-KEM-768 public key and a one-time nonce.
2. **Evidence**: `GET /chutes/{chute}/evidence?nonce={hex}` returns the TDX quote and optional GPU evidence for the selected instance.
3. Verifies the TDX quote and REPORTDATA binding: `sha256(nonce_hex + e2e_pubkey_base64)` is placed in REPORTDATA.
4. Performs ML-KEM-768 key encapsulation to derive a shared secret.
5. Encrypts the request body with ChaCha20-Poly1305.
6. Decrypts the streaming response with the same shared secret.

Nonces are managed by a pool per instance to avoid repeated evidence fetches on every request. Failed instances are tracked for failover across the multi-instance deployment.

### Phala Cloud (Format-Agnostic Gateway)

Phala Cloud's RedPill gateway accepts traffic destined for multiple underlying TEE backends and returns attestation in the backend's native format. The proxy:

1. Sends a request to `api.redpill.ai/v1`.
2. Receives an attestation response and inspects the JSON keys to determine the backend format: Chutes (`attestation_type`) or dStack (`intel_quote`).
3. Delegates parsing and verification to the appropriate backend handler.
4. Uses a 120-second timeout to accommodate multi-instance attestation latency.

Channel security depends on the detected backend. Chutes backends use ML-KEM-768 E2EE; dStack backends use TLS only.

### Tinfoil Cloud (EHBP via Router)

Tinfoil Cloud routes traffic through a model router at `inference.tinfoil.sh` that runs in an AMD SEV-SNP enclave. The proxy:

1. Fetches attestation from the router's `/enclave/attestation` endpoint with the model name and a client nonce.
2. Verifies the SEV-SNP attestation report: checks the AMD certificate chain, debug policy, REPORTDATA binding, and TCB version.
3. Extracts the HPKE X25519 public key from the attestation's `report_data.hpke_key`.
4. Optionally verifies Sigstore code measurements: fetches the DSSE bundle from the model's GitHub repo and compares the signed code measurement against the live enclave's SEV-SNP MEASUREMENT register.
5. Creates an EHBP session: generates an ephemeral X25519 keypair, encapsulates against the router's public key.
6. Encrypts the entire request body using AES-256-GCM with the derived shared secret, framed as chunked EHBP frames (`[4-byte length][AEAD ciphertext]`).
7. Sends the request with `Ehbp-Encapsulated-Key` header carrying the encapsulated key.
8. Decrypts the response using `Ehbp-Response-Nonce` header for key derivation.

The router decrypts, forwards to the per-model inference enclave internally, and re-encrypts the response. The EHBP key belongs to the router, not the per-model enclave.

### Tinfoil Direct (EHBP to Enclave)

Tinfoil Direct connects to per-model inference enclaves at `{model-slug}.inference.tinfoil.sh`. The proxy:

1. Resolves the model's enclave domain via the `/v1/models` discovery API.
2. Fetches attestation directly from the enclave.
3. Verifies the SEV-SNP report and Sigstore code measurements (same as Cloud).
4. The EHBP key belongs to the inference enclave itself — no router intermediary.
5. Encrypts and decrypts using the same EHBP protocol as Cloud.

This provides true end-to-end encryption: the shared secret is derived between the client and the inference enclave, with no intermediary capable of decryption.

## Provider Comparison

| Provider | Attestation | Channel Security | REPORTDATA Binding |
|----------|-------------|------------------|--------------------|
| Venice AI | TDX + NVIDIA | E2EE (secp256k1 ECDH + AES-256-GCM) | `keccak256(enclave_pubkey)` + nonce |
| NEAR AI Direct | TDX + NVIDIA | TLS pinning (model subdomain) | `sha256(signing_address ‖ tls_fingerprint)` + nonce |
| NEAR AI Cloud | TDX + NVIDIA | TLS pinning (gateway) | `sha256(signing_address ‖ tls_fingerprint)` + nonce |
| NanoGPT | TDX (dStack) | TLS only | None (dStack format) |
| Chutes | TDX + GPU evidence | E2EE (ML-KEM-768 + ChaCha20-Poly1305) | `sha256(nonce_hex + e2e_pubkey_base64)` |
| Phala Cloud | Backend-dependent | Backend-dependent | Backend-dependent |
| Tinfoil Cloud | SEV-SNP | E2EE (HPKE X25519 + AES-256-GCM) | `sha256(nonce ‖ hpke_key ‖ tls_fp ‖ gpu_hash)` in REPORTDATA |
| Tinfoil Direct | SEV-SNP | E2EE (HPKE X25519 + AES-256-GCM) | `sha256(nonce ‖ hpke_key ‖ tls_fp ‖ gpu_hash)` in REPORTDATA |

## Verification Factor Reference

Each factor produces PASS, FAIL, or SKIP. Factors marked `[ENFORCED]` cause the proxy to refuse requests when they fail. Run `teep help <factor>` for a detailed explanation of any individual factor.

### Tier 1: Core Attestation

| # | Factor | Description |
|---|--------|-------------|
| 1 | `nonce_match` | Attestation response nonce matches submitted nonce. Prevents replay attacks. |
| 2 | `tee_quote_present` | Attestation includes a hardware quote (Intel TDX or AMD SEV-SNP). |
| 3 | `tee_quote_structure` | Hardware quote parses as valid QuoteV4 or SEV-SNP report. Displays MRTD or MEASUREMENT. |
| 4 | `tee_cert_chain` | Certificate chain verifies against Intel or AMD root CA. Proves genuine hardware. |
| 5 | `tee_quote_signature` | ECDSA signature over the TDX quote body is valid. Proves the quote hasn't been tampered with. |
| 6 | `tee_debug_disabled` | TD_ATTRIBUTES debug bit is 0. A debug enclave lets the host read enclave memory. |
| 7 | `tee_measurement` | MRTD and MRSEAM match configured measurement policy allowlists. Skipped when no allowlist is configured. |
| 8 | `tee_hardware_config` | RTMR[0] matches the hardware config allowlist. Skipped when no allowlist is configured. |
| 9 | `tee_boot_config` | RTMR[1] and RTMR[2] match the boot config allowlists. Skipped when no allowlist is configured. |
| 10 | `signing_key_present` | Enclave ECDH public key present in response. Required for E2EE key exchange. |
| 11 | `response_schema` | Attestation response JSON matches expected schema (no unknown or missing fields). |

### Tier 2: Binding & Crypto

| # | Factor | Description |
|---|--------|-------------|
| 12 | `tee_reportdata_binding` | REPORTDATA cryptographically binds enclave public key to TDX quote. Without this, an attacker can substitute the key while leaving the quote intact — making E2EE security theater. |
| 13 | `intel_pcs_collateral` | Intel PCS collateral (TCB info, CRLs) fetched for TCB currency check. Skipped in `--offline` mode. |
| 14 | `tee_tcb_current` | TCB SVN meets minimum threshold. Passes for `UpToDate` and `SWHardeningNeeded`. Fails for `OutOfDate` or `Revoked`. Reports Intel Security Advisory IDs when applicable. |
| 15 | `tee_tcb_not_revoked` | TCB SVN is not in the revoked set per Intel PCS. Skipped in `--offline` mode. |
| 16 | `nvidia_payload_present` | NVIDIA GPU attestation payload (EAT or JWT) is present. Proves inference runs on genuine NVIDIA GPU with confidential computing enabled. |
| 17 | `nvidia_signature` | NVIDIA EAT SPDM ECDSA P-384 signatures verified on each GPU cert chain. For JWTs, verifies against NVIDIA JWKS. |
| 18 | `nvidia_claims` | NVIDIA EAT claims valid — architecture, GPU count, driver version, confidential computing mode. |
| 19 | `nvidia_nonce_client_bound` | Nonce in NVIDIA EAT payload matches submitted nonce. Proves GPU attestation is fresh. |
| 20 | `nvidia_nras_verified` | NVIDIA NRAS RIM measurement comparison passed. Complements local SPDM verification by checking firmware hashes against NVIDIA's Reference Integrity Manifest. Skipped in `--offline` mode. |
| 21 | `e2ee_capable` | Enclave public key is a valid secp256k1 uncompressed point suitable for ECDH key exchange. |
| 22 | `e2ee_usable` | E2EE round-trip succeeded with the verified enclave key. Deferred until after the first live request. |

### Tier 3: Supply Chain & Channel Integrity

| # | Factor | Description |
|---|--------|-------------|
| 23 | `tls_key_binding` | TLS certificate public key matches attestation document. Without this, a MITM at the provider's load balancer can intercept traffic. |
| 24 | `cpu_gpu_chain` | CPU (TDX) and GPU (NVIDIA) attestations are cryptographically bound. Without this, attestations could come from different machines. |
| 25 | `nvswitch_binding` | NVSwitch fabric evidence hash verified in REPORTDATA. On multi-GPU NVLink nodes, authenticates the inter-GPU communication fabric. Skips when topology does not use NVSwitch. |
| 26 | `measured_model_weights` | Attestation includes hashes of model weight files. Without this, a compromised provider could load a backdoored model. |
| 27 | `build_transparency_log` | Runtime measurements match an immutable transparency log. Proves the running code matches an audited source revision. |
| 28 | `cpu_id_registry` | CPU PPID verified against the Proof of Cloud registry — a vendor-neutral, append-only log of hardware identities verified by alliance members. Uses threshold multisig across Secret Labs, Nillion, and iEx.ec. |
| 29 | `compose_binding` | `sha256(app_compose)` matches TDX MRConfigID (encoded as `0x01 + sha256`). Binds the docker-compose deployment manifest to hardware attestation. |
| 30 | `sigstore_verification` | Container image sha256 digests from docker-compose found in Sigstore transparency log. Proves verifiable CI/CD provenance. |
| 31 | `sigstore_code_verified` | Tinfoil-specific: Sigstore DSSE bundle code measurements match live enclave's SEV-SNP MEASUREMENT or TDX RTMRs. Skipped for non-Tinfoil providers. |
| 32 | `event_log_integrity` | TDX event log replayed: `RTMR_new = SHA384(RTMR_old ‖ digest)` starting from 48 zero bytes. All 4 replayed RTMRs match quote. Proves the log is authentic and complete. |

### Tier 4: Gateway Attestation (nearcloud only)

Verifies the TEE gateway itself (`cloud-api.near.ai`), in addition to the model inference node.

| # | Factor | Description |
|---|--------|-------------|
| 33 | `gateway_nonce_match` | Gateway `request_nonce` matches the client nonce. Prevents replay attacks against the gateway. |
| 34 | `gateway_tee_quote_present` | Gateway TDX quote is present in the attestation response. |
| 35 | `gateway_tee_quote_structure` | Gateway TDX quote parses as valid QuoteV4. |
| 36 | `gateway_tee_cert_chain` | Gateway certificate chain verifies against Intel SGX/TDX root CA. |
| 37 | `gateway_tee_quote_signature` | ECDSA signature over the gateway TDX quote body is valid. |
| 38 | `gateway_tee_debug_disabled` | Gateway TD_ATTRIBUTES debug bit is 0 (production enclave). |
| 39 | `gateway_tee_measurement` | Gateway MRTD and MRSEAM match configured measurement policy allowlists. |
| 40 | `gateway_tee_hardware_config` | Gateway RTMR[0] matches the hardware config allowlist. |
| 41 | `gateway_tee_boot_config` | Gateway RTMR[1] and RTMR[2] match the boot config allowlists. |
| 42 | `gateway_tee_reportdata_binding` | Gateway REPORTDATA binds `sha256(signing_address ‖ tls_fingerprint)` — same scheme as NEAR AI Direct. |
| 43 | `gateway_compose_binding` | Gateway `sha256(app_compose)` matches TDX MRConfigID. |
| 44 | `gateway_cpu_id_registry` | Gateway CPU PPID verified against the Proof of Cloud registry. |
| 45 | `gateway_event_log_integrity` | Gateway event log replayed; all 4 RTMRs match the gateway TDX quote. |

## TOML Configuration

Config file path is set via `TEEP_CONFIG`. File should have `0600` permissions — teep warns on startup if it is group- or world-readable.

```toml
[providers.venice]
base_url = "https://api.venice.ai"
api_key_env = "VENICE_API_KEY"
e2ee = true

[providers.neardirect]
base_url = "https://completions.near.ai"
api_key_env = "NEARAI_API_KEY"
e2ee = false

[providers.nearcloud]
base_url = "https://cloud-api.near.ai"
api_key_env = "NEARAI_API_KEY"
e2ee = false

[providers.nanogpt]
base_url = "https://nano-gpt.com/api"
api_key_env = "NANOGPT_API_KEY"
e2ee = false

[providers.tinfoil_v3_cloud]
base_url = "https://inference.tinfoil.sh"
api_key_env = "TINFOIL_API_KEY"
e2ee = true

[providers.tinfoil_v3_direct]
api_key_env = "TINFOIL_API_KEY"
e2ee = true

[policy]
enforce = [
  "nonce_match",
  "tee_cert_chain",
  "tee_quote_signature",
  "tee_debug_disabled",
  "signing_key_present",
  "tee_reportdata_binding",
  "compose_binding",
  "nvidia_signature",
  "nvidia_nonce_match",
  "event_log_integrity",
]
```

### Measurement Allowlists

Optional allowlists restrict which TDX measurements are accepted. Values are 96 hex characters (SHA-384), no `0x` prefix.

```toml
# VM image measurement — SHA-384 of initial TD image
mrtd_allow = [
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
]

# Intel SEAM module measurement
mrseam_allow = [
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
]

# Runtime measurement registers (replayed from event log)
rtmr0_allow = [
  "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
]
rtmr1_allow = []
rtmr2_allow = []
rtmr3_allow = []
```

When configured:
- `mrtd_allow` and `mrseam_allow` are enforced in `tee_quote_structure`.
- `rtmr*_allow` values are enforced in `event_log_integrity` after event-log replay matches quote RTMRs.

Empty allowlists disable policy for that measurement.

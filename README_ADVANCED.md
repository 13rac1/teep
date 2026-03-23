# Teep — Technical Reference

Detailed cryptographic and attestation documentation for security engineers. For an overview, see [README.md](README.md).

## Attestation Architecture

Both providers use Intel TDX for CPU attestation and NVIDIA confidential computing for GPU attestation. They differ in how the secure channel between client and TEE is established.

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

The gateway adds 8 additional verification factors (Tier 4) covering gateway nonce, TDX quote, debug mode, compose binding, sigstore verification, and event log integrity.

## Provider Comparison

| Provider | Attestation | Channel Security | REPORTDATA Binding |
|----------|-------------|-----------------|-------------------|
| Venice AI | TDX + NVIDIA | E2EE (ECDH + AES-256-GCM) | `keccak256(enclave_pubkey)` + nonce |
| NEAR AI Direct | TDX + NVIDIA | TLS pinning (model subdomain) | `sha256(signing_address ‖ tls_fingerprint)` + nonce |
| NEAR AI Cloud | TDX + NVIDIA | TLS pinning (gateway) | `sha256(signing_address ‖ tls_fingerprint)` + nonce |

## Verification Factor Reference

Each factor produces PASS, FAIL, or SKIP. Factors marked `[ENFORCED]` cause the proxy to refuse requests when they fail. Run `teep help <factor>` for a detailed explanation of any individual factor.

### Tier 1: Core Attestation

| # | Factor | Description |
|---|--------|-------------|
| 1 | `nonce_match` | Attestation response nonce matches submitted nonce. Prevents replay attacks. |
| 2 | `tdx_quote_present` | Attestation includes an Intel TDX quote — the hardware proof. |
| 3 | `tdx_quote_structure` | TDX quote parses as valid QuoteV4. Displays MRTD (SHA-384 hash of VM image). |
| 4 | `tdx_cert_chain` | Certificate chain verifies against Intel SGX/TDX root CA. Proves genuine Intel hardware. |
| 5 | `tdx_quote_signature` | ECDSA signature over the TDX quote body is valid. Proves the quote hasn't been tampered with. |
| 6 | `tdx_debug_disabled` | TD_ATTRIBUTES debug bit is 0. A debug enclave lets the host read enclave memory. |
| 7 | `signing_key_present` | Enclave ECDH public key present in response. Required for E2EE key exchange. |

### Tier 2: Binding & Crypto

| # | Factor | Description |
|---|--------|-------------|
| 8 | `tdx_reportdata_binding` | REPORTDATA cryptographically binds enclave public key to TDX quote. Without this, an attacker can substitute the key while leaving the quote intact — making E2EE security theater. |
| 9 | `intel_pcs_collateral` | Intel PCS collateral (TCB info, CRLs) fetched for TCB currency check. Skipped in `--offline` mode. |
| 10 | `tdx_tcb_current` | TCB SVN meets minimum threshold. Passes for `UpToDate` and `SWHardeningNeeded`. Fails for `OutOfDate` or `Revoked`. Reports Intel Security Advisory IDs when applicable. |
| 11 | `nvidia_payload_present` | NVIDIA GPU attestation payload (EAT or JWT) is present. Proves inference runs on genuine NVIDIA GPU with confidential computing enabled. |
| 12 | `nvidia_signature` | NVIDIA EAT SPDM ECDSA P-384 signatures verified on each GPU cert chain. For JWTs, verifies against NVIDIA JWKS. |
| 13 | `nvidia_claims` | NVIDIA EAT claims valid — architecture, GPU count, driver version, confidential computing mode. |
| 14 | `nvidia_nonce_match` | Nonce in NVIDIA EAT payload matches submitted nonce. Proves GPU attestation is fresh. |
| 15 | `nvidia_nras_verified` | NVIDIA NRAS RIM measurement comparison passed. Complements local SPDM verification by checking firmware hashes against NVIDIA's Reference Integrity Manifest. Skipped in `--offline` mode. |
| 16 | `e2ee_capable` | Enclave public key is a valid secp256k1 uncompressed point suitable for ECDH key exchange. |

### Tier 3: Supply Chain & Channel Integrity

| # | Factor | Description |
|---|--------|-------------|
| 17 | `tls_key_binding` | TLS certificate public key matches attestation document. Without this, a MITM at the provider's load balancer can intercept traffic. |
| 18 | `cpu_gpu_chain` | CPU (TDX) and GPU (NVIDIA) attestations are cryptographically bound. Without this, attestations could come from different machines. |
| 19 | `measured_model_weights` | Attestation includes hashes of model weight files. Without this, a compromised provider could load a backdoored model. |
| 20 | `build_transparency_log` | Runtime measurements match an immutable transparency log. Proves the running code matches an audited source revision. |
| 21 | `cpu_id_registry` | CPU PPID verified against the Proof of Cloud registry — a vendor-neutral, append-only log of hardware identities verified by alliance members. Uses threshold multisig across Secret Labs, Nillion, and iEx.ec. |
| 22 | `compose_binding` | `sha256(app_compose)` matches TDX MRConfigID (encoded as `0x01 + sha256`). Binds the docker-compose deployment manifest to hardware attestation. |
| 23 | `sigstore_verification` | Container image sha256 digests from docker-compose found in Sigstore transparency log. Proves verifiable CI/CD provenance. |
| 24 | `event_log_integrity` | TDX event log replayed: `RTMR_new = SHA384(RTMR_old ‖ digest)` starting from 48 zero bytes. All 4 replayed RTMRs match quote. Proves the log is authentic and complete. |

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

[policy]
enforce = [
  "nonce_match",
  "tdx_cert_chain",
  "tdx_quote_signature",
  "tdx_debug_disabled",
  "signing_key_present",
  "tdx_reportdata_binding",
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
- `mrtd_allow` and `mrseam_allow` are enforced in `tdx_quote_structure`.
- `rtmr*_allow` values are enforced in `event_log_integrity` after event-log replay matches quote RTMRs.

Empty allowlists disable policy for that measurement.

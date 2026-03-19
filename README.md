# Teep

A local TEE (Trusted Execution Environment) proxy for AI APIs. Teep sits between OpenAI-compatible clients and TEE-capable providers, handling attestation verification, end-to-end encryption, and streaming decryption transparently.

It also benchmarks vendor attestation against a 20-factor verification framework, exposing gaps in TEE implementations.

```
Client (OpenAI SDK) --> 127.0.0.1:8080 (teep)
                          |-- Verify attestation (TDX + NVIDIA GPU)
                          |-- E2EE encrypt request (ECDH + AES-256-GCM)
                          |-- Forward to upstream (Venice AI / NEAR AI)
                          |-- Decrypt streaming response
                          '-- Return plaintext to client
```

## Quick Start

```bash
go build -o teep ./cmd/teep

export VENICE_API_KEY="your-key-here"
./teep serve
```

Point any OpenAI-compatible client at `http://127.0.0.1:8080`:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key="unused")
resp = client.chat.completions.create(
    model="e2ee-qwen3-5-122b-a10b",
    messages=[{"role": "user", "content": "Hello from a TEE"}],
)
print(resp.choices[0].message.content)
```

## Attestation Verification

Run a standalone attestation check against any configured provider:

```bash
./teep verify --provider venice --model e2ee-qwen3-5-122b-a10b
```

Example output:

```
Attestation Report: venice / e2ee-qwen3-5-122b-a10b
════════════════════════════════════════════════════

Tier 1: Core Attestation
  ✓ nonce_match                Nonce matches (64 hex chars)
  ✓ tdx_quote_present          TDX quote present (1,247 bytes)
  ✓ tdx_quote_structure        Valid QuoteV4 structure
  ✓ tdx_cert_chain             Certificate chain valid (Intel root CA)
  ✓ tdx_quote_signature        Quote signature verified
  ✓ tdx_debug_disabled         Debug bit is 0
  ✓ signing_key_present        Signing key: 04a3b2...

Tier 2: Binding & Crypto
  ✓ tdx_reportdata_binding     REPORTDATA binds signing key + nonce  [ENFORCED]
  ? attestation_freshness      Quote age not determinable from response
  ✓ tdx_tcb_current            TCB SVN: 03000000000000000000000000000000
  ✓ nvidia_jwt_present         NVIDIA payload present
  ✓ nvidia_jwt_signature       JWT signature valid (RS256, NVIDIA JWKS)
  ✓ nvidia_jwt_claims          Claims valid (exp: 2026-03-18T21:00:00Z)
  ? nvidia_nonce_match         Nonce field not found in NVIDIA payload
  ✓ e2ee_capable               E2EE key exchange possible

Tier 3: Supply Chain & Channel Integrity
  ✗ tls_key_binding            No TLS key in attestation document
  ✗ cpu_gpu_chain              No CPU->GPU binding in attestation
  ✗ measured_model_weights     No model weight hashes in attestation
  ✗ build_transparency_log     No Sigstore bundle or equivalent
  ✗ cpu_id_registry            No CPU ID registry verification

Score: 12/20 passed, 2 skipped, 6 failed
```

Exits with code 1 if any enforced factor fails.

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VENICE_API_KEY` | Venice AI API key |
| `NEARAI_API_KEY` | NEAR AI API key |
| `TEEP_LISTEN_ADDR` | Listen address (default `127.0.0.1:8080`) |
| `TEEP_CONFIG` | Path to optional TOML config file |

### TOML Config File

```toml
[providers.venice]
base_url = "https://api.venice.ai"
api_key_env = "VENICE_API_KEY"
e2ee = true

[providers.venice.models]
"qwen-e2ee" = "e2ee-qwen3-5-122b-a10b"

[providers.nearai]
base_url = "https://api.near.ai"
api_key_env = "NEARAI_API_KEY"
e2ee = false

[policy]
enforce = ["nonce_match", "tdx_debug_disabled", "signing_key_present", "tdx_reportdata_binding"]
```

Config file should have `0600` permissions. Teep warns on startup if it is group- or world-readable.

## Verification Factors

### Tier 1: Core Attestation

| # | Factor | Description |
|---|--------|-------------|
| 1 | `nonce_match` | Attestation response nonce matches submitted nonce |
| 2 | `tdx_quote_present` | Attestation includes an Intel TDX quote |
| 3 | `tdx_quote_structure` | TDX quote parses as valid QuoteV4 |
| 4 | `tdx_cert_chain` | Certificate chain verifies against Intel root CA |
| 5 | `tdx_quote_signature` | Quote signature valid under attestation key |
| 6 | `tdx_debug_disabled` | TD_ATTRIBUTES debug bit is 0 (production enclave) |
| 7 | `signing_key_present` | Attestation includes a signing public key |

### Tier 2: Binding & Crypto

| # | Factor | Description |
|---|--------|-------------|
| 8 | `tdx_reportdata_binding` | REPORTDATA cryptographically binds signing key + nonce |
| 9 | `attestation_freshness` | TDX quote was generated recently |
| 10 | `tdx_tcb_current` | TCB SVN meets minimum threshold |
| 11 | `nvidia_jwt_present` | NVIDIA GPU attestation payload present |
| 12 | `nvidia_jwt_signature` | NVIDIA JWT signature valid against JWKS |
| 13 | `nvidia_jwt_claims` | JWT claims valid (expiry, issuer) |
| 14 | `nvidia_nonce_match` | Nonce in NVIDIA payload matches submitted nonce |
| 15 | `e2ee_capable` | Provider returned enough info for E2EE key exchange |

### Tier 3: Supply Chain & Channel Integrity

| # | Factor | Description |
|---|--------|-------------|
| 16 | `tls_key_binding` | TLS certificate key matches attestation document |
| 17 | `cpu_gpu_chain` | CPU attestation cryptographically binds GPU attestation |
| 18 | `measured_model_weights` | Attestation proves specific model weights by hash |
| 19 | `build_transparency_log` | Runtime measurements match an immutable transparency log |
| 20 | `cpu_id_registry` | CPU ID verified against a known-good hardware registry |

## Supported Providers

| Provider | Attestation | E2EE | Status |
|----------|-------------|------|--------|
| Venice AI | TDX + NVIDIA | Yes | Supported |
| NEAR AI | TDX + NVIDIA | No | Attestation only |

## License

AGPL-3.0. See [LICENSE](LICENSE).

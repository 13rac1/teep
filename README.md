# Teep

A local TEE (Trusted Execution Environment) proxy for AI APIs. Teep sits between OpenAI-compatible clients and TEE-capable providers, handling attestation verification and channel security transparently.

It also benchmarks vendor attestation against a 21-factor verification framework, exposing gaps in TEE implementations.

```
Client (OpenAI SDK) --> 127.0.0.1:8080 (teep)
                          |
                          |-- Verify attestation (TDX + NVIDIA GPU)
                          |
                          |-- Venice AI path:
                          |     E2EE encrypt (ECDH + AES-256-GCM)
                          |     Forward to upstream
                          |     Decrypt streaming response
                          |
                          |-- NEAR AI path:
                          |     TLS connection pinning via attestation
                          |     Verify SPKI matches attested TLS fingerprint
                          |     Chat on same verified connection
                          |
                          '-- Return plaintext to client
```

## Quick Start

```bash
go build -o teep ./cmd/teep

# Venice AI (E2EE)
export VENICE_API_KEY="your-key-here"
./teep serve

# NEAR AI (TLS pinning)
export NEARAI_API_KEY="your-key-here"
./teep serve --provider nearai
```

Point any OpenAI-compatible client at `http://127.0.0.1:8080`:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key="unused")
resp = client.chat.completions.create(
    model="e2ee-qwen3-5-122b-a10b",  # Venice
    # model="qwen3-235b-a22b",       # NEAR AI
    messages=[{"role": "user", "content": "Hello from a TEE"}],
)
print(resp.choices[0].message.content)
```

## Attestation Verification

Run a standalone attestation check against any configured provider:

```bash
./teep verify --provider venice --model e2ee-qwen3-5-122b-a10b
```

Example output (Venice AI):

```
Attestation Report: venice / e2ee-qwen3-5-122b-a10b
════════════════════════════════════════════════════

Tier 1: Core Attestation
  ✓ nonce_match                nonce matches (64 hex chars) (client-supplied)
  ✓ tdx_quote_present          TDX quote present (10012 hex chars)
  ✓ tdx_quote_structure        QuoteV4 (648 header + 4358 signed data bytes)
  ✓ tdx_cert_chain             certificate chain valid (Intel root CA)
  ✓ tdx_quote_signature        quote signature verified
  ✓ tdx_debug_disabled         debug bit is 0 (production enclave)
  ✓ signing_key_present        signing key present (04e3a1c5b2...)

Tier 2: Binding & Crypto
  ✓ tdx_reportdata_binding     REPORTDATA binds signing key via Ethereum address  [ENFORCED]
  ✓ intel_pcs_collateral       Intel PCS collateral fetched (TCB status: UpToDate)
  ✓ tdx_tcb_current            TCB status UpToDate (TEE_TCB_SVN: 03000500...)
  ✓ nvidia_payload_present     NVIDIA payload present (97782 chars)
  ✓ nvidia_signature            signature valid (ECDSA-P384, NVIDIA Device Identity CA)
  ✓ nvidia_claims              EAT claims valid (arch: HOPPER, GPUs: 8)
  ✓ nvidia_nonce_match         nonce matches in EAT (64 hex chars, HOPPER)
  ✓ nvidia_nras_verified       NRAS: true (JWT verified)
  ✓ e2ee_capable               secp256k1 key valid; E2EE key exchange possible

Tier 3: Supply Chain & Channel Integrity
  ✗ tls_key_binding            no TLS certificate binding in attestation
  ✗ cpu_gpu_chain              CPU-GPU attestation not bound
  ✗ measured_model_weights     no model weight hashes
  ✗ build_transparency_log     no build transparency log
  ✓ cpu_id_registry            registered (machine: ..., label: ...)

Score: 17/21 passed, 0 skipped, 4 failed
```

NEAR AI scores differently — it passes `tls_key_binding` (TLS certificate SPKI bound to attestation) but does not yet support `e2ee_capable` or `cpu_id_registry`.

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
| 8 | `tdx_reportdata_binding` | REPORTDATA cryptographically binds signing key to TDX quote (vendor-specific scheme) |
| 9 | `intel_pcs_collateral` | Intel PCS collateral fetched for TCB status |
| 10 | `tdx_tcb_current` | TCB SVN meets minimum threshold |
| 11 | `nvidia_payload_present` | NVIDIA GPU attestation payload present |
| 12 | `nvidia_signature` | NVIDIA EAT SPDM signature valid (ECDSA-P384) |
| 13 | `nvidia_claims` | NVIDIA EAT claims valid (architecture, GPU count) |
| 14 | `nvidia_nonce_match` | Nonce in NVIDIA EAT payload matches submitted nonce |
| 15 | `nvidia_nras_verified` | NVIDIA NRAS RIM measurement comparison passed |
| 16 | `e2ee_capable` | Provider returned enough info for E2EE key exchange |

### Tier 3: Supply Chain & Channel Integrity

| # | Factor | Description |
|---|--------|-------------|
| 17 | `tls_key_binding` | TLS certificate key matches attestation document |
| 18 | `cpu_gpu_chain` | CPU attestation cryptographically binds GPU attestation |
| 19 | `measured_model_weights` | Attestation proves specific model weights by hash |
| 20 | `build_transparency_log` | Runtime measurements match an immutable transparency log |
| 21 | `cpu_id_registry` | CPU ID verified against a known-good hardware registry |

## Supported Providers

| Provider | Attestation | Channel Security | REPORTDATA Binding |
|----------|-------------|-----------------|-------------------|
| Venice AI | TDX + NVIDIA | E2EE (ECDH + AES-256-GCM) | `sha256(signing_key)` + nonce |
| NEAR AI | TDX + NVIDIA | TLS pinning via attestation | `sha256(signing_address ‖ tls_fingerprint)` + nonce |

**Venice AI** uses end-to-end encryption: the proxy negotiates an ECDH shared secret with the TEE's attested signing key, encrypts the request with AES-256-GCM, and decrypts the streaming response.

**NEAR AI** uses connection pinning: attestation and the chat request happen on the same TLS connection. The proxy verifies the server's TLS certificate SPKI matches the `tls_cert_fingerprint` in the attestation response, which is itself bound to the TDX quote via REPORTDATA. This ensures no MITM between attestation and chat. NEAR AI models are resolved dynamically via an endpoint discovery API (`completions.near.ai/endpoints`), and verified SPKI hashes are cached per-domain to avoid repeated attestation for subsequent requests.

## Development

```bash
make        # build
make test   # run tests with race detector
make lint   # golangci-lint (strict config)
make check  # fmt + vet + lint + test
```

## License

AGPL-3.0. See [LICENSE](LICENSE).

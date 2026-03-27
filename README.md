# Teep

[![CI](https://github.com/13rac1/teep/actions/workflows/ci.yml/badge.svg)](https://github.com/13rac1/teep/actions/workflows/ci.yml)
[![Coverage](https://raw.githubusercontent.com/13rac1/teep/badges/coverage.svg)](https://github.com/13rac1/teep/actions/workflows/ci.yml)
[![License: AGPL](https://img.shields.io/badge/License-AGPL-green.svg)](https://opensource.org/license/agpl-3-0)

**Verify that AI providers can't read your prompts — even if they wanted to.**

When you send a prompt to an AI API, the provider can see everything: your questions, your data, the responses. Teep changes that. It's a local proxy that cryptographically proves the AI model is running inside tamper-proof hardware (a Trusted Execution Environment), then encrypts your conversation so only that hardware can read it.

Teep also scores each provider against a 24-point checklist covering hardware authenticity, encryption strength, and supply-chain integrity — so you can see exactly where the security guarantees hold and where they don't.

```
Client (any OpenAI SDK) ──► localhost:8337 (teep)
                                │
                                ├── Prove the server is genuine hardware
                                ├── Encrypt so only that hardware can read it
                                └── Return plaintext to your app
```

## Quick Start

Binary releases coming soon. For now, requires Go 1.23+.

```bash
# Install
go install github.com/13rac1/teep/cmd/teep@latest

# Venice AI
export VENICE_API_KEY="your-key-here"
teep serve venice

# NEAR AI (direct to inference nodes)
export NEARAI_API_KEY="your-key-here"
teep serve neardirect

# NEAR AI (via cloud gateway)
export NEARAI_API_KEY="your-key-here"
teep serve nearcloud

# NanoGPT
export NANOGPT_API_KEY="your-key-here"
teep serve nanogpt
```

Point any OpenAI-compatible client at `http://127.0.0.1:8337`:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8337/v1", api_key="unused")
resp = client.chat.completions.create(
    model="e2ee-qwen3-5-122b-a10b",  # Venice
    # model="qwen3-235b-a22b",       # NEAR AI
    # model="TEE/llama-3.3-70b-instruct",  # NanoGPT
    messages=[{"role": "user", "content": "Hello from a TEE"}],
)
print(resp.choices[0].message.content)
```

## How It Works

Before forwarding your request, teep asks three questions about the server:

1. **Is the hardware real?** — Verifies Intel TDX and NVIDIA GPU attestation signatures chain back to the manufacturer. A fake server can't forge these.

2. **Is the encryption real?** — Confirms the encryption key was generated inside the verified hardware and is cryptographically bound to the attestation proof. No one — not even the provider — can intercept the key.

3. **Is the software supply chain trustworthy?** — Checks container image signatures against Sigstore transparency logs, verifies the deployment manifest is bound to the hardware attestation, and replays the runtime event log to detect tampering.

Each check produces a pass/fail/skip result. Run `teep verify` to see the full report, or see [Verification Factors](#verification-factors) for details on all 24 checks.

## Attestation Verification

Run a standalone attestation check against any configured provider:

```bash
teep verify venice --model e2ee-qwen3-5-122b-a10b
```

Each line is an independent check — teep verifies these directly against hardware proofs, not provider claims:

```
Attestation Report: venice / e2ee-qwen3-5-122b-a10b
═══════════════════════════════════════════════════

  Hardware:      intel-tdx
  Upstream:      Qwen/Qwen3.5-122B-A10B
  App:           dstack-nvidia-0.5.5
  Compose hash:  242a62724303cc32...
  OS image:      9b69bb1698bacbb6...
  Device:        71b4c123bc28aa4d...
  PPID:          ba19033e7e0a7678...
  Nonce source:  client
  Candidates:    1/6 evaluated
  Event log:     30 entries

Tier 1: Core Attestation
  ✓ nonce_match                nonce matches (64 hex chars) (client-supplied)  [ENFORCED]
  ✓ tdx_quote_present          TDX quote present (10012 hex chars)
  ✓ tdx_quote_structure        valid QuoteV4, MRTD: b24d3b24e9e3c160...
  ✓ tdx_cert_chain             certificate chain valid (Intel root CA)
  ✓ tdx_quote_signature        quote signature verified
  ✓ tdx_debug_disabled         debug bit is 0 (production enclave)  [ENFORCED]
  ✓ signing_key_present        enclave pubkey present (041d9bbc96...)  [ENFORCED]

Tier 2: Binding & Crypto
  ✓ tdx_reportdata_binding     REPORTDATA binds enclave pubkey via keccak256-derived address  [ENFORCED]
  ✓ intel_pcs_collateral       Intel PCS collateral fetched (TCB status: UpToDate)
  ✓ tdx_tcb_current            TCB is UpToDate per Intel PCS
  ✓ nvidia_payload_present     NVIDIA payload present (97494 chars)
  ✓ nvidia_signature           EAT: 8 GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: HOPPER)
  ✓ nvidia_claims              EAT: arch=HOPPER, 8 GPUs, nonce verified
  ✓ nvidia_nonce_match         EAT nonce matches submitted nonce (8 GPUs)
  ✓ nvidia_nras_verified       NRAS: true (JWT verified)
  ✓ e2ee_capable               enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible (ecdsa)

Tier 3: Supply Chain & Channel Integrity
  ✗ tls_key_binding            no TLS certificate binding in attestation
  ✗ cpu_gpu_chain              CPU-GPU attestation not bound
  ✗ measured_model_weights     no model weight hashes
  ? build_transparency_log     compose hash present (242a6272...) but not an independent transparency log
  ✗ cpu_id_registry            hardware not found in Proof of Cloud registry
  ✓ compose_binding            sha256(app_compose) matches MRConfigID
  ✓ sigstore_verification      3 image digest(s) found in Sigstore transparency log
  ✓ event_log_integrity        event log replayed (30 entries), all 4 RTMRs match quote

Score: 19/24 passed, 1 skipped, 4 failed
```

NEAR AI (`neardirect` / `nearcloud`) scores differently — it passes `tls_key_binding` (TLS certificate SPKI bound to attestation) but does not yet support `e2ee_capable` or `cpu_id_registry`.

Exits with code 1 if any enforced factor fails.

## Verification Factors

### Tier 1: Core Attestation

Is the hardware genuine? These checks verify the TDX quote is present, properly signed by Intel, and not from a debug enclave.

<details>
<summary>7 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 1 | `nonce_match` | Attestation response nonce matches submitted nonce |
| 2 | `tdx_quote_present` | Attestation includes an Intel TDX quote |
| 3 | `tdx_quote_structure` | TDX quote parses as valid QuoteV4 |
| 4 | `tdx_cert_chain` | Certificate chain verifies against Intel root CA |
| 5 | `tdx_quote_signature` | Quote signature valid under attestation key |
| 6 | `tdx_debug_disabled` | TD_ATTRIBUTES debug bit is 0 (production enclave) |
| 7 | `signing_key_present` | Enclave ECDH public key present (API field: `signing_key`) |

</details>

### Tier 2: Binding & Crypto

Is the encryption bound to the hardware? These checks verify the encryption key can't be swapped out, GPU attestation is valid, and E2EE key exchange is possible.

<details>
<summary>9 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 8 | `tdx_reportdata_binding` | REPORTDATA cryptographically binds enclave public key to TDX quote (vendor-specific scheme) |
| 9 | `intel_pcs_collateral` | Intel PCS collateral fetched for TCB status |
| 10 | `tdx_tcb_current` | TCB SVN meets minimum threshold |
| 11 | `nvidia_payload_present` | NVIDIA GPU attestation payload present |
| 12 | `nvidia_signature` | NVIDIA EAT SPDM signature valid (ECDSA-P384) |
| 13 | `nvidia_claims` | NVIDIA EAT claims valid (architecture, GPU count) |
| 14 | `nvidia_nonce_match` | Nonce in NVIDIA EAT payload matches submitted nonce |
| 15 | `nvidia_nras_verified` | NVIDIA NRAS RIM measurement comparison passed |
| 16 | `e2ee_capable` | Provider returned enough info for E2EE key exchange |

</details>

### Tier 3: Supply Chain & Channel Integrity

Is the software what it claims to be? These checks verify container provenance, deployment manifests, TLS binding, and runtime integrity.

<details>
<summary>8 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 17 | `tls_key_binding` | TLS certificate key matches attestation document |
| 18 | `cpu_gpu_chain` | CPU attestation cryptographically binds GPU attestation |
| 19 | `measured_model_weights` | Attestation proves specific model weights by hash |
| 20 | `build_transparency_log` | Runtime measurements match an immutable transparency log |
| 21 | `cpu_id_registry` | CPU ID verified against a known-good hardware registry |
| 22 | `compose_binding` | `sha256(app_compose)` matches TDX MRConfigID, binding docker-compose manifest to hardware attestation |
| 23 | `sigstore_verification` | Container image digests found in Sigstore transparency log, proving verifiable CI/CD provenance |
| 24 | `event_log_integrity` | Event log replayed against TDX RTMRs — proves log is authentic and complete |

</details>

For full factor descriptions, run `teep help factors` or see [README_ADVANCED.md](README_ADVANCED.md).

## Supported Providers

| Provider | What teep does |
|----------|---------------|
| [Venice AI](https://venice.ai) | End-to-end encryption (ECDH + AES-256-GCM) |
| [NEAR AI Direct](https://near.ai) | TLS connection pinning to model-specific TEE nodes |
| [NEAR AI Cloud](https://near.ai) | TLS connection pinning through TEE-attested gateway |
| [NanoGPT](https://nano-gpt.com) | TEE attestation with Intel TDX + NVIDIA GPU |

See [README_ADVANCED.md](README_ADVANCED.md) for cryptographic details (ECDH key exchange, REPORTDATA binding schemes, SPKI pinning).

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VENICE_API_KEY` | Venice AI API key |
| `NEARAI_API_KEY` | NEAR AI API key |
| `NANOGPT_API_KEY` | NanoGPT API key |
| `TEEP_LISTEN_ADDR` | Listen address (default `127.0.0.1:8337`) |
| `TEEP_CONFIG` | Path to optional TOML config file |

For TOML configuration, enforcement policies, and measurement allowlists, see [README_ADVANCED.md](README_ADVANCED.md#toml-configuration).

## Development

```bash
make        # build
make test   # run tests with race detector
make lint   # golangci-lint (strict config)
make check  # fmt + vet + lint + test
```

## License

AGPL-3.0. See [LICENSE](LICENSE).

Dual licensing available.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/teep-logo.svg">
  <img alt="teep" src="docs/brand/teep-logo-light.svg" width="200">
</picture>

[![CI](https://github.com/13rac1/teep/actions/workflows/ci.yml/badge.svg)](https://github.com/13rac1/teep/actions/workflows/ci.yml)
[![Coverage](https://raw.githubusercontent.com/13rac1/teep/badges/coverage.svg)](https://github.com/13rac1/teep/actions/workflows/ci.yml)
[![License: AGPL](https://img.shields.io/badge/License-AGPL-green.svg)](https://opensource.org/license/agpl-3-0)

**Verify that AI providers can't read your prompts — even if they wanted to.**

When you type a prompt into an AI API, the company can read everything — your questions, your code, your medical questions, your unreleased ideas. Teep changes that. It's a local proxy that sits between your app and the AI provider, verifies the model is running in a secure hardware vault, and encrypts your conversation so only that hardware can read it — not the company, not their employees, not an attacker who's compromised their servers.

```
Client (any OpenAI SDK) ──► localhost:8337 (teep)
                                │
                                ├── Prove the server is genuine hardware
                                ├── Encrypt so only that hardware can read it
                                └── Return plaintext to your app
```

## Works With

Teep works with any OpenAI-compatible app. Change the base URL to `http://127.0.0.1:8337/v1` in your app's settings:

[OpenClaw](https://openclaw.ai/) · [IronClaw](https://www.ironclaw.com/)

[Open WebUI](https://openwebui.com) · [AnythingLLM](https://anythinglm.com) · [LibreChat](https://librechat.ai)

[Aider](https://aider.chat) · [Cline](https://cline.bot) · [Opencode](https://opencode.ai)

## Supported Providers

[Venice AI](https://venice.ai) · [NEAR AI](https://near.ai) · [Chutes](https://chutes.ai) · [Tinfoil](https://tinfoil.sh) · [Phala Cloud](https://phala.network) · [NanoGPT](https://nano-gpt.com)

## Quick Start

Binary releases coming soon. For now, requires Go 1.25+.

```bash
# Install
go install github.com/13rac1/teep/cmd/teep@latest

# Set API keys for whichever providers you want to use
export VENICE_API_KEY="your-key-here"
export NEARAI_API_KEY="your-key-here"
export CHUTES_API_KEY="your-key-here"
export TINFOIL_API_KEY="your-key-here"

# Start the proxy — all providers with a configured key are active simultaneously
teep serve
```

Query `/v1/models` to see all available `provider:model` combinations:

```bash
curl http://127.0.0.1:8337/v1/models | jq '.data[].id'
# "venice:e2ee-qwen3-5-122b-a10b"
# "neardirect:Qwen/Qwen3-VL-30B-A3B-Instruct"
# "chutes:deepseek-ai/DeepSeek-V3-0324-TEE"
# "tinfoil_v3_cloud:llama3-3-70b"
# ...
```

Point any OpenAI-compatible client at `http://127.0.0.1:8337` and use the `provider:model` format:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8337/v1", api_key="unused")
resp = client.chat.completions.create(
    model="venice:e2ee-qwen3-5-122b-a10b",
    # model="neardirect:Qwen/Qwen3-VL-30B-A3B-Instruct",
    # model="chutes:deepseek-ai/DeepSeek-V3-0324-TEE",
    # model="tinfoil_v3_cloud:llama3-3-70b",
    messages=[{"role": "user", "content": "Hello from a TEE"}],
)
print(resp.choices[0].message.content)
```

## How It Works

Before forwarding your request, teep asks three questions:

1. **Is the hardware real?** — The server proves it's running on genuine Intel TDX or AMD SEV-SNP hardware. A fake server can't forge this proof.

2. **Is the encryption real?** — The encryption key was generated inside the verified hardware. The provider cannot intercept it.

3. **Is the software trustworthy?** — Container images and deployment configuration are verified against public transparency logs that can't be altered.

If any enforced check fails, teep blocks the request. Run `teep verify` to see the full report.

## Attestation Verification

Run a standalone check against any configured provider:

```bash
teep verify venice --model e2ee-qwen3-5-122b-a10b
```

Teep checks up to 45 factors across hardware, encryption, and supply chain, then prints which pass, fail, or skip. Factors that skip are typically optional policy checks not configured for your setup. Factors that fail are known current limitations — see [attestation gaps](docs/attestation_gaps/) for details.

Exits with code 1 if any enforced factor fails. For the full factor list, see [Verification Factors](#verification-factors).

## FAQ

**Does this slow down my app?**
The first request to a provider takes an extra 200–500ms while teep fetches and verifies the attestation. After that, results are cached for 10 minutes — subsequent requests add under 1ms.

**What does this actually protect against?**
Teep protects your prompts from the AI company's employees, a compromised data center, and a network attacker who can see your traffic. It does not protect against a malicious model or hardware backdoors. See [Verification Factors](#verification-factors) for exactly what each provider currently proves.

**What if verification fails?**
Teep blocks the request and returns an error. It never forwards a request to an unverified provider. Run `teep verify` to see exactly which checks failed and why.

**Do I need to trust teep?**
Teep runs entirely on your machine. Your prompts never pass through a teep server. You can verify the binary's own build provenance with `teep self-check`.

**Is this free?**
Yes. Teep is open source under AGPL-3.0. Dual licensing is available for commercial use.

## Provider Details

| Provider | What teep does |
|----------|---------------|
| [Venice AI](https://venice.ai) | End-to-end encryption (ECDH + AES-256-GCM) |
| [NEAR AI Direct](https://near.ai) | TLS connection pinning to model-specific TEE nodes |
| [NEAR AI Cloud](https://near.ai) | TLS connection pinning through TEE-attested gateway |
| [NanoGPT](https://nano-gpt.com) | TEE attestation with Intel TDX + NVIDIA GPU |
| [Chutes](https://chutes.ai) | End-to-end encryption (ML-KEM-768 + ChaCha20-Poly1305) with multi-instance failover |
| [Phala Cloud](https://phala.network) | Format-agnostic gateway supporting Chutes and dStack attestation backends |
| [Tinfoil](https://tinfoil.sh) (Cloud) | End-to-end encryption (HPKE X25519 + AES-256-GCM) via Tinfoil's model router |
| [Tinfoil](https://tinfoil.sh) (Direct) | End-to-end encryption (HPKE X25519 + AES-256-GCM) directly to per-model enclaves |

See [README_ADVANCED.md](README_ADVANCED.md) for cryptographic details.

## Verification Factors

### Tier 1: Core Attestation

Is the hardware genuine? These checks verify the TDX quote (or SEV-SNP report) is present, properly signed, and not from a debug enclave.

<details>
<summary>11 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 1 | `nonce_match` | Attestation response nonce matches submitted nonce |
| 2 | `tee_quote_present` | Attestation includes a hardware quote (Intel TDX or AMD SEV-SNP) |
| 3 | `tee_quote_structure` | Hardware quote parses as valid QuoteV4 or SEV-SNP report |
| 4 | `tee_cert_chain` | Certificate chain verifies against Intel or AMD root CA |
| 5 | `tee_quote_signature` | Quote signature valid under attestation key |
| 6 | `tee_debug_disabled` | TD_ATTRIBUTES debug bit is 0 (production enclave) |
| 7 | `tee_measurement` | MRTD and MRSEAM match configured measurement policy allowlists |
| 8 | `tee_hardware_config` | RTMR[0] matches hardware config allowlist |
| 9 | `tee_boot_config` | RTMR[1] and RTMR[2] match boot config allowlists |
| 10 | `signing_key_present` | Enclave ECDH public key present (API field: `signing_key`) |
| 11 | `response_schema` | Attestation response JSON matches expected schema (no unknown or missing fields) |

</details>

### Tier 2: Binding & Crypto

Is the encryption bound to the hardware? These checks verify the encryption key can't be swapped out, GPU attestation is valid, and E2EE key exchange is possible.

<details>
<summary>11 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 12 | `tee_reportdata_binding` | REPORTDATA cryptographically binds enclave public key to TDX quote (vendor-specific scheme) |
| 13 | `intel_pcs_collateral` | Intel PCS collateral fetched for TCB status |
| 14 | `tee_tcb_current` | TCB SVN meets minimum threshold |
| 15 | `tee_tcb_not_revoked` | TCB SVN is not revoked per Intel PCS |
| 16 | `nvidia_payload_present` | NVIDIA GPU attestation payload present |
| 17 | `nvidia_signature` | NVIDIA EAT SPDM signature valid (ECDSA-P384) |
| 18 | `nvidia_claims` | NVIDIA EAT claims valid (architecture, GPU count) |
| 19 | `nvidia_nonce_client_bound` | Nonce in NVIDIA EAT payload matches submitted nonce |
| 20 | `nvidia_nras_verified` | NVIDIA NRAS RIM measurement comparison passed |
| 21 | `e2ee_capable` | Provider returned enough info for E2EE key exchange |
| 22 | `e2ee_usable` | E2EE round-trip succeeded with the verified enclave key |

</details>

### Tier 3: Supply Chain & Channel Integrity

Is the software what it claims to be? These checks verify container provenance, deployment manifests, TLS binding, and runtime integrity.

<details>
<summary>10 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 23 | `tls_key_binding` | TLS certificate key matches attestation document |
| 24 | `cpu_gpu_chain` | CPU attestation cryptographically binds GPU attestation |
| 25 | `nvswitch_binding` | NVSwitch fabric evidence hash verified in REPORTDATA (multi-GPU NVLink nodes) |
| 26 | `measured_model_weights` | Attestation proves specific model weights by hash |
| 27 | `build_transparency_log` | Runtime measurements match an immutable transparency log |
| 28 | `cpu_id_registry` | CPU ID verified against a known-good hardware registry |
| 29 | `compose_binding` | `sha256(app_compose)` matches TDX MRConfigID, binding docker-compose manifest to hardware attestation |
| 30 | `sigstore_verification` | Container image digests found in Sigstore transparency log, proving verifiable CI/CD provenance |
| 31 | `sigstore_code_verified` | Sigstore DSSE bundle code measurements match live enclave (Tinfoil-specific) |
| 32 | `event_log_integrity` | Event log replayed against TDX RTMRs — proves log is authentic and complete |

</details>

### Tier 4: Gateway Attestation

Available only for providers that route traffic through an independently-attested TEE
gateway (currently `nearcloud`). These factors verify the gateway itself, in addition
to the model inference node.

<details>
<summary>13 factors</summary>

| # | Factor | Description |
|---|--------|-------------|
| 33 | `gateway_nonce_match` | Gateway request nonce matches the client nonce |
| 34 | `gateway_tee_quote_present` | Gateway TDX quote is present |
| 35 | `gateway_tee_quote_structure` | Gateway TDX quote parses as valid QuoteV4 |
| 36 | `gateway_tee_cert_chain` | Gateway cert chain verifies against Intel root CA |
| 37 | `gateway_tee_quote_signature` | Gateway quote signature valid |
| 38 | `gateway_tee_debug_disabled` | Gateway debug bit is 0 (production enclave) |
| 39 | `gateway_tee_measurement` | Gateway MRTD and MRSEAM match measurement policy allowlists |
| 40 | `gateway_tee_hardware_config` | Gateway RTMR[0] matches hardware config allowlist |
| 41 | `gateway_tee_boot_config` | Gateway RTMR[1] and RTMR[2] match boot config allowlists |
| 42 | `gateway_tee_reportdata_binding` | Gateway REPORTDATA binding verified |
| 43 | `gateway_compose_binding` | Gateway sha256(app_compose) matches TDX MRConfigID |
| 44 | `gateway_cpu_id_registry` | Gateway CPU PPID verified in Proof of Cloud registry |
| 45 | `gateway_event_log_integrity` | Gateway event log replayed; all 4 RTMRs match quote |

</details>

For full factor descriptions, run `teep help factors` or see [README_ADVANCED.md](README_ADVANCED.md).

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VENICE_API_KEY` | Venice AI API key |
| `NEARAI_API_KEY` | NEAR AI API key |
| `NANOGPT_API_KEY` | NanoGPT API key |
| `CHUTES_API_KEY` | Chutes API key |
| `PHALA_API_KEY` | Phala Cloud API key |
| `TINFOIL_API_KEY` | Tinfoil API key |
| `TEEP_LISTEN_ADDR` | Listen address (default `127.0.0.1:8337`) |
| `TEEP_CONFIG` | Path to optional TOML config file |

For TOML configuration, enforcement policies, and measurement allowlists, see [README_ADVANCED.md](README_ADVANCED.md#toml-configuration).

## Development

```bash
make           # build
make test      # run tests with race detector
make test-live # run live network tests (requires internet)
make lint      # golangci-lint (strict config)
make check     # fmt + vet + lint + test
```

## License

AGPL-3.0. See [LICENSE](LICENSE).

Dual licensing available.

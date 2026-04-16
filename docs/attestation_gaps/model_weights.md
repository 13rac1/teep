# Model Weight Authentication: Runtime Weights Not Covered by TEE Measurements

**Date:** 2026-04-16
**Status:** Open

TEE attestation proves the correctness of an inference provider's software stack — firmware, kernel, and application code — but does not prove which model weights the inference engine loaded. A provider could pass all hardware attestation checks while serving inference from a cheaper, quantized, or backdoored model. No compensating controls currently exist across the industry, except for Tinfoil's dm-verity attested model volumes.

## The Problem

A TEE attestation proves the *software stack* is correct (firmware, kernel, application code), but does not inherently prove which *data* (model weights) the inference engine loaded. A measured boot chain guarantees the correct inference engine binary is running inside a genuine hardware enclave, but the weights file downloaded at runtime is not covered by the boot measurements.

This creates a gap that undermines the trust model: a compromised or dishonest provider could boot the correct software stack (passing all TEE attestation), then load a cheaper, quantized, or backdoored model. The TEE measurements would still verify, but the inference output would come from the wrong model. Users and downstream applications relying on a specific model's capabilities, safety alignment, or licensing terms have no way to independently verify which model is actually generating their responses.

This is an industry-wide limitation of the current TEE attestation technology stack, not a failure of any individual provider. No current provider — across any TEE framework — exposes model weight hashes or per-token output binding to external clients in a way that enables independent verification. The one exception is Tinfoil, which closes this gap by design using dm-verity attested model volumes.

## Impact

**Security impact:**

- **Model substitution attack**: An attacker controlling or compromising a provider can load a different model than advertised while passing all TEE attestation checks. The substituted model could be quantized (lower quality), fine-tuned (with injected biases or backdoors), or entirely different. The TEE hardware attestation provides no signal of this substitution.
- **Safety alignment bypass**: A backdoored model could pass standard safety evaluations while containing hidden behaviors triggered by specific inputs. Since the model weights are not covered by attestation, there is no cryptographic proof that the deployed model is the same one that passed safety evaluation.
- **Intellectual property fraud**: A provider could claim to run a premium model (justifying higher pricing) while actually serving a cheaper alternative. Users have no verification mechanism.

**Operational impact:**

- **No client-side verification path**: External clients interacting through inference APIs cannot verify model identity. All existing verification mechanisms (where they exist) are server-side and privileged.
- **Trust dependency**: Users must trust provider claims about which model is loaded, despite TEE attestation being specifically designed to eliminate such trust dependencies.

---

## Technical Background

This section covers the foundational knowledge shared across all remediation approaches: what TEE measurements cover, what they don't, and how the gap manifests in each provider architecture.

### TDX measurement registers and model weights

Intel TDX measurement registers cover the boot chain:

| Register | Covers | Relevant to model weights? |
|----------|--------|---------------------------|
| MRTD | Virtual firmware measurement | No — firmware identity only |
| RTMR0 | Virtual hardware config (CPU, RAM, GPU) | No — hardware config only |
| RTMR1 | Linux kernel measurement | No — kernel identity only |
| RTMR2 | Kernel cmdline + initrd + rootfs hash | No — OS image identity only |
| RTMR3 | Runtime event log (compose hash, instance ID) | **Indirectly** — could be extended |
| MRCONFIGID | `0x01 \|\| SHA256(app_compose)` — Docker Compose manifest | **Indirectly** — binds container images, not model files within them |

The key gap: MRTD through RTMR2 measure the *software stack*. MRCONFIGID binds the Docker Compose manifest, which specifies *container images* — but model weights are typically downloaded at runtime by the inference engine *inside* the container, after boot measurements are complete.

### Provider architecture differences

The gap manifests differently across provider architectures:

- **Dstack providers** (Venice, Nearcloud, Neardirect): The Docker Compose manifest is bound into `MRCONFIGID`, and image digests are independently verifiable via Sigstore/Rekor. However, the compose manifest specifies the *container image*, not the model weights. Weights are typically downloaded at runtime by the inference engine inside the container.

- **Sek8s (Chutes)**: The cosign admission controller verifies container images inside the TEE, and the LUKS-encrypted root filesystem prevents boot-time substitution. Weights are downloaded by the inference engine inside the already-measured TEE. See [sek8s_integrity.md](sek8s_integrity.md) for the full Chutes-specific analysis.

- **Tinfoil**: Tinfoil closes the model weight gap by design using dm-verity attested model volumes. The dm-verity root hash is pinned in a measured configuration whose SHA-256 is embedded in the kernel command line (measured into RTMR2). See [dm-verity attested model volumes (Tinfoil V3)](#dm-verity-attested-model-volumes-tinfoil-v3) in Remediation.

---

## Detailed Gap Analysis

### Dstack providers: compose binding does not cover model data

For dstack-based providers, the attestation chain from TDX hardware through compose binding to Sigstore-verified container images is complete and independently verifiable. However, this chain proves which *container image* is deployed — not which model weights the inference engine loaded. The inference engine downloads weights from HuggingFace (or another source) at runtime, inside the already-measured container. No current dstack provider includes a model-specific image or model identity in the Docker Compose manifest.

### Chutes: existing verification mechanisms exclude TEE instances

Chutes implements two server-side weight verification systems — the watchtower and cllmv. Neither is available to external clients for independent verification.

#### Watchtower — server-side weight probing

Source: [`chutesai/chutes-api/watchtower.py`](https://github.com/chutesai/chutes-api/blob/main/watchtower.py)

The watchtower is Chutes' continuous validator-side monitoring system that probes running instances for integrity. It performs multiple verification passes on each chute:

**What the watchtower checks:**

1. **Model weight file hashes** (`check_llm_weights`): For vLLM/SGLang-templated chutes, the watchtower fetches `model.safetensors.index.json` and `config.json` from HuggingFace for the chute's declared model and revision. It SHA256-hashes the full file contents and compares against the hash of the same file read from the miner via the encrypted `/_slurp` endpoint. It then parses the safetensors index to enumerate individual weight shard files and spot-checks random byte ranges within randomly selected shards, comparing SHA256 hashes against HuggingFace.

2. **Process command verification** (`check_commands`, `check_live_code`): Reads `/proc/1/cmdline` and the chute source file from the miner to verify the correct process and code are running.

3. **Environment dump verification** (`check_chute`): Checks Kubernetes environment, LD_PRELOAD (chutes-aegis.so), SGLang process presence and PID stability, and running command line arguments.

4. **Ping tests** (`check_pings`): Encrypted challenge-response liveness probes.

**Why external clients cannot replicate the watchtower:**

| Requirement | Watchtower has | External clients have |
|------------|---------------|----------|
| Filesystem access to miners | Yes, via encrypted `/_slurp` endpoint | No |
| Validator-miner symmetric keys | Yes (AES-256 from hardware attestation handshake) | No |
| Internal miner HTTP protocol | Yes (Bittensor hotkey-authenticated `miner_client`) | No |
| Redis caching infrastructure | Yes (server-side, caches HF hashes) | No |
| Direct HuggingFace model access | Yes | Yes, but no miner-side comparison target |

**Critical: TEE instances are excluded from watchtower.** The watchtower's `load_chute_instances()` explicitly filters out TEE instances:

```python
LaunchConfig.env_type != "tee",  # Exclude TEE
```

For the exact class of instances that run in hardware TEEs, the watchtower's weight verification does not run. TEE instances rely entirely on the measured boot chain (LUKS gating + cosign admission) rather than runtime filesystem probing for weight integrity.

The watchtower exclusion is architecturally coherent: the TEE's measured boot chain should make filesystem probing redundant because the cosign admission controller prevents loading unsigned images, and the LUKS-encrypted root filesystem prevents boot-time substitution. However, this means there is no runtime verification that the correct model weights are loaded in GPU VRAM after the initial boot sequence.

#### cllmv — per-token LLM verification

Source: [`chutesai/cllmv`](https://github.com/chutesai/cllmv) (Python wrapper), `chutes-aegis.so` / `chutes-aegis-verify.so` (closed-source native libraries)

cllmv is a per-token output verification system that cryptographically binds each generated token to the model name and exact HuggingFace revision hash. It is designed to detect model substitution attacks where a miner loads a cheaper or different model than claimed.

**How cllmv works:**

The inference engine (SGLang or vLLM, via Chutes' fork) includes cllmv hooks that generate a verification token for each output token. The token is included in the streaming response as a `chutes_verification` field in each SSE chunk's JSON payload.

The system has two protocol versions:

**V1 (legacy, pre-0.5.5):** An MD5-based interleaving hash.
- Inputs: chunk ID, created timestamp, token text, salt (derived from `config_id`), model name, revision hash
- Output: 32-hex verification token

**V2 (current, >= 0.5.5):** HMAC-SHA256 with an ephemeral session key.
- Session initialization: The miner's `chutes-aegis.so` generates a 312-hex init blob containing an X25519 ephemeral public key. The validator calls `decrypt_session_key()` with its own X25519 private key to derive a shared HMAC session key.
- Inputs: chunk ID, created timestamp, token text, expected token, session key (hex), sub (derived from `config_id + rint_nonce + package_hash`), model name, revision hash
- Output: 32-hex HMAC-SHA256 verification token

**Validator-side enforcement** (from `api/chute/util.py`): The validator checks cllmv tokens for the first 3 tokens of each response plus 1% of subsequent tokens. A failure raises `InvalidCLLMV` and terminates the miner instance — **but only for non-TEE chutes**.

**cllmv is not enforced for TEE instances.** The validator code explicitly exempts TEE chutes:

```python
if not cllmv_ok:
    if not chute.tee:
        raise InvalidCLLMV(...)
```

For TEE instances, cllmv failures are logged but not enforced. TEE chutes rely on hardware attestation and the measured boot chain rather than per-token software verification.

**Why external clients cannot implement cllmv verification:**

1. **Closed-source algorithm**: The hash generation and validation logic lives in `chutes-aegis.so` and `chutes-aegis-verify.so` — proprietary native libraries. The `chutesai/cllmv` Python package is a thin ctypes wrapper; the actual cryptographic algorithm is not published.

2. **Session key unavailable**: V2 cllmv requires an HMAC session key derived from an X25519 key exchange between the miner and the Chutes validator during instance activation. External clients do not participate in this handshake.

3. **Salt/sub depends on internal state**: The `sub` parameter depends on `config_id`, `rint_nonce`, and `package_hashes` — internal Chutes validator state not exposed to clients.

4. **TEE exemption makes it moot**: Since Chutes themselves do not enforce cllmv for TEE instances, implementing client-side cllmv checking for TEE instances would be verifying a property the provider intentionally does not guarantee.

**Could cllmv ever be useful to external clients?** In theory, if Chutes published the cllmv hash algorithm specification (or open-sourced the native libraries), the session key or a client-derivable equivalent, and the salt/sub construction from publicly available data, then external clients could add a verification factor that validates per-token proofs. This would provide post-attestation runtime verification — proof that the inference engine is actually using the claimed model, not just that the correct software was booted. However, this would require Chutes to change their TEE trust model to include cllmv enforcement for TEE instances.

### Tinfoil: gap closed by design

Tinfoil closes the model weight gap using dm-verity attested model volumes (see [dm-verity attested model volumes (Tinfoil V3)](#dm-verity-attested-model-volumes-tinfoil-v3) in Remediation). Model weights are transitively authenticated through the Sigstore → code measurements → RTMR2 → kernel cmdline → config hash → dm-verity root hash chain.

### Summary of per-provider model weight evidence

| Provider | Weight auth mechanism | Available to external clients? |
|----------|----------------------|-------------------------------|
| Venice (dstack) | None | N/A |
| Nearcloud (dstack) | None | N/A |
| Neardirect (dstack) | None | N/A |
| Chutes (sek8s) — watchtower | SHA256 weight file probing, random byte range spot-checks | No (server-side only, TEE-excluded) |
| Chutes (sek8s) — cllmv | Per-token HMAC binding model+revision | No (closed-source, TEE-exempt) |
| Tinfoil | dm-verity root hash in attested config → Sigstore bundle | Yes (transitive via Sigstore verification) |

---

## Remediation

Three approaches are viable paths to model weight authentication with current or near-term infrastructure:

1. **[IMA manifest verification](#ima-manifest-verification-requires-provider-api-enrichment)** provides per-file runtime hash verification of model weight files anchored to TDX hardware, but requires providers to enable IMA in their CVM kernels and expose the measurement log through their attestation evidence API.

2. **[Compose-attested model image identity](#compose-attested-model-image-identity-dstack-attestation-chain)** is the fastest path for dstack. It requires only that providers include Sigstore-signed model weight images in the Docker Compose manifest — infrastructure that teep already fully verifies today. Tinfoil's [`modelwrap`](https://github.com/tinfoilsh/modelwrap) tool can create such images. No kernel changes, no new APIs, no new attestation endpoints. The missing piece is provider adoption.

3. **[dm-verity attested model volumes (Tinfoil V3)](#dm-verity-attested-model-volumes-tinfoil-v3)** is the strongest approach. It provides block-level runtime integrity enforcement via dm-verity, with root hashes pinned in a measured configuration and authenticated through Sigstore. Already implemented by Tinfoil; the pattern is reusable by dstack providers.

The remaining approaches — [Independent HuggingFace baseline computation](#independent-huggingface-baseline-computation-reference), [Per-token output binding](#per-token-output-binding-reference), and [Reproducible inference verification](#reproducible-inference-verification-reference) — are documented for reference but are either insufficient on their own (HuggingFace baselines have no verification target without IMA or compose-attested images), depend on closed-source or nonexistent protocols (per-token binding), or face fundamental practical barriers that make them unsuitable as primary verification mechanisms (reproducible inference). Teep cannot independently audit any of these three today.

### IMA manifest verification (requires provider API enrichment)

#### Background: Linux IMA in Confidential Computing

The Linux kernel's [Integrity Measurement Architecture (IMA)](https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture) is a subsystem that measures (hashes) files before they are accessed for read or execution. IMA maintains a runtime measurement list and, when anchored in trusted hardware, an aggregate integrity value over that list. The subsystem has been part of the Linux kernel since version 2.6.30 and consists of three features:

- **IMA-Measurement**: Collects SHA-256 (or SHA-384) hashes of files as they are opened, stores them in a kernel-maintained measurement log at `/sys/kernel/security/ima/ascii_runtime_measurements`, and extends the aggregate hash into a hardware register (TPM PCR or TDX RTMR).
- **IMA-Appraisal**: Compares a file's runtime hash against a known-good value stored as an extended attribute (`security.ima`), denying access on mismatch.
- **IMA-Audit**: Logs file hashes to the system audit log for forensic analysis.

IMA is policy-driven. The `tcb` (Trusted Computing Base) policy measures all executables, all files `mmap`'d for execution (shared libraries), all kernel modules, all firmware, and all files opened by root. Custom policies can restrict measurement to specific paths, file owners, or filesystem types. See the [IMA documentation](https://ima-doc.readthedocs.io/en/latest/ima-concepts.html) and [Keylime's runtime integrity monitoring guide](https://keylime-docs.readthedocs.io/en/latest/user_guide/runtime_ima.html) for policy configuration details.

#### IMA in Intel TDX Trust Domains

Traditional IMA relies on a TPM to anchor the aggregate integrity value. Intel TDX VMs do not have a TPM, but Intel has published a solution: the IMA subsystem is modified to extend measurements into [TDX RTMRs instead of TPM PCRs](https://www.intel.com/content/www/us/en/developer/articles/community/runtime-integrity-measure-and-attest-trust-domain.html). Specifically, an `ima_rtmr_extend` function replaces the TPM PCR extend path, using SHA-384 (the only hash algorithm supported by TDX RTMRs). The event logs are stored in the Confidential Computing Event Log (CCEL) table, and the aggregate measurement is extended into an RTMR — typically RTMR3 for runtime events.

This means the IMA measurement list inside a TDX VM is hardware-anchored: a remote verifier can obtain the TDX quote (which includes the RTMR values), then replay the IMA event log to confirm that the aggregate matches the hardware-attested RTMR value. Any tampering with the event log — adding, removing, or modifying entries — would cause a mismatch with the RTMR, and would be detected.

Intel's [Container Integrity Measurement Agent (CIMA)](https://github.com/cc-api/container-integrity-measurement-agent) project, part of the Confidential Cloud-Native Primitives effort, extends this concept to container-level measurements in TDX environments. CIMA provides container-level evidence including per-container measurements, event logs, and CC reports — exactly the kind of infrastructure needed for model weight verification.

#### How IMA could verify model weights

If a provider enabled IMA inside its TDX inference CVM and exposed the IMA measurement log through its attestation evidence API, teep could:

1. **Fetch the IMA measurement log** from the provider's attestation evidence endpoint alongside the TDX quote and event log.
2. **Replay the IMA log** to recompute the aggregate hash, verifying it matches the RTMR value in the hardware-attested TDX quote. This proves the log has not been tampered with.
3. **Search the IMA log for model weight file entries**. When the inference engine (vLLM, SGLang) opens model weight files (`.safetensors` shards, `config.json`, `tokenizer.json`, etc.), IMA records their SHA-256 or SHA-384 hashes in the measurement log.
4. **Compare model file hashes against HuggingFace reference values**. Teep independently fetches `model.safetensors.index.json` and individual shard metadata from HuggingFace for the declared model and revision, computes expected hashes, and verifies they match the IMA-measured values.
5. **Block the request** if any model weight file hash does not match the expected HuggingFace reference, or if expected model files are absent from the IMA log.

This approach provides **hardware-attested runtime file integrity** — proof not just that the correct software was booted, but that the specific model weight files loaded into the inference engine are the exact files published on HuggingFace for the declared model and revision. Unlike the watchtower approach (which requires server-side filesystem access), IMA verification works through the same attestation evidence channel that teep already consumes.

#### IMA policy requirements for weight verification

For model weight verification to work, the IMA policy inside the inference CVM must be configured to measure the model weight directory. A minimal custom policy would include:

```
# Measure all files read by the inference engine user
measure func=FILE_CHECK uid=1000
# Or more targeted: measure files under the model directory
measure func=FILE_CHECK fowner=1000 dir=/models/
```

The `tcb` built-in policy would also work, since it measures all files opened by root, but a targeted policy reduces log size and focuses on the security-relevant files.

#### Current barriers

No current teep provider exposes IMA measurement logs in their attestation evidence API. The specific barriers are:

1. **dstack does not enable IMA by default**. The dstack base image kernel has IMA support compiled in, but no IMA policy is loaded at boot. Enabling IMA requires adding `ima_policy=tcb` (or a custom policy) to the kernel command line, which would change `RTMR2` (since RTMR2 measures the kernel command line). This is a configuration change that providers would need to make.

2. **No evidence API endpoint for IMA logs**. Even if IMA were enabled, the attestation evidence API would need to expose the IMA measurement log (`/sys/kernel/security/ima/ascii_runtime_measurements`) alongside the TDX quote. No current provider API includes this.

3. **Log size**. The `tcb` policy measures every file opened by root, which in a container runtime produces a large measurement log. For a model inference CVM, the log could contain thousands of entries for system libraries and configuration files in addition to the model weights. This is manageable (Keylime handles IMA logs at scale), but requires efficient parsing.

4. **RTMR binding**. The IMA aggregate must be bound to a specific RTMR in the TDX quote. In the Intel IMA-TDX integration, this is RTMR3 — the same register that dstack currently uses for compose hash and instance ID. Providers would need to coordinate the event log format so that both dstack runtime events and IMA measurements coexist in RTMR3, or allocate a separate register.

This is the single most impactful potential enhancement for model weight authentication. It requires provider cooperation (enabling IMA and exposing the log), but the underlying kernel infrastructure exists today and is actively being developed for confidential computing use cases.

### Compose-attested model image identity (dstack attestation chain)

For dstack-based providers (Venice, Nearcloud, Neardirect), a stronger approach than simple metadata is available today through the existing dstack attestation chain. The key insight is that the Docker Compose manifest is cryptographically bound to the TDX hardware attestation, and the images referenced in that manifest can be independently verified through Sigstore and Rekor. If the inference container image is built reproducibly and its source code is auditable, then the attestation chain can prove that a specific model image — and therefore specific model weights — is in use.

#### The dstack attestation chain for model identity

The full chain from hardware attestation to model identity works as follows:

```
Intel TDX Hardware
  │
  ├── MRSEAM ← Intel TDX module identity (published by Intel)
  ├── MRTD ← Virtual firmware measurement (deterministic per dstack image version,
  │           derivable via reproducible build from Dstack-TEE/meta-dstack)
  ├── RTMR0 ← Virtual hardware config (CPU, RAM, GPU)
  ├── RTMR1 ← Linux kernel measurement
  ├── RTMR2 ← Kernel cmdline + initrd + rootfs hash
  │
  └── RTMR3 → Event log (replayable)
        │
        └── MRCONFIGID = 0x01 || SHA256(app_compose)
                │
                └── app_compose contains Docker Compose manifest
                      │
                      ├── image: registry/inference-engine@sha256:<digest>
                      │     │
                      │     └── Sigstore/Rekor verification:
                      │           ├── Rekor transparency log entry exists
                      │           ├── DSSE signature verifies against Fulcio cert
                      │           ├── SET verifies against Rekor public key
                      │           ├── Merkle inclusion proof verifies
                      │           └── Fulcio OIDC provenance (source repo, commit, builder)
                      │
                      └── image: registry/model-weights@sha256:<digest>
                            │
                            └── Same Sigstore/Rekor chain as above
```

Each link in this chain is already verified by teep:

1. **TDX quote verification**: The quote signature is verified against Intel PCS collateral, proving it was generated by genuine TDX hardware.
2. **Base image authentication**: `MRTD` is deterministic for a given dstack OS image version and can be derived from the [reproducible build](https://github.com/Dstack-TEE/meta-dstack) using the [`dstack-mr` tool](https://github.com/Dstack-TEE/dstack/tree/master/dstack-mr). This proves the virtual firmware is the expected open-source dstack firmware. `RTMR1` and `RTMR2` prove the kernel and rootfs match the expected dstack image. See the [dstack attestation guide](https://github.com/Dstack-TEE/dstack/blob/master/attestation.md) for the full measurement derivation process.
3. **Compose binding**: `MRCONFIGID` is compared (using `subtle.ConstantTimeCompare`) against `0x01 || SHA256(app_compose)`, proving the Docker Compose manifest running in the CVM is exactly the one declared in the attestation evidence.
4. **Image digest verification**: Image digests (`@sha256:...`) are extracted from the compose manifest and looked up in the [Rekor transparency log](https://docs.sigstore.dev/logging/overview/). Each entry is verified: DSSE signature against the Fulcio certificate, Signed Entry Timestamp (SET) against the Rekor public key, and Merkle inclusion proof against the append-only log. [Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) OIDC provenance metadata (source repository, commit SHA, CI/CD builder identity) is extracted where available.

#### How this chain can prove model identity

The crucial observation is that the Docker Compose manifest can reference **both** an inference engine image **and** a model weights image (or a combined image containing both). If the provider structures its deployment as:

```yaml
services:
  inference:
    image: registry/provider-inference@sha256:abc123...
    volumes:
      - model-data:/models
  model-loader:
    image: registry/model-weights-llama3.1-70b@sha256:def456...
    volumes:
      - model-data:/models
```

...or as a single combined image:

```yaml
services:
  inference:
    image: registry/inference-with-llama3.1-70b@sha256:abc123...
```

...then the model weights image digest is bound into the compose manifest, which is bound into `MRCONFIGID`, which is bound into the TDX quote. The chain from hardware attestation to model identity is complete.

#### Sigstore verification of model weight images

For the chain to provide cryptographic assurance, the model weights image must be signed in Sigstore with verifiable provenance:

1. **The image is built reproducibly** from a public Dockerfile and published model weights (e.g., from HuggingFace). The build process downloads specific model weight files by revision hash, packages them into a container image, and pushes the image to a registry with a content-addressable digest.

2. **The image is signed with Sigstore/Cosign** using [keyless signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/) (Fulcio OIDC identity from a CI/CD system like GitHub Actions). The signature and attestation are recorded in the [Rekor transparency log](https://docs.sigstore.dev/logging/overview/).

3. **The image includes SLSA provenance and/or SBOM attestations** generated by BuildKit or a dedicated attestation tool, documenting the source repository, commit, build parameters, and base image used. These attestations are themselves signed and logged in Rekor.

4. **Teep verifies the Sigstore chain** for the model weights image digest extracted from the compose manifest. If the Fulcio OIDC provenance shows the image was built from a known source repository at a specific commit, the image contents are auditable: anyone can inspect the Dockerfile and build scripts to confirm that the image contains the claimed model weights and nothing else.

#### Source code audit of inference images

The Sigstore provenance chain connects each image digest to a source repository and commit. For the proof to be complete, the inference engine image source code must be auditable to verify that:

1. **The inference engine loads weights from the declared path** — the container's entrypoint or startup script specifies a model directory that corresponds to the volume mount or embedded weights.
2. **No runtime weight substitution is possible** — the inference engine does not download alternative weights at runtime, override the model path via environment variables that are not in the compose manifest, or accept model paths from external API calls.
3. **The model revision matches** — if the image embeds a HuggingFace model, the Dockerfile pins the exact revision hash (e.g., `huggingface-cli download meta-llama/Llama-3.1-70B --revision abc123`).

Since dstack is open source ([Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack)) and the base image is reproducibly built ([Dstack-TEE/meta-dstack](https://github.com/Dstack-TEE/meta-dstack)), the runtime environment itself is auditable. The remaining audit target is the inference container image — which, if it too is built from public source with Sigstore provenance, completes the chain.

#### What providers need to do

For this approach to work, providers must:

1. **Reference model weight images by digest** in the Docker Compose manifest (not by tag). Tags are mutable; digests are content-addressed and immutable.
2. **Sign model weight images with Sigstore** using keyless (Fulcio OIDC) signing from a CI/CD pipeline, and include SLSA provenance attestations. This records the build in the Rekor transparency log.
3. **Build model weight images from public, auditable source** — a public Dockerfile that downloads weights from HuggingFace by revision hash and packages them. The Dockerfile and CI configuration must be in a public repository so that the Fulcio OIDC provenance (source repo + commit) is independently verifiable. Tinfoil's [`modelwrap`](https://github.com/tinfoilsh/modelwrap) tool can create model weight container images suitable for this purpose.
4. **Use separate images or clearly structured combined images** so that the model identity is unambiguous from the compose manifest. A combined `inference-with-model` image works if the Dockerfile clearly shows which model is embedded.

#### What teep can verify today vs. what's needed

| Verification step | Status |
|------------------|--------|
| TDX quote authenticity | **Verified today** |
| Base image measurements (MRTD, RTMR0–2) | **Verified today** (with allowlists) |
| Compose binding (MRCONFIGID) | **Verified today** |
| Image digests in Sigstore/Rekor | **Verified today** |
| DSSE signature + SET + inclusion proof | **Verified today** |
| Fulcio OIDC provenance extraction | **Verified today** |
| **Model weights image in compose** | **Not yet available** — no provider currently includes a model-specific image or model identity in the compose manifest |
| **Source audit of inference images** | **Manual** — requires human review of Dockerfiles and build scripts linked from Fulcio provenance |

The infrastructure for this verification already exists in teep. The missing piece is provider adoption: structuring deployments so that model identity is explicit in the compose manifest, and signing model images with Sigstore provenance that traces back to auditable source.

### dm-verity attested model volumes (Tinfoil V3)

Tinfoil's V3 attestation uses [`modelwrap`](https://github.com/tinfoilsh/modelwrap) to create a read-only dm-verity volume containing model weights and compute a Merkle tree root hash over the volume contents. This root hash is pinned in `tinfoil-config.yml`, whose SHA-256 is embedded in the kernel command line (measured into RTMR2 for TDX, or the launch measurement for SEV-SNP).

At runtime, the CVM mounts the model volume read-only with dm-verity enabled. The kernel validates every block read against the Merkle tree root hash. A tampered block causes an I/O error and inference fails. All disks are mounted read-only with ramdisk for ephemeral data, so runtime weight substitution is not possible.

The full authentication chain is: Sigstore bundle → code measurements → RTMR2 → kernel cmdline → config hash → dm-verity root hash → model weight volume. Teep verifies the Sigstore bundle and compares attestation registers against it; when `sigstore_code_verified` passes, the model weights are transitively authenticated, and `measured_model_weights` can be set to `Pass`.

This approach is strictly stronger than compose-attested images because it provides block-level runtime integrity enforcement — not just proof that an image was deployed, but cryptographic verification of every block of model data as it is read. The `modelwrap` tool and dm-verity volume scheme are not Tinfoil-specific; dstack providers could adopt the same pattern by building dm-verity model volumes, pinning their root hashes in the compose manifest or a measured configuration file, and mounting them read-only inside the CVM.

#### Comparison of approaches

| Property | IMA manifest verification | Compose-attested model image | dm-verity attested volume |
|----------|---------------------------|------------------------------|---------------------------|
| Proves model weights on disk | Yes (runtime file hashes) | Yes (image contains weights) | Yes (block-level Merkle tree) |
| Proves weights loaded in VRAM | Closer (measures files as they are opened for read) | No (proves image was deployed, not that engine used those files) | Block-level (every read validated by kernel) |
| Requires provider API changes | Significant (enable IMA, expose log, coordinate RTMR usage) | Minimal (add model image to compose, sign in Sigstore) | Moderate (build dm-verity volumes, pin root hash in config) |
| Requires source code audit | No (file hashes are directly compared) | Yes (Dockerfiles + inference scripts) | No (dm-verity enforced by kernel) |
| Runtime substitution prevention | No (measures but does not block) | Depends on container config | Yes (read-only mount, kernel-enforced) |
| Available today | Kernel infrastructure exists; needs provider enablement + API | Infrastructure exists; needs provider adoption | Implemented by Tinfoil; pattern reusable by dstack |
| Granularity | Per-file (individual weight shard hashes) | Per-image (all weights verified as a unit) | Per-block (4K block Merkle tree) |

### Independent HuggingFace baseline computation (reference)

Teep could independently compute expected model reference data from HuggingFace:

1. For a given model, resolve the model name and revision (already available from provider configuration)
2. Fetch `model.safetensors.index.json` from HuggingFace for the specific revision
3. Compute SHA256 hashes of config files and the safetensors index itself
4. Store these as expected values in configuration

This would not verify what is actually loaded on the provider (teep has no filesystem access), but it would provide a **reference baseline** that could be checked against any future evidence API enrichment (IMA manifests, model identity metadata, or per-token output binding tokens).

### Per-token output binding (reference)

If inference engines exposed a standardized per-token verification hash that clients can independently recompute, teep could verify that each token was generated by the claimed model. This requires:

1. A published, open specification for the hash algorithm
2. Inputs derivable by the client (model name, revision, token text, nonce)
3. No dependency on server-side secrets

No provider currently offers this. Chutes' cllmv is the closest existing implementation, but it uses closed-source algorithms and server-side secrets.

### Reproducible inference verification (reference)

Both SGLang and vLLM have recently added **batch-invariant inference** modes that aim to make LLM output deterministic regardless of concurrent server load. If a provider runs its inference engine in deterministic mode, teep could exploit this property to verify model identity without filesystem access, IMA manifests, or provider cooperation: send a challenge prompt with a fixed seed, and compare the output against a known-good reference.

#### How the verification would work

1. **Baseline generation**: Teep generates a random "word salad" prompt (to avoid caching or memorization shortcuts) and selects a fixed seed. It sends this prompt+seed to a **known-good reference provider** — an attested instance that has already passed full TEE verification — and records the complete output as the expected baseline.

2. **Challenge**: Teep sends the identical prompt, seed, and sampling parameters to the **target provider** to be tested.

3. **Comparison**: If the target's output is token-for-token identical to the baseline, the target is running the same model with the same weights on a deterministic inference engine. A mismatch indicates either a different model, different weights (quantized, fine-tuned, or backdoored), or a non-deterministic engine configuration.

This approach is powerful because it requires **no provider API changes** — it works entirely through the existing OpenAI-compatible chat completions endpoint, which already supports a `seed` parameter. It detects model substitution attacks at the inference output level rather than the filesystem level.

#### SGLang deterministic inference

Source: [SGLang deterministic inference blog post](https://www.lmsys.org/blog/2025-09-22-sglang-deterministic/), [tracking issue](https://github.com/sgl-project/sglang/issues/10278), [SGLang docs](https://docs.sglang.ai/advanced_features/deterministic_inference.html)

SGLang (>= 0.5.3) supports deterministic inference via the `--enable-deterministic-inference` server flag. Building on [Thinking Machines Lab's batch-invariant operators](https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/), SGLang replaces the three non-batch-invariant reduction operations in the transformer forward pass — RMSNorm, matrix multiplication, and attention — with batch-invariant implementations that use fixed reduction split sizes. This ensures the floating-point addition order is identical regardless of how many other requests are being processed concurrently.

Key capabilities and limitations:

- **Attention backends**: FlashInfer, FlashAttention 3 (FA3), and Triton are supported. Radix cache support varies — FA3 and Triton support it; FlashInfer does not yet.
- **Non-greedy sampling**: SGLang exposes a per-request `sampling_seed` parameter (distinct from the OpenAI `seed`). When deterministic mode is enabled, SGLang uses a Gumbel-noise-based sampling function seeded by this value, making temperature > 0 sampling reproducible. The default seed is 42.
- **Dense models only (initially)**: Early support covered dense models (Qwen3-8B, Llama-3.1-8B). MoE models (Qwen3-30B-A3B, DeepSeek-V3) were added subsequently. The tracking issue shows ongoing work for quantized models (FP8, NVFP4) and speculative decoding.
- **Tensor parallelism**: TP1 and TP2 are deterministic. Larger TP configurations require deterministic all-reduce kernels, which were added for NVIDIA (via NVLink-Sharp) but had issues on Blackwell TP4 (see [#11513](https://github.com/sgl-project/sglang/issues/11513)).
- **Performance overhead**: ~25–45% throughput reduction compared to non-deterministic mode (with FlashInfer or FA3). CUDA graphs reduce this substantially (2.8x speedup over non-graph deterministic mode).
- **Hardware**: Requires NVIDIA GPUs. AMD ROCm support exists via the Triton backend.

#### vLLM batch invariance

Source: [vLLM reproducibility docs](https://docs.vllm.ai/en/latest/usage/reproducibility/), [batch invariance docs](https://docs.vllm.ai/en/latest/features/batch_invariance/), [tracking issue](https://github.com/vllm-project/vllm/issues/27433), [example](https://github.com/vllm-project/vllm/blob/main/examples/offline_inference/reproducibility.py)

vLLM supports two modes for reproducibility:

1. **`VLLM_ENABLE_V1_MULTIPROCESSING=0`** (offline only): Makes scheduling deterministic by running in single-process mode. Not applicable to online serving.

2. **`VLLM_BATCH_INVARIANT=1`** (offline and online): Enables batch-invariant kernels that produce identical outputs regardless of batch size, based on the same Thinking Machines Lab batch-invariant operators. This is the mode relevant to teep's use case.

Key capabilities and limitations:

- **Hardware requirement**: NVIDIA compute capability 9.0+ only (H100, H200, B100, B200). This excludes A100 and all consumer GPUs.
- **Seed handling**: vLLM V1 defaults seed to 0 (always set). The OpenAI-compatible API accepts a `seed` parameter in the request body. With `VLLM_BATCH_INVARIANT=1`, the same seed produces the same output across runs.
- **Model support**: Tested on DeepSeek-V3/R1, Qwen3 (dense and MoE), Qwen2.5, Llama 3, GPT-OSS, and Mistral models. Other models may work but are not validated.
- **Same-hardware restriction**: vLLM explicitly documents that reproducibility is only guaranteed "when it runs on the same hardware and the same vLLM version." Different GPU models or driver versions may produce different results even with identical inputs.
- **Feature status**: Batch invariance is in beta. The tracking issue shows ongoing work for Blackwell DeepGEMM support, TRITON_MLA, FLASHINFER_MLA, torch.compile integration, and performance optimization.

#### Limitations for teep

Despite the promise, several fundamental obstacles prevent teep from implementing reproducible inference verification today:

1. **Providers do not enable deterministic mode**. No current teep provider (Venice, Nearcloud, Neardirect, Chutes) is known to launch its inference engine with `--enable-deterministic-inference` (SGLang) or `VLLM_BATCH_INVARIANT=1` (vLLM). Without these flags, the `seed` parameter only controls the sampling random state — the forward pass itself remains non-deterministic due to varying batch sizes, making cross-instance output comparison unreliable.

2. **Same-hardware requirement**. Both SGLang and vLLM only guarantee determinism on identical hardware (same GPU model, same driver version, same CUDA version) and the same engine version. Teep's known-good reference and the target provider must run on the same GPU SKU. If Venice runs vLLM on H100s and teep's reference was generated on an A100, the outputs will differ even with deterministic mode enabled and the same model. This means teep would need to maintain per-hardware-configuration, per-engine-version reference baselines — a combinatorial explosion.

3. **Engine version coupling**. A vLLM or SGLang version upgrade can change the deterministic output for the same input, even when the model weights are unchanged. Internal kernel implementations, tiling strategies, and numerical libraries evolve across versions. Teep's baselines would need to be regenerated for every engine version, and teep would need to know the exact engine version the target is running — information currently not exposed in attestation evidence.

4. **Tensor parallelism sensitivity**. Most production deployments use TP > 1 for large models. Determinism under larger TP configurations is fragile: SGLang had open bugs for Blackwell TP4 ([#11513](https://github.com/sgl-project/sglang/issues/11513)), and vLLM's batch-invariant custom all-reduce is still under active development. Different TP configurations produce different results even with the same GPU model.

5. **No way to confirm deterministic mode is active**. Even if a provider claims to support deterministic inference, teep has no way to verify the inference engine was actually launched with the deterministic flag. The attestation evidence covers the software image (container hash) but not runtime launch arguments. A provider could run the correct container image but omit `--enable-deterministic-inference`, and teep would have no way to distinguish this from a provider running in deterministic mode with a different model.

6. **Model coverage gaps**. Deterministic inference support is not universal. Both SGLang and vLLM are still expanding model coverage — quantized models (FP8, NVFP4), speculative decoding configurations, and newer architectures may not yet be validated for determinism. A model that works non-deterministically on a provider may not be testable via this approach.

7. **Performance cost to providers**. Deterministic inference carries a 25–45% throughput penalty (SGLang benchmarks). Providers optimizing for cost and latency have no incentive to enable it. Unless the deterministic mode becomes zero-cost or providers adopt it for their own RL training workloads, voluntary adoption is unlikely.

8. **MoE model non-determinism**. Mixture-of-Experts models (DeepSeek-V3, Qwen3-30B-A3B) have additional sources of non-determinism from expert routing and expert-parallel communication. While both SGLang and vLLM have added MoE deterministic support for some models, this area is less mature than dense model determinism, and expert-parallel (EP) configurations remain unsupported.

#### What would make this viable?

For reproducible inference verification to become practical for teep:

1. **Providers enable deterministic mode** and advertise it in their attestation evidence or API metadata, along with the exact engine version and GPU hardware identifier.
2. **Deterministic mode flag is bound into TEE measurements** — e.g., included in the Docker Compose manifest (for dstack) or container entrypoint arguments (for sek8s), so that the attestation proves the flag was set at launch.
3. **A standard "deterministic inference" capability** is advertised by the OpenAI-compatible API (e.g., a field in the `/v1/models` response), allowing teep to discover support automatically.
4. **Engine version and GPU model** are included in the attestation evidence, enabling teep to select the correct reference baseline.
5. **The performance gap narrows** sufficiently that providers are willing to accept the overhead, or deterministic mode becomes the default for TEE deployments where correctness matters more than throughput.

Even without complete provider support, teep could implement a partial verification by maintaining a set of challenge-response baselines per model, per engine version, per GPU SKU, and flagging any provider whose output deviates. This would not be a hard authentication factor (too many confounding variables), but could serve as a **soft signal** — a mismatch warrants further investigation, while a match provides additional confidence beyond attestation alone.

### Deployment priority

| Priority | Approach | Effort | Security strength | Available today? |
|----------|---------|--------|-------------------|-----------------|
| 1 (fastest) | Compose-attested model image identity | Minimal — add model image to compose, sign in Sigstore | Image-level (proves deployment, not runtime load) | Infrastructure exists; needs provider adoption |
| 2 (strongest) | dm-verity attested model volumes | Moderate — build dm-verity volumes, pin root hash | Block-level runtime enforcement | Implemented by Tinfoil; pattern reusable |
| 3 (most impactful) | IMA manifest verification | Significant — enable IMA, expose log, coordinate RTMR | Per-file runtime hashes, hardware-anchored | Kernel infrastructure exists; needs provider enablement + API |

For dstack and sek8s providers, `measured_model_weights` will remain `Fail` until one of the viable approaches is adopted:

1. **[Compose-attested model image identity](#compose-attested-model-image-identity-dstack-attestation-chain)** (fastest path for dstack): Include Sigstore-signed model weight images in the Docker Compose manifest (Tinfoil's [`modelwrap`](https://github.com/tinfoilsh/modelwrap) can create such images). Teep's existing verification chain already covers every link from TDX hardware to image identity. The only missing piece is provider adoption.

2. **[dm-verity attested model volumes](#dm-verity-attested-model-volumes-tinfoil-v3)** (strongest, reusable): Build dm-verity model weight volumes with [`modelwrap`](https://github.com/tinfoilsh/modelwrap) or equivalent, pin the root hash in a measured configuration, and mount read-only. Provides block-level runtime integrity. Already implemented by Tinfoil; the pattern is reusable by dstack providers.

3. **[IMA manifest verification](#ima-manifest-verification-requires-provider-api-enrichment)** (per-file granularity): Enable Linux IMA in the CVM kernel and expose the IMA measurement log through the attestation evidence API. This gives per-file runtime hash verification of model weights, hardware-anchored to TDX RTMRs.

The remaining approaches documented above (HuggingFace baselines, per-token output binding, reproducible inference) are provided for reference but are either insufficient on their own, depend on closed-source protocols, or face fundamental practical barriers. They cannot serve as primary model weight authentication mechanisms for teep.

---

## References

- **Linux IMA**
  - [How to use the Linux kernel's Integrity Measurement Architecture](https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture) — Red Hat IMA overview
  - [IMA concepts documentation](https://ima-doc.readthedocs.io/en/latest/ima-concepts.html) — IMA policy and configuration
  - [Keylime runtime integrity monitoring](https://keylime-docs.readthedocs.io/en/latest/user_guide/runtime_ima.html) — IMA integration with remote attestation

- **IMA in Intel TDX**
  - [Runtime integrity measurement and attestation in Trust Domains](https://www.intel.com/content/www/us/en/developer/articles/community/runtime-integrity-measure-and-attest-trust-domain.html) — Intel IMA-TDX integration
  - [Container Integrity Measurement Agent (CIMA)](https://github.com/cc-api/container-integrity-measurement-agent) — Intel container-level TDX measurements

- **Sigstore and supply chain**
  - [Sigstore overview](https://docs.sigstore.dev/) — Keyless signing and transparency logging
  - [Signing with containers (Cosign)](https://docs.sigstore.dev/cosign/signing/signing_with_containers/) — Keyless container image signing
  - [Rekor transparency log](https://docs.sigstore.dev/logging/overview/) — Append-only transparency log
  - [Fulcio certificate authority](https://docs.sigstore.dev/certificate_authority/overview/) — OIDC-based code signing certificates

- **Dstack attestation**
  - [Dstack attestation guide](https://github.com/Dstack-TEE/dstack/blob/master/attestation.md) — Full measurement derivation
  - [dstack-mr tool](https://github.com/Dstack-TEE/dstack/tree/master/dstack-mr) — Reproducible measurement computation
  - [meta-dstack reproducible build](https://github.com/Dstack-TEE/meta-dstack) — Dstack base image build system
  - [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) — Dstack source code

- **Tinfoil model weight tooling**
  - [modelwrap](https://github.com/tinfoilsh/modelwrap) — Tool for creating dm-verity model weight images

- **Chutes verification systems**
  - [chutesai/chutes-api/watchtower.py](https://github.com/chutesai/chutes-api/blob/main/watchtower.py) — Chutes watchtower source
  - [chutesai/cllmv](https://github.com/chutesai/cllmv) — Chutes per-token LLM verification wrapper

- **Deterministic inference**
  - [SGLang deterministic inference blog post](https://www.lmsys.org/blog/2025-09-22-sglang-deterministic/)
  - [SGLang deterministic inference tracking issue](https://github.com/sgl-project/sglang/issues/10278)
  - [SGLang deterministic inference docs](https://docs.sglang.ai/advanced_features/deterministic_inference.html)
  - [Thinking Machines Lab batch-invariant operators](https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/)
  - [vLLM reproducibility docs](https://docs.vllm.ai/en/latest/usage/reproducibility/)
  - [vLLM batch invariance docs](https://docs.vllm.ai/en/latest/features/batch_invariance/)
  - [vLLM batch invariance tracking issue](https://github.com/vllm-project/vllm/issues/27433)
  - [vLLM reproducibility example](https://github.com/vllm-project/vllm/blob/main/examples/offline_inference/reproducibility.py)
  - [SGLang Blackwell TP4 issue](https://github.com/sgl-project/sglang/issues/11513)

---

## Teep Status

Teep currently returns `Fail` for `measured_model_weights` with detail "no model weight hashes" for all providers except Tinfoil. No provider currently exposes model weight hashes or per-token output binding to clients in a way that teep can independently verify.

| Provider | Weight auth mechanism | Available to teep? | Status |
|----------|----------------------|-------------------|--------|
| Venice (dstack) | None | N/A | `Fail`: "no model weight hashes" |
| Nearcloud (dstack) | None | N/A | `Fail`: "no model weight hashes" |
| Neardirect (dstack) | None | N/A | `Fail`: "no model weight hashes" |
| Chutes (sek8s) — watchtower | SHA256 weight file probing, random byte range spot-checks | No (server-side only, TEE-excluded) | `Fail`: "no model weight hashes" |
| Chutes (sek8s) — cllmv | Per-token HMAC binding model+revision | No (closed-source, TEE-exempt) | `Fail`: "no model weight hashes" |
| Tinfoil | dm-verity root hash in attested config → Sigstore bundle | Yes (transitive via `sigstore_code_verified`) | `Pass`: model weights authenticated via dm-verity + Sigstore chain |

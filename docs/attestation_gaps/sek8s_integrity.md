# Sek8s Integrity Chain — Chutes Provider

**Date:** 2025-04-16
**Status:** Open

Chutes runs a custom Kubernetes distribution called **sek8s** inside Intel TDX confidential VMs with a fundamentally different attestation model than dstack providers. While hardware-level TDX measurements can be independently verified by remote clients, the application-layer integrity chain — container image identity, model weights, runtime measurements, and boot gating — relies entirely on server-side controls that are not exposed in the client-facing evidence API.

## The Problem

Chutes' attestation architecture splits trust between two enforcement layers: hardware measurements verified by the Intel TDX platform, and application-layer controls verified by the Chutes validator infrastructure. Only the hardware layer produces evidence available to external clients. The application layer — which determines what software actually runs inside the TEE and what model weights are loaded — is enforced exclusively by Chutes' own systems.

This means that users of Chutes' confidential inference service cannot independently verify which container images are running, whether the correct model was loaded, whether disk decryption was properly gated on measurement verification, or whether runtime integrity monitoring is active. They must trust that Chutes' cosign admission controller, LUKS boot gating, IMA measurement system, and model weight verification are all correctly implemented and enforced.

Unlike dstack-based providers where the Docker Compose manifest hash is bound into a TDX register and container image digests are available for independent supply chain verification, Chutes exposes none of this metadata to clients. The supply chain verification gap is complete: there is zero external visibility into the application-layer software stack.

## Impact

### Security impact

- **Container image substitution:** A compromise of the cosign signing key, a misconfigured admission controller, or a webhook bypass would allow unauthorized container images to run inside an otherwise hardware-attested TEE. External clients would have no way to detect this — the TDX quote would still contain valid hardware measurements.

- **LUKS key leakage:** If the LUKS decryption passphrase leaked or if a code path in `chutes-api` released the key without full measurement verification, a VM with a substituted lower stack could boot and serve traffic. Clients verifying only hardware measurements would see a valid quote from a compromised guest.

- **Golden measurement poisoning:** If the `tee_measurements.yaml` ConfigMap contained a malicious measurement set or fell out of sync with production images, the LUKS gate and measurement verification would pass for the wrong sek8s image. All downstream integrity checks (cosign, IMA, runtime attestation) would inherit this compromise.

- **Model weight substitution:** For TEE instances, model weight integrity depends entirely on the boot chain and cosign admission controller. The watchtower's runtime weight verification explicitly excludes TEE instances, and cllmv per-token verification is not enforced for TEE chutes. A time-of-check-to-time-of-use gap exists: the boot chain verifies the software stack at boot, but does not continuously prove that the expected model revision was loaded into VRAM. TEE memory isolation and the aegis locked-down execution environment mitigate but do not cryptographically prove this.

### Operational impact

- **Verification asymmetry with dstack providers:** Consumers evaluating multiple confidential inference providers will find that Chutes requires significantly more trust assumptions than dstack-based alternatives. Dstack exposes compose bindings, image digests, event logs, and Sigstore/Rekor provenance for independent verification. Chutes exposes none of these, creating a qualitative gap in assurance level.

- **Audit burden:** The absence of client-verifiable application-layer evidence means that security audits of Chutes deployments require direct access to Chutes' infrastructure, source code, and operational practices — they cannot be performed solely from the client perspective.

---

## Technical Background

### Sek8s Architecture

Chutes does not use dstack. It runs **sek8s**, a custom Kubernetes distribution, inside Intel TDX confidential VMs. The attestation model differs from dstack: instead of binding a Docker Compose hash into `MRCONFIGID`, Chutes LUKS-encrypts the guest root filesystem and gates disk decryption on full measurement verification by the Chutes validator (`chutes-api`). Container images are then verified by a cosign admission controller running inside the already-measured TEE.

### TDX Register Usage in Sek8s

Sek8s uses standard Intel TDX registers, but the measurements reflect a different guest stack than dstack:

| Register | What sek8s measures | Determinism notes |
|----------|-------------------|-------------------|
| **MRSEAM** | Intel TDX module identity | Same Intel values as dstack; shared across all TDX providers |
| **MRTD** | sek8s virtual firmware (OVMF) image | Deterministic per firmware version; different from dstack OVMF |
| **RTMR0** | ACPI tables, early boot firmware | Fixed per deployment class; sek8s host-tools fix memory, vCPU, GPU MMIO, and PCI hole sizing to preserve determinism |
| **RTMR1** | Kernel + initramfs | Deterministic per sek8s image build |
| **RTMR2** | Kernel command line | Deterministic per deployment class |
| **RTMR3** | Runtime / IMA measurements | Varies per instance; used in runtime attestation |
| **MRCONFIGID** | **Not used** | Sek8s does not bind a compose manifest or any configuration hash here |
| **REPORTDATA** | Nonce + key binding | Two different formats for server-side and client-side attestation |

Measurement computation uses Intel's `tdx-measure` tool with boot artifacts extracted during the sek8s build process. Golden values are maintained in a Kubernetes ConfigMap (`tee_measurements.yaml`) loaded by `chutes-api`.

### Chutes Security Architecture — Additional Components

Source: [Chutes Security/Integrity documentation](https://chutes.ai/docs/core-concepts/security-architecture)

Chutes documents several additional security layers beyond TEE attestation. Most are **closed-source, validator-side-only** mechanisms:

| Component | Purpose | Available to clients? |
|-----------|---------|-------------------|
| **chutes-aegis.so** | Runtime security: network access control, filesystem encryption, LD_PRELOAD integrity, DNS verification, pod intrusion prevention (intentional segfault on exec/attach) | No. Runs inside the chute container; its enforcement is not attestable externally. |
| **Chutes Secure Filesystem Validation** | Challenge-response filesystem integrity using random digest seeds | No. Validator-miner protocol only. |
| **cllmv** (Chutes LLM Verification) | Per-token verification hashes binding output to model+revision | No. Closed-source algorithm, session key not available. |
| **Environment Dump** | Comprehensive environment snapshot (env vars, kernel, Python modules) | No. Validator-miner protocol only. |
| **Python Code Inspection** | Static analysis of Python bytecode for overrides and logic bombs | No. Validator-side only. |
| **GPU Attestation (graval)** | Proof of Consecutive VRAM Work via matrix multiplications | No. Uses a separate challenge-response protocol not exposed to clients. |
| **forge** (image builder) | Source-of-truth for filesystem and bytecode baselines, cosign signing | No. Build-time only; signed images verified by in-TEE admission controller. |

### IMA (Integrity Measurement Architecture)

The Chutes security documentation states that the Linux kernel's IMA generates a signed manifest of every file on the filesystem, and that this manifest is included in the attestation report's measurements. The documentation further claims:

> "For any chute running on the network, at any time, anyone will be able to query: [...] The Full Software Manifest: We use the Integrity Measurement Architecture (IMA) of the Linux kernel to generate a signed manifest of every single file, library, and package on the filesystem."

However, the current Chutes evidence API does **not** expose IMA manifests or RTMR3 event logs to clients.

---

## Verification Surface

A remote verifier receives a standard Intel TDX quote from the Chutes evidence API. The quote contains the same hardware-signed measurements as any other TDX provider. The following properties can be independently enforced:

### MRSEAM — Intel TDX module identity

The Intel TDX module MRSEAM values are **platform constants** at the TDX module level, but Chutes does not use `DstackMRSEAMAllow` directly. Teep's Chutes defaults use `Sek8sMRSEAMAllow`, which extends `attestation.DstackMRSEAMAllow` with additional accepted module versions. The base dstack defaults live in `internal/attestation/dstack_defaults.go`, and the Chutes provider enforces the sek8s-specific MRSEAM allowlist in `internal/provider/chutes/policy.go`.

**Status:** Enforced. Applied via Go-coded defaults in `internal/provider/chutes/policy.go`, with TOML override support.

### MRTD — Virtual firmware image

Sek8s uses its own OVMF build, distinct from dstack. The MRTD value is deterministic per sek8s firmware version and can be pinned once golden values are obtained. Enforceable via `mrtd_allow` in the provider's TOML policy section.

**Status:** Enforced. Pinned in `internal/provider/chutes/policy.go`.

### RTMR0 — Hardware and boot policy configuration

Sek8s explicitly fixes VM parameters (memory, vCPU count, GPU MMIO regions, PCI hole sizing) to make RTMR0 deterministic within a deployment class. This is documented in `chutesai/sek8s/host-tools/README.md`. Enforceable per deployment class via the `rtmr0_allow` policy.

**Status:** Pinned in `internal/provider/chutes/policy.go`, but allow-fail by default. The `tdx_hardware_config` factor is in `ChutesDefaultAllowFail`, so RTMR0 mismatches are reported but do not block requests unless the operator removes it from `allow_fail`.

### RTMR1 and RTMR2 — Kernel and command line

RTMR1 (kernel + initramfs) and RTMR2 (kernel command line) are deterministic per sek8s image build and deployment class. Enforceable via `rtmr1_allow` and `rtmr2_allow` TOML policy lists.

**Status:** Pinned in `internal/provider/chutes/policy.go`, but allow-fail by default. The `tdx_boot_config` factor is in `ChutesDefaultAllowFail`, so RTMR1/RTMR2 mismatches are reported but do not block requests unless the operator removes it from `allow_fail`. Values will change when Chutes updates the sek8s image.

### REPORTDATA binding

The client-facing REPORTDATA format is:

```
REPORTDATA[0:32] = SHA256(nonce_hex + e2e_pubkey_base64)
```

Verified using the client-generated nonce and the ML-KEM-768 public key from the instances endpoint (`ReportDataVerifier` in `internal/provider/chutes/reportdata.go`). This is a constant-time comparison.

**Status:** Enforced.

### Other enforced factors

- **`tdx_debug_disabled`** — debug attribute bit check
- **`intel_pcs_collateral`** — DCAP certificate chain and collateral verification
- **`tdx_tcb_current`** — TCB level freshness

### Server-side-only security mechanisms

Chutes implements several strong server-side controls that are **not client-verifiable** but form part of the provider's security story:

- **LUKS boot gating:** The `chutes-api` validator only releases the LUKS decryption key after verifying MRTD + all RTMRs against the golden `TeeMeasurementConfig`. If measurements fail, the VM cannot decrypt its root filesystem and cannot boot.

- **Cosign admission controller:** A Kubernetes admission webhook (`chutesai/sek8s/sek8s/validators/cosign.py`) inside the TEE calls `cosign verify` on every container image before allowing pod scheduling. The Chutes build system (`forge`) signs all images during the build process.

- **Runtime re-attestation:** Chutes performs runtime re-attestation using RTMR3 and IMA measurements, verified server-side by `chutes-api`.

The trust implications of these server-side-only mechanisms are analyzed in Detailed Gap Analysis below.

### Comparison with Dstack

| Property | Dstack | Sek8s (Chutes) |
|----------|--------|----------------|
| Firmware identity | MRTD (OVMF, shared across dstack providers) | MRTD (sek8s OVMF, distinct from dstack) |
| App-layer binding | `MRCONFIGID` = `0x01 \|\| SHA256(compose)` | Not used; cosign admission inside TEE |
| Container image verification | Client inspects compose image digests + Sigstore/Rekor | Validator-side only; not visible to clients |
| Event log | Exposed; client replays RTMR3 | Not exposed to clients |
| Boot gating | None; host launches VM regardless | LUKS key withheld until measurements verified |
| Supply chain visibility | Full (compose + image digests + Rekor) | None (trust the cosign admission controller) |
| Model weight verification | Not applicable (no model-specific attestation) | Watchtower (non-TEE only) + cllmv (non-TEE enforced); neither available to clients. See [model_weights.md](model_weights.md) |
| Per-token output binding | Not applicable | cllmv: closed-source, TEE-exempt, not client-verifiable. See [model_weights.md](model_weights.md) |

The trade-off is clear: dstack gives remote verifiers **more independent verification surface** (compose binding, image digests, event log replay), while sek8s gives the **validator stronger boot-time enforcement** (LUKS gating prevents non-compliant VMs from starting) at the cost of requiring trust in the validator's implementation.

---

## Detailed Gap Analysis

### Gap 1: Container image identity not exposed to clients

Chutes verifies container images using a cosign admission controller running inside the TEE (`chutesai/sek8s/sek8s/validators/cosign.py`). The attestation evidence returned to clients does **not** include container image digests, cosign signatures, or any supply chain metadata.

Unlike dstack providers where compose-listed image digests can be inspected and checked against Sigstore/Rekor provenance, there is **zero visibility** into which containers are actually running on a Chutes sek8s node.

### Gap 2: Model weight identity not verifiable

Chutes has two mechanisms for verifying model weights, neither of which is available to external clients:

1. **Watchtower weight verification** (server-side filesystem probing) — explicitly excludes TEE instances
2. **cllmv per-token verification** (closed-source inference-time hashing) — not enforced for TEE chutes

Both are analyzed in detail in [model_weights.md](model_weights.md).

### Gap 3: LUKS boot gating not independently verifiable

The LUKS boot gate is a strong server-side control, but remote clients have no way to independently verify that the LUKS gate was applied or that the decryption key was withheld for a non-matching VM.

### Gap 4: Runtime attestation (RTMR3) not exposed to clients

The event log and runtime IMA measurements are not exposed in the client-facing evidence API. Remote verifiers cannot replay or verify RTMR3.

### Gap 5: GPU-to-measurement binding not independently verifiable

Chutes' `TeeMeasurementConfig` includes `expected_gpus` and `gpu_count` fields, allowing the validator to reject a VM whose GPU inventory does not match the expected deployment class. Remote verifiers can verify GPU evidence independently via NVIDIA EAT tokens, but cannot verify that the Chutes validator applied the GPU-to-measurement binding correctly.

### Gap 6: IMA manifest not exposed despite documentation claims

The Chutes security documentation claims clients will be able to query a full software manifest via IMA, but the current evidence API does not expose IMA manifests or RTMR3 event logs. If implemented as documented, this would enable independent verification of model weight file hashes, container image digests, and library versions by cross-referencing IMA measurements against RTMR3 values in the TDX quote.

### Residual Trust Assumptions

The sek8s attestation model requires trusting Chutes to correctly implement several security controls that cannot be independently verified:

1. **Cosign admission controller is deployed and enforcing.** A compromise of the cosign signing key, a misconfigured admission controller, or a bypass of the webhook would allow unauthorized container images to run inside an otherwise-valid TEE.

2. **LUKS gating is correctly implemented.** If the LUKS passphrase leaked, or if a code path in `chutes-api` released the key without full measurement verification, a VM with a substituted lower stack could boot and serve traffic.

3. **Golden measurements are correct and current.** If the `tee_measurements.yaml` ConfigMap contained a malicious measurement set, or if it fell out of sync with production images, the LUKS gate and measurement verification would pass for the wrong image. When MRTD and RTMR values are pinned via `--update-config`, the recorded values are only trustworthy if the deployment was running the correct sek8s image at capture time.

4. **Runtime attestation is enforced.** RTMR3/IMA verification is entirely server-side. Clients must trust that Chutes re-attests running VMs and revokes access when runtime measurements diverge.

5. **Model weight integrity relies on boot chain, not runtime verification.** The residual risk is a time-of-check-to-time-of-use gap: the boot chain verifies the software stack at boot, but does not continuously prove that the inference engine loaded the expected model revision from HuggingFace into VRAM. In practice, this risk is mitigated by the TEE's memory isolation (an external attacker cannot modify VRAM) and the locked-down execution environment (aegis blocks outbound network access and pod intrusion), but it is not cryptographically proven. See [model_weights.md](model_weights.md) for full analysis.

### Teep Factor Behavior

Teep correctly returns `Skip` for factors where the sek8s architecture does not expose verifiable data:

- **`build_transparency_log`**: "chutes attestation does not include container image metadata; supply chain verification is validator-side only"
- **`compose_binding`**: "chutes uses cosign image admission + IMA, not docker-compose; compose binding not applicable"
- **`sigstore_verification`**: "chutes attestation does not include container image digests; cosign verification is validator-side only"
- **`event_log_integrity`**: "chutes performs RTMR verification validator-side against a golden baseline; event log not exposed to clients"

Teep returns `Fail` for `measured_model_weights` with detail "no model weight hashes" because neither weight verification mechanism exposes verifiable data to clients.

---

## Remediation

### Short-term: Pin observed measurements (done)

Sek8s measurement defaults have been captured and coded in `internal/provider/chutes/policy.go`:
- MRTD, RTMR0, RTMR1, RTMR2 pinned from known-good Chutes deployments
- MRSEAM allowlist extended for sek8s fleet TDX module versions (1.5.0d, 2.0.06)
- Registered in `internal/defaults/defaults.go`

Teep now rejects quotes from VMs running unexpected firmware, kernels, or boot configurations.

### Medium-term: Request evidence API enrichment

Ask Chutes to include in their evidence API response:

1. **IMA manifest** (highest priority): A signed manifest of all files on the TEE filesystem, as described in their own security documentation. This would let teep verify model weight file hashes, container image digests, and library versions independently. Cross-referencing IMA measurements against RTMR3 values in the TDX quote would provide the first client-verifiable runtime integrity proof for sek8s. This would address Gaps 4 and 6, and partially address Gaps 1 and 2.

2. **Model identity metadata**: The HuggingFace model name and exact revision hash for the model loaded on the instance. Even without full weight hashes, confirming model identity would let teep populate `measured_model_weights` with at least a declared-model check. Addresses Gap 2 partially.

3. **`TeeMeasurementConfig` version string**: The deployment class identifier that matched the boot attestation, so teep can correlate the quote to a declared configuration.

4. **Container image digests**: Image hashes for running workloads, so teep can apply independent supply chain checks. Addresses Gap 1.

### Medium-term: Model weight authentication

See [model_weights.md](model_weights.md) for a detailed analysis of approaches including cllmv specification publication, IMA-based weight file verification, HuggingFace baseline computation, and per-token output binding. Addresses Gap 2.

### Long-term: Independent measurement reproduction

Reproduce sek8s golden measurements independently by:

1. Building sek8s from source (`chutesai/sek8s`)
2. Computing MRTD using `tdx-measure` with the sek8s OVMF binary
3. Computing RTMR0-2 for each deployment class using the documented VM parameters
4. Comparing against observed values captured via `--update-config`

This would eliminate residual trust assumption 3 (golden measurement correctness).

### Deployment Priority

| Priority | Action | Addresses | Effort | Responsible |
|----------|--------|-----------|--------|-------------|
| 1 (done) | Pin observed measurements | Hardware verification baseline | Low | Teep (completed) |
| 2 | IMA manifest exposure | Gaps 1, 2, 4, 6 | Medium (Chutes) | Chutes |
| 3 | Container image digests in evidence API | Gap 1 | Low (Chutes) | Chutes |
| 4 | Model identity metadata | Gap 2 | Low (Chutes) | Chutes |
| 5 | Independent measurement reproduction | Trust assumption 3 | High (teep) | Teep |

---

## References

- **Chutes Security/Integrity documentation:** https://chutes.ai/docs/core-concepts/security-architecture
- **Model weight analysis:** [model_weights.md](model_weights.md)
- **Sek8s host-tools README:** `chutesai/sek8s/host-tools/README.md`
- **Cosign admission controller:** `chutesai/sek8s/sek8s/validators/cosign.py`
- **Intel TDX module GitHub repository:** source for MRSEAM allowlist values

---

## Teep Status

**Hardware measurement enforcement:** Partially enforced by default. MRTD and MRSEAM are pinned in `internal/provider/chutes/policy.go` and enforced fail-closed via `tdx_mrseam_mrtd`. RTMR0, RTMR1, and RTMR2 are also pinned and registered in Teep defaults, but their corresponding checks (`tdx_hardware_config` / `tdx_boot_config`) are allow-fail by default for Chutes. REPORTDATA binding is enforced via `ReportDataVerifier` in `internal/provider/chutes/reportdata.go`.

**Supply chain factors:** Correctly return `Skip` for `build_transparency_log`, `compose_binding`, `sigstore_verification`, and `event_log_integrity` because the sek8s architecture does not expose the required evidence to clients.

**Model weights:** Returns `Fail` for `measured_model_weights`. This is the correct behavior — neither Chutes weight verification mechanism exposes verifiable data to clients.

**Pending:** If Chutes enriches the evidence API with IMA manifests, container image digests, or model identity metadata, teep should implement verification for each new evidence type and update the corresponding factor results.

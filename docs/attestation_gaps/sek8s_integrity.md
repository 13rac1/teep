# Sek8s Integrity Chain — Chutes Provider

Chutes does not use dstack. It runs a custom Kubernetes distribution called **sek8s** inside Intel TDX confidential VMs. The attestation model is fundamentally different from dstack: instead of binding a Docker Compose hash into `MRCONFIGID`, Chutes LUKS-encrypts the guest root filesystem and gates disk decryption on full measurement verification by the Chutes validator (`chutes-api`). Container images are then verified by a cosign admission controller running inside the already-measured TEE.

This document describes what teep can independently verify, what it must trust Chutes to implement correctly, and the residual risks of that trust.

## TDX Register Usage in Sek8s

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
| **REPORTDATA** | Nonce + key binding | Two different formats for server-side and client-side attestation (see below) |

Measurement computation uses Intel's `tdx-measure` tool with boot artifacts extracted during the sek8s build process. Golden values are maintained in a Kubernetes ConfigMap (`tee_measurements.yaml`) loaded by `chutes-api`.

## What Teep Can Independently Verify

Teep receives a standard Intel TDX quote from the Chutes evidence API. The quote contains the same hardware-signed measurements as any other TDX provider. Teep can enforce:

### MRSEAM — Intel TDX module identity

The Intel TDX module MRSEAM values are **platform constants**, identical across all TDX providers. Teep already maintains an allowlist of known TDX module versions (`DstackMRSEAMAllow` in `dstack_defaults.go`) sourced from the Intel TDX module GitHub repository. These apply directly to Chutes without modification.

**Status:** Enforceable today with TOML config or Go-coded defaults.

### MRTD — Virtual firmware image

Sek8s uses its own OVMF build, distinct from dstack. The MRTD value is deterministic per sek8s firmware version and can be pinned once golden values are obtained. Teep can enforce MRTD via `mrtd_allow` in the provider's TOML policy section.

**Status:** Enforceable via `--update-config` once a known-good sek8s quote is captured.

### RTMR0 — Hardware and boot policy configuration

Sek8s explicitly fixes VM parameters (memory, vCPU count, GPU MMIO regions, PCI hole sizing) to make RTMR0 deterministic within a deployment class. This is documented in `chutesai/sek8s/host-tools/README.md`. Teep can pin RTMR0 values per deployment class via the `rtmr0_allow` policy.

**Status:** Enforceable via `--update-config` once values for each deployment class are captured.

### RTMR1 and RTMR2 — Kernel and command line

RTMR1 (kernel + initramfs) and RTMR2 (kernel command line) are deterministic per sek8s image build and deployment class. Teep can pin these via `rtmr1_allow` and `rtmr2_allow` TOML policy lists, populated via `--update-config`.

**Status:** Enforceable via `--update-config`. Values will change when Chutes updates the sek8s image.

### REPORTDATA binding

The client-facing REPORTDATA format is:

```
REPORTDATA[0:32] = SHA256(nonce_hex + e2e_pubkey_base64)
```

Teep already verifies this binding (`ReportDataVerifier` in `internal/provider/chutes/reportdata.go`) using the client-generated nonce and the ML-KEM-768 public key from the instances endpoint. This is a constant-time comparison.

**Status:** Enforced.

### Other enforced factors

- **`tdx_debug_disabled`** — debug attribute bit check
- **`intel_pcs_collateral`** — DCAP certificate chain and collateral verification
- **`tdx_tcb_current`** — TCB level freshness

## What Teep Cannot Independently Verify

### Container image identity

Chutes verifies container images using a **cosign admission controller running inside the TEE** (`chutesai/sek8s/sek8s/validators/cosign.py`). This is a Kubernetes admission webhook that calls `cosign verify` on every container image before allowing pod scheduling. The Chutes build system (`forge`) signs all images during the build process.

The attestation evidence returned to clients does **not** include container image digests, cosign signatures, or any supply chain metadata. Teep cannot independently verify which container images are running.

This is why teep correctly returns `Skip` for these chutes factors:

- **`build_transparency_log`**: "chutes attestation does not include container image metadata; supply chain verification is validator-side only"
- **`compose_binding`**: "chutes uses cosign image admission + IMA, not docker-compose; compose binding not applicable"
- **`sigstore_verification`**: "chutes attestation does not include container image digests; cosign verification is validator-side only"
- **`event_log_integrity`**: "chutes performs RTMR verification validator-side against a golden baseline; event log not exposed to clients"

### LUKS boot gate

Chutes gates disk decryption on measurement verification: the `chutes-api` validator only releases the LUKS decryption key after verifying MRTD + all RTMRs against the golden `TeeMeasurementConfig`. If measurements fail, the VM cannot decrypt its root filesystem and cannot boot.

This is a strong server-side control, but teep has no way to independently verify that the LUKS gate was applied or that the decryption key was withheld for a non-matching VM.

### Runtime attestation (RTMR3)

Chutes performs runtime re-attestation using RTMR3 and IMA measurements, verified server-side by `chutes-api`. The event log and runtime measurements are not exposed in the client-facing evidence API. Teep cannot replay or verify RTMR3.

### GPU-to-measurement binding

Chutes' `TeeMeasurementConfig` includes `expected_gpus` and `gpu_count` fields, allowing the validator to reject a VM whose GPU inventory does not match the expected deployment class. Teep verifies GPU evidence independently via NVIDIA EAT tokens, but cannot verify that the Chutes validator applied the GPU-to-measurement binding correctly.

## Trust Model

The sek8s attestation model requires trusting Chutes to correctly implement several security controls that teep cannot independently verify. The residual trust assumptions are:

### 1. Cosign admission controller is deployed and enforcing

Teep trusts that the cosign admission webhook is correctly configured, that it runs inside every sek8s TEE VM, and that it rejects unsigned or incorrectly signed images. A compromise of the cosign signing key, a misconfigured admission controller, or a bypass of the webhook would allow unauthorized container images to run inside an otherwise-valid TEE.

Unlike dstack providers where teep can inspect compose-listed image digests and check Sigstore/Rekor provenance, teep has **zero visibility** into which containers are actually running on a Chutes sek8s node.

### 2. LUKS gating is correctly implemented

Teep trusts that `chutes-api` withholds the LUKS key for VMs whose measurements do not match the golden config. If the LUKS passphrase leaked, or if a code path in `chutes-api` released the key without full measurement verification, a VM with a substituted lower stack could boot and serve traffic.

### 3. Golden measurements are correct and current

Teep trusts that the values in Chutes' `tee_measurements.yaml` ConfigMap accurately reflect the intended sek8s image. If the ConfigMap contained a malicious measurement set, or if it fell out of sync with production images, the LUKS gate and measurement verification would pass for the wrong image.

When teep pins MRTD and RTMR values via `--update-config`, it is recording values observed from a live Chutes deployment. Those values are only trustworthy if the deployment was running the correct sek8s image at capture time.

### 4. Runtime attestation is enforced

RTMR3/IMA verification is entirely server-side. Teep trusts that Chutes re-attests running VMs and revokes access when runtime measurements diverge.

## Comparison with Dstack

| Property | Dstack | Sek8s (Chutes) |
|----------|--------|----------------|
| Firmware identity | MRTD (OVMF, shared across dstack providers) | MRTD (sek8s OVMF, distinct from dstack) |
| App-layer binding | `MRCONFIGID` = `0x01 \|\| SHA256(compose)` | Not used; cosign admission inside TEE |
| Container image verification | Teep inspects compose image digests + Sigstore/Rekor | Validator-side only; not visible to teep |
| Event log | Exposed; teep replays RTMR3 | Not exposed to clients |
| Boot gating | None; host launches VM regardless | LUKS key withheld until measurements verified |
| Supply chain visibility | Full (compose + image digests + Rekor) | None (trust the cosign admission controller) |

The trade-off is clear: dstack gives teep **more independent verification surface** (compose binding, image digests, event log replay), while sek8s gives the **validator stronger boot-time enforcement** (LUKS gating prevents non-compliant VMs from starting) at the cost of requiring trust in the validator's implementation.

## Recommended Actions

### Short-term: Pin observed measurements

Use `--update-config` to capture MRTD, RTMR0, RTMR1, and RTMR2 from a known-good Chutes deployment. Add MRSEAM from the existing Intel allowlist. This lets teep reject quotes from VMs running unexpected firmware, kernels, or boot configurations.

Add Go-coded defaults for Chutes once stable sek8s measurement values are confirmed, similar to the existing `DstackBaseMeasurementPolicy()` and per-provider `DefaultMeasurementPolicy()` functions used by venice, nearcloud, and neardirect.

### Medium-term: Request evidence API enrichment

Ask Chutes to include in their evidence API response:

1. The `TeeMeasurementConfig` version string that matched the boot attestation, so teep can correlate the quote to a declared deployment class
2. Container image digests for running workloads, so teep can apply independent supply chain checks
3. IMA measurement log or RTMR3 event log, so teep can perform runtime replay

### Long-term: Independent measurement reproduction

Reproduce sek8s golden measurements independently by:

1. Building sek8s from source (`chutesai/sek8s`)
2. Computing MRTD using `tdx-measure` with the sek8s OVMF binary
3. Computing RTMR0-2 for each deployment class using the documented VM parameters
4. Comparing against observed values captured via `--update-config`

This would eliminate the trust assumption in item 3 (golden measurement correctness).

# Plan: PrivateMode Provider Support for Teep

## TL;DR

Implement a first-class `privatemode` provider in Teep with direct attestation verification and direct E2EE handling, while extending Teep endpoint coverage to include `POST /v1/completions` and `POST /v1/messages` in addition to current routed endpoints.

This plan is intentionally implementation-complete for an independent code agent. It defines trust chains, protocol contracts, factor policy, endpoint encryption behavior, phase-by-phase file changes, tests, and release gates.

This plan uses only public documentation as normative input and does not require private source or prior conversation context.

## Architecture Decision

Use direct provider integration in Teep rather than routing through the vendor proxy. Teep performs:

1. Coordinator and manifest verification in the client trust domain.
1. Mesh trust anchor validation before key upload/exchange.
1. Request/response E2EE operations inside Teep.
1. Fail-closed enforcement on any trust or crypto failure.

No plaintext fallback is allowed when E2EE is configured for a request path.

## Scope

### In Scope

1. New provider `privatemode` for direct attestation and E2EE.
1. Teep route support for `POST /v1/completions` and `POST /v1/messages`.
1. Endpoint-aware encryption/decryption behavior for all supported APIs.
1. Verification factor definitions and default enforcement profile.
1. Unit tests, fixture integration tests, and live API-key integration tests.

### Out of Scope

1. Compatibility fallback to an external vendor proxy.
1. Silent downgrade to plaintext.
1. Security weakening beyond existing Teep `allow_fail` and `offline` controls.

## Public References (Normative)

1. https://docs.privatemode.ai/architecture/overview/
1. https://docs.privatemode.ai/architecture/client-side/
1. https://docs.privatemode.ai/architecture/attestation/overview/
1. https://docs.privatemode.ai/architecture/attestation/contrast-integration/
1. https://docs.privatemode.ai/architecture/encryption/
1. https://docs.privatemode.ai/api/overview/
1. https://docs.privatemode.ai/api/chat-completions/
1. https://docs.privatemode.ai/api/legacy-completions/
1. https://docs.privatemode.ai/api/messages/
1. https://docs.privatemode.ai/api/embeddings/
1. https://docs.privatemode.ai/api/speech-to-text/
1. https://docs.privatemode.ai/api/models/
1. https://docs.privatemode.ai/api/proxy-configuration/
1. RFC 5869 (HKDF)
1. RFC 5116 (AEAD requirements)

## Provider Characteristics

| Property | Planned Value |
|---|---|
| Provider Name | `privatemode` |
| API Key Env | `PRIVATEMODE_API_KEY` |
| Base URL | Configurable; default to public API base |
| Attestation Root | Contrast Coordinator trust chain + manifest match |
| E2EE Primitive | AES-GCM for prompt/response protection (per public docs) |
| Key Exchange | Hybrid key establishment flow, bound to attestation result |
| Trust Anchors | Coordinator attestation identity and mesh CA |
| Connection Model | Standard TLS plus application-level E2EE and attestation gating |
| PinnedHandler | Not required initially |
| Supply Chain Evidence | Manifest-based Contrast model (no Sigstore requirement in public docs) |
| Backend Trust | Transitive through Coordinator policy/attestation path |

## Authentication Chain Analysis

### Chain 1: Coordinator Identity and Manifest Integrity

Goal: prove Teep is communicating with the expected Coordinator and that Coordinator-enforced manifest equals expected manifest.

1. Teep fetches expected manifest from configured source.
1. Teep establishes Coordinator session and verifies Coordinator identity through remote attestation flow.
1. Teep retrieves Coordinator-enforced manifest identity.
1. Teep compares expected and enforced manifest identity with constant-time equality.
1. Any mismatch fails closed.

What this chain proves:

1. The central attestation authority is verified before key operations.
1. Manifest policy drift is detected by the client.

What this chain does not prove alone:

1. Per-request backend freshness unless combined with session policy and re-attestation triggers.

### Chain 2: Mesh CA and Secret-Exchange Key Binding

Goal: prove Teep uploads or exchanges encryption material only with the expected secret-service identity.

1. After Coordinator verification, Teep obtains mesh CA trust anchor.
1. Teep performs secret exchange and receives `mesh_cert`, `signature`, and `encapsulated_key`.
1. Teep verifies `mesh_cert` chains to the attested `mesh_ca`.
1. Teep verifies `signature` over `SHA256(request_public_key || encapsulated_key)` with the ECDSA public key in `mesh_cert`.
1. Teep derives the shared secret only after signature and cert-chain checks pass.

What this chain proves:

1. Key path is bound to Coordinator-verified mesh trust.
1. A signer holding the private key corresponding to a mesh-CA-issued certificate participated in the key exchange transcript.

What this chain does not prove alone:

1. That a particular worker instance consumed a key, unless tied to worker attestation outcomes.

### Chain 3: Worker Trust Through Coordinator Policy (Partially Verified — Transitive)

Goal: ensure key release and inference forwarding occur only after worker attestation/policy acceptance.

1. The Contrast Coordinator validates each worker pod's AMD SEV-SNP attestation report against the reference values encoded in the manifest before issuing a mesh CA certificate to that worker.
1. Key release to admitted workers depends on the Coordinator accepting the worker's attestation.
1. Teep treats Coordinator acceptance — evidenced by the manifest binding in the Coordinator's own attestation — as the gating signal for encrypted inference.

#### How Worker Admission Works Internally

Each worker container runs inside an AMD SEV-SNP confidential VM. At launch the worker generates a SEV-SNP attestation report containing:

| Field | Byte size | Meaning in Contrast admission |
|---|---|---|
| `measurement` | 96 | HMAC-SHA-384 over the guest's initial memory image (firmware, kernel, initrd, guest data). Covers the workload container image and its launch configuration. |
| `host_data` | 32 | Set to a policy hash derived from the active Contrast manifest (`Policies` map key). Proves the workload was launched under a manifest-authorized policy entry. |
| `report_data` | 64 | Caller-controlled binding field; Contrast uses this to bind ephemeral keys. |
| `guest_svn` | 4 | Guest security version; must meet the manifest's minimum threshold. |
| `policy` | 8 | Guest policy flags (debug disable, migration disable, SMT settings). Must match policy fields in manifest reference values. |
| Signature | variable | ECDSA P-384 signature over all fields, signed by the chip's VCEK derived via AMD ARK → AMD ASK → VCEK. |

The Coordinator verifies each worker's SEV-SNP report against the manifest's reference values for that pod class:
- `measurement` must match the manifest's `expectedMeasurement` for the relevant container image.
- `host_data` must equal the expected policy hash derived from the active manifest — this proves the worker matches a manifest-authorized policy entry.
- `policy` flags must satisfy the manifest's `guestPolicy` constraints.
- VCEK chain validates to the AMD hardware root.

If all checks pass, the Coordinator issues the worker a mesh CA certificate (signed by the mesh CA private key held inside the Coordinator's own TEE). This certificate is the worker's credential for TLS connections within the deployment, including access to key material from the secret service.

#### What Teep Sees

Teep receives only the **Coordinator's** SEV-SNP attestation report. The Coordinator's `host_data` field is set to the Coordinator policy hash from the active manifest, which Teep can verify via Contrast validators. The Coordinator's `measurement` covers the Coordinator container image.

Teep does **not** receive individual worker SEV-SNP reports. The worker admission protocol is entirely internal between the Contrast node agent and the Coordinator's gRPC API (`/contrast.userapi.UserAPI/SetManifest`, `/contrast.userapi.UserAPI/GetManifest`). No worker quote is forwarded to or verifiable by the Teep client.

#### Contrast SDK Verification Transcript

1. Teep sends `POST /privatemode/v1/attest` with a 32-byte nonce.
1. The endpoint returns `AttestationDoc` (opaque attestation transcript bytes).
1. Validation logic extracts attested coordinator state (including `manifests[]`, `root_ca`, and `mesh_ca`) from `AttestationDoc`.
1. `ValidateAttestation()` in Contrast SDK validates the latest manifest and builds SNP/TDX validators from that manifest.
1. The SDK computes expected `REPORT_DATA` using:

$$
\mathrm{reportdata32} = \mathrm{SHA256}(\mathrm{nonce} \parallel \mathrm{transitionDigest} \parallel \mathrm{SHA256}(\mathrm{rootCA}) \parallel \mathrm{SHA256}(\mathrm{meshCA}))
$$

then zero-pads to 64 bytes for SNP/TDX report-data comparison:

$$
\mathrm{reportdata64} = \mathrm{reportdata32} \parallel 0^{256}
$$

1. Each validator checks attestation signature/cert chain and verifies that attested report-data equals `reportdata64`.

This gives a strong binding between nonce freshness, manifest-history transition state, and deployment CA material.

Important boundary: this report-data construction does **not** include per-worker quote digests, GPU attestation evidence hashes, or host TPM/vTPM quotes. Those remain out of Teep's direct verification surface.

#### What This Chain Proves

1. The Coordinator is a genuine SEV-SNP TEE with a known-good measurement.
1. The Coordinator was launched under a specific manifest-authorized policy entry (proven by `host_data = CoordinatorPolicyHash(manifest)`).
1. The manifest contains reference values that govern which worker measurements are admitted.
1. The secret-exchange signer key is certified by the mesh CA, which is controlled by the attested Coordinator.

#### What This Chain Does Not Prove Directly to Teep

1. **Worker measurement registers are not exposed.** The actual SEV-SNP `measurement` field for inference worker pods is consumed by the Coordinator and never forwarded to the Teep client. Teep cannot verify directly which container image hash, kernel, or firmware the inference workers are running.
1. **Expected-manifest bootstrap trust.** Attestation authenticates the manifest bytes returned by the Coordinator, but does not by itself authenticate which manifest Teep *should* expect. If Teep's expected manifest is sourced from an untrusted channel, policy identity can be accepted without an authenticated operator intent anchor.
1. **Post-admission worker state is not re-verified.** Once admitted, a worker holds a mesh CA certificate valid for its certificate lifetime. Teep cannot verify per-request that the specific worker handling inference is still running the attested workload.
1. **Model weight dm-verity roots are inside the manifest.** The manifest specifies expected dm-verity root hashes for model weight disks. Teep's verification of the manifest hash is one step removed from verifying model weight integrity: `manifest hash → manifest content → dm-verity roots → model files`.

### Chain 4: Prompt/Response Confidentiality and Integrity

Goal: guarantee application-level confidentiality and authenticity of prompt/response data.

1. Teep derives session keys only after chains 1 and 2 pass.
1. Teep encrypts sensitive request fields before forwarding.
1. Teep verifies response authenticity during decryption.
1. Teep rejects malformed ciphertext, missing required crypto metadata, nonce/sequence violations, and authentication failures.

What this chain proves:

1. Data remains protected outside verified endpoints.
1. Tampered encrypted payloads fail closed.

## Security Architecture and Attestation Gap Analysis

This section documents the structural attestation gaps in the PrivateMode Contrast architecture and the residual trust assumptions that cannot be eliminated without changes to the PrivateMode protocol. Teep's implementation is designed around these constraints; the `PrivatemodeDefaultAllowFail` profile in the factor design section reflects them directly.

### Architecture Overview

PrivateMode uses the [Contrast](https://github.com/edgelesssys/contrast) framework from Edgeless Systems to establish a confidential Kubernetes deployment on AMD SEV-SNP hardware. The trust architecture differs substantially from dstack-based providers (NearCloud, NearDirect, Chutes) and from the transitive-Nitro model used by MapleAI.

```
Teep Client
  │
  │  (1) TLS to coordinator.privatemode.ai
  │      Verify Coordinator SEV-SNP attestation
  │      Verify Coordinator host_data == CoordinatorPolicyHash(latest manifest)
  ▼
Contrast Coordinator (AMD SEV-SNP TEE)
  │  Holds: mesh CA keypair, manifest, worker admission policy
  │
  │  (2) Secret exchange with mesh certificate proof
  │      Verify mesh_cert chain to attested mesh CA
  │      Verify signature over (request_public_key || encapsulated_key)
  ▼
PrivateMode Secret Service (admitted worker pod, AMD SEV-SNP TEE)
  │  Holds: E2EE key material, tied to attested session
  │  Worker's SEV-SNP quote verified by Coordinator at admission time
  │  Worker's mesh CA cert issued by Coordinator after admission
  │
  │  (3) Internal Kubernetes mesh (mTLS)
  ▼
PrivateMode Inference Workers (admitted worker pods, AMD SEV-SNP TEEs)
  │  Worker measurements (measurement, host_data, policy) verified by Coordinator
  │  dm-verity root hashes for model weights verified against manifest reference values
  │  Raw worker SEV-SNP quotes NOT forwarded to Teep client
  ▼
(inference result → secret service → E2EE response → Teep client)
```

Teep's verification surface ends at **step (2)**: the Coordinator's attestation and the secret service's mesh-CA-bound TLS identity. Everything to the right of the Coordinator is enforced internally by the Contrast framework and is not externally observable from the Teep client perspective.

### AMD SEV-SNP Attestation Report Field Reference

The following table documents the SEV-SNP attestation report fields relevant to PrivateMode's Contrast integration. All fields are covered by an ECDSA P-384 signature using the chip's VCEK (Versioned Chip Endorsement Key), verified via the AMD certificate chain `AMD ARK → AMD ASK → VCEK`.

| Field | Size | Role in Contrast | Verifiable by Teep? |
|---|---|---|---|
| `measurement` | 96 bytes | HMAC-SHA-384 over initial guest memory image. Covers firmware, kernel, initrd, and guest data pages loaded at VM launch. Each container image produces a deterministic measurement. | Yes — for the Coordinator's measurement. Worker measurements: No. |
| `host_data` | 32 bytes | Set to a policy hash key derived from the active manifest (`Policies` map). Binds the launched TEE to a manifest-authorized policy identity. | Yes — Teep verifies Coordinator `host_data == CoordinatorPolicyHash(latest manifest)`. |
| `report_data` | 64 bytes | Caller-bound field. In this flow it binds client nonce, transition state, and CA material into the quote transcript. | Yes — enforced as `tee_reportdata_binding` + `nonce_match`. |
| `guest_svn` | 4 bytes | Guest security version number. Must meet manifest minimum. | Yes — feeds `tee_tcb_current` factor. |
| `policy` | 8 bytes | Guest policy flags: debug disable, migration disable, SMT settings, minimum platform version. | Yes — feeds `tee_hardware_config` factor. |
| `current_tcb` | 8 bytes | Platform TCB version: boot loader, TEE, SNP firmware, microcode SVN. Checked against AMD KDS minimum. | Partially — requires AMD KDS network call; allow-fail under `--offline`. |
| `platform_info` | 8 bytes | SMT enabled, TSME enabled flags. | Yes — within `tee_hardware_config`. |
| VCEK signature | variable | ECDSA P-384 over all fields. VCEK derived from chip and TCB version via AMD KDS. | Yes — `tee_cert_chain` verifies AMD ARK→ASK→VCEK→quote signature. |

### Contrast Coordinator `/attest` Transcript Semantics (Internal)

This section describes Contrast attestation transcript semantics represented inside `AttestationDoc`.
It is not a second public HTTP API contract; Teep calls the public endpoint `POST /privatemode/v1/attest` defined in the protocol contract section below.

The internal coordinator attestation flow represented by `AttestationDoc` uses this sequence:

1. Enforce `Content-Type: application/json` and nonce length exactly 32 bytes.
1. Read latest Coordinator state and manifest history from state guard.
1. Build `CoordinatorState` with manifests, root CA, and mesh CA.
1. Compute `report_data` via `ConstructReportData(nonce, transitionHash, coordinatorState)`.
1. Issue raw SNP/TDX attestation with that `report_data`.
1. Return attestation transcript bytes that encode coordinator state including attestation evidence, manifest history, `root_ca`, and `mesh_ca`.

This confirms that the attestation document returned to Teep is cryptographically tied to the Coordinator's current transition hash and CA material, not only to a static coordinator measurement.

### Contrast Manifest Structure

The Contrast manifest is a JSON policy document that defines the expected state of every container in the deployment. It is the central binding artifact: the Coordinator and workers bind `host_data` to manifest-derived policy hashes, and the attestation response carries the manifest history needed to validate those bindings.

Relevant manifest fields (from public Contrast documentation and `edgelesssys/contrast` source):

| Manifest field | Content | Security purpose |
|---|---|---|
| `referenceValues[].snp.measurement` | 96-byte hex, per pod class | Expected `measurement` field for each worker type. A worker pod is admitted only if its live `measurement` matches this value. |
| `referenceValues[].snp.hostData` | 32 bytes | Expected `host_data` policy hash for workload classes, keyed by manifest policy entries. |
| `referenceValues[].snp.guestPolicy` | policy bitmap | Required `policy` flags (debug must be disabled, etc.). |
| `referenceValues[].snp.minimumTCB` | SVN fields | Minimum platform TCB. |
| `referenceValues[].productName` | string | AMD SEV-SNP product class (e.g., `Milan`). |
| `devices` / `volumes` | dm-verity root hashes | Expected dm-verity root hash for each mounted volume, including model weight disks. |
| `images` | SHA256 digests | OCI container image digests for each pod class. Pinned at manifest creation time. |
| `policy` (Rego) | OPA policy document | Defines allowed inter-pod communication, port access, and admission rules. |

When Teep verifies `manifest_policy_match` (Coordinator `host_data == CoordinatorPolicyHash(latest manifest)` plus latest-manifest byte equality against expected content), it is indirectly asserting all of the above — including model weight dm-verity roots and container image digests — but without seeing or independently computing any of those values.

### Gap 1: Worker Attestation Not Independently Verifiable (Primary Gap)

Teep receives and verifies only the **Coordinator's** SEV-SNP attestation. Worker pod attestation reports are exchanged internally via the Contrast node agent gRPC API and are never forwarded to the external client.

**What Teep cannot verify:**
- The `measurement` field for the secret service pod, inference worker pods, and init containers.
- The `policy` flags (debug disable, migration disable) for any worker pod.
- The `current_tcb` for worker pods (TCB SVN for the CPU running inference).
- Whether a specific worker certificate has been revoked or has expired since admission.

**Cryptographic consequence:** Teep's verification proves a valid Contrast Coordinator is enforcing an expected manifest. It does not prove that any specific inference worker passes that manifest's admission criteria at the time Teep's request is served. A worker admitted at time T may have been rescheduled, restarted, or patched between T and the time the inference request is processed, and Teep has no mechanism to detect this.

**Analogous gap in other providers:**
- MapleAI (Chain 3): The OpenSecret Nitro enclave verifies PrivateMode backend attestation internally but does not forward backend SEV-SNP quotes to the Teep client. The teep client cannot independently verify backend attestation — it can only verify PCR0 and trust that the measured code does what the source says.
- Chutes (sek8s): Chutes verifies container images using a cosign admission controller inside the TEE, but does not expose container image digests or supply chain metadata to clients.

**Impact on factors:**

| Factor | Status | Reason |
|---|---|---|
| Worker `tee_boot_config` | Not reported | Worker RTMR1/RTMR2 or SEV-SNP measurement registers not forwarded to client |
| Worker `tee_hardware_config` | Not reported | Worker guest policy and platform info not forwarded |
| Worker `tee_tcb_current` | Not reported | Worker TCB SVN not forwarded |
| Coordinator `tee_boot_config` | Reported; allow-fail initial | Coordinator measurement in `tee_mrseam_mrtd`; RTMR analogues allow-fail until allowlists populated |
| Coordinator `tee_hardware_config` | Reported; allow-fail initial | Coordinator policy flags; allow-fail until fleet values confirmed |

### Gap 2: Expected-Manifest Authenticity Bootstrap

The cryptographic binding in the attestation flow is:

1. Coordinator includes `manifests[]`, `root_ca`, `mesh_ca` in `/attest` response.
1. Coordinator computes `report_data = SHA256(nonce || transitionDigest || SHA256(root_ca) || SHA256(mesh_ca)) || 32 zero bytes`.
1. Verifier recomputes `transitionDigest` from the returned `manifests[]` chain and validates quote report-data equality.

This means the returned manifest bytes are authenticated by the attestation transcript. A network attacker cannot swap `manifests[]` without breaking report-data verification.

**Where the gap actually is:** the protocol does not provide an authenticated statement of the *operator-intended* manifest identity (for example a vendor signing key assertion delivered in the `/attest` transcript). Therefore, the verifier must obtain expected manifest identity out-of-band.

**Cryptographic consequence:** if Teep accepts whatever manifest arrives from a mutable external source as "expected", `manifest_policy_match` can degrade to proving only self-consistency (`host_data` matches that same manifest) instead of proving membership in a pre-authorized manifest set.

**Current handling status:**

1. Contrast SDK correctly validates quote signature/cert chain and report-data binding to returned `manifests[]`, `root_ca`, and `mesh_ca`.
1. Contrast SDK explicitly does **not** verify that returned manifest bytes equal caller-expected policy; caller must enforce this check.
1. Privatemode client logic compares attested manifest bytes against caller-provided expected manifest and fails closed on mismatch.

**Mitigation in Teep implementation:**

1. Require `privatemode_manifest_hash = "<hex>"` for enforced production profiles.
1. Verify `SHA256(attested_manifest_bytes) == configured_hash` with constant-time compare.
1. When hash pinning is absent, classify `manifest_policy_match` as policy-weak mode and emit a high-signal warning that expected-manifest authenticity is not anchored.

**Analogous gap in other providers:**
- Dstack (in-band discovery gap): dstack providers do not publish expected RTMR measurement values through an authenticated channel. Operators must source them out-of-band.
- MapleAI: The PCR0 reference value must be obtained from the OpenSecret `pcrProdHistory.json` file, which is not published to a transparency log.

**Impact on factors:**

| Factor | Status | Reason |
|---|---|---|
| `manifest_policy_match` | Enforced; expected-manifest pinning required for high assurance | Fails closed if Coordinator `host_data` != `CoordinatorPolicyHash(manifest)`, or if `SHA256(attested_manifest)` != configured expected hash when pinning is enabled. |

### Gap 3: E2EE Key Binding Is to the Secret Service, Not to Inference Workers

Teep establishes an E2EE session with the **secret service** pod. The secret service holds the symmetric key material and grants access to admitted worker pods on the internal mesh. Inference workers receive decrypted request data on the internal mTLS path (not through the Teep client).

**Cryptographic consequence:** Teep's `tls_key_binding` factor proves that the key-exchange signer holds the private key corresponding to a certificate chained to the Coordinator-attested mesh CA. But the mesh CA can certify multiple admitted pods, so Teep cannot verify that the specific worker pod that processed the inference request (a) was the intended worker class, (b) is still running the attested image, or (c) did not receive request data outside the attested path.

The E2EE chain looks like:
```
Teep encrypts request with AES-256-GCM session key
  → key exchange authenticated by mesh_cert + ECDSA signature
  → secret service decrypts → plaintext JSON on internal mesh
  → internal mTLS to inference worker (worker's mesh CA cert)
  → inference worker receives plaintext
```

The internal segment (secret service → inference worker) is encrypted via mTLS but the plaintext is accessible to any pod in the mesh that holds a valid mesh CA certificate. Teep cannot independently verify which workers hold mesh CA certificates at any given time.

PrivateMode's API does **not** mirror NearCloud-style broad plaintext field exposure. Public behavior and docs indicate only a small metadata subset remains plaintext for routing/billing (for example `model`, `stream`, `id`, `usage`), while content-bearing fields (`messages`, `choices`, and analogous payload fields) are encrypted blobs. This reduces exposed plaintext on the external hop. The residual gap here is architectural placement of decryption at secret-service / mesh level, not selector omission.

**This is not a protocol defect** — it is a consequence of PrivateMode's Coordinator-centric trust model in which worker identity is established by the Coordinator, not by the external client. The model is sound if the Coordinator correctly enforces admission. Teep documents this dependency as a structural gap.

**Impact on factors:**

| Factor | Status | Reason |
|---|---|---|
| `e2ee_capable` | Enforced | Proves key exchange with mesh CA-bound secret service |
| `e2ee_usable` | Enforced | Proves AES-GCM round-trip on live request |
| Inference worker key scope | Not verifiable | Plaintext is accessible to any admitted pod; not directly constrained by Teep's E2EE |

### Gap 4: Model Weight Verification Is Second-Order Transitive

Model weights are stored on dm-verity protected volumes mounted into inference worker pods. The dm-verity root hashes are specified in the Contrast manifest's `devices`/`volumes` fields.

The verification chain is:
```
Teep verifies:
  Coordinator.host_data == CoordinatorPolicyHash(manifest)
  → manifest.devices["model-weights"].rootHash == <expected dm-verity root>
  → dm-verity enforces at runtime: block reads fail if content does not match rootHash
  → model weights file integrity is protected
```

Teep never sees the dm-verity root hash directly. It is embedded in the manifest content. Teep's `manifest_policy_match` is one step removed from model weight verification: Teep proves the manifest hash, the manifest asserts the dm-verity roots, and dm-verity asserts model file integrity.

**Analogous gap in other providers:**
- MapleAI: `measured_model_weights` Fails (allow_fail) because dm-verity is used by the backend but not exposed to the client. The teep client can only infer model weight integrity transitively through PCR0 → Nitro EIF → sidecar proxy → Contrast SDK → dm-verity.

**Impact on factors:**

| Factor | Status | Reason |
|---|---|---|
| `measured_model_weights` | Allow-fail | Transitive through manifest → dm-verity. Direct dm-verity root hash not exposed to Teep client. |

### Gap 5: No Sigstore/Rekor Transparency for Contrast or PrivateMode Container Images

Contrast and PrivateMode do not publish Sigstore/cosign signatures or Rekor transparency log entries for:
- The Contrast Coordinator container image
- PrivateMode worker container images
- The `edgelesssys/privatemode-public` binary artifacts

Unlike dstack providers where container image digests can be cross-referenced with Sigstore/Rekor provenance chains, the PrivateMode supply chain is verified only through the Contrast manifest (which pins SHA256 OCI image digests) and CDN distribution of that manifest.

**Consequence:** An operator who pins the manifest hash in `teep.toml` is asserting trust in whatever images are pinned in that manifest. There is no independent third-party log that records when those image digests were published and by whom. A compromised manifest distribution (CDN or GitHub release) would not be detected through a transparency log.

**Mitigation available:** The Contrast framework itself supports reproducible container image builds. An auditor can reproduce the Coordinator and worker images from source and verify their SHA256 digests against the manifest's `images` field. This is auditable but not automated in the Teep implementation.

**Analogous gap in other providers:**
- MapleAI: `continuum-proxy` binary is pre-compiled and checked into the git repo without automated CI verification that it matches the submodule source. No Sigstore entries for the OpenSecret organization.
- Chutes: No container image metadata exposed to clients; cosign admission is validator-side only.

**Impact on factors:**

| Factor | Status | Reason |
|---|---|---|
| `cpu_gpu_chain` | Allow-fail | GPU-CPU binding not externally observable via PrivateMode public API |
| `nvidia_payload_present` | Allow-fail | NVIDIA attestation not exposed |
| `nvidia_claims` | Allow-fail | NVIDIA attestation not exposed |
| `nvidia_nras_verified` | Allow-fail | NVIDIA attestation not exposed |

### Gap 6: No TPM/vTPM Cross-Certification in Current Contrast Chain

The PrivateMode verification chain is based on:

1. SNP/TDX attestation validators derived from manifest reference values.
1. `host_data` binding to coordinator policy hash / manifest lineage.
1. `report_data` binding to nonce + transition digest + CA state.

Current public Contrast/Privatemode attestation documentation and protocol behavior do **not** expose TPM/vTPM cross-certification evidence to the external client, and do not describe a dual-attestation transcript with host TPM quote binding:

1. No host TPM quote verification in the attestation response path.
1. No vTPM PCR quote binding exposed to external clients.
1. No AK/EK certificate chain validation linked to Coordinator report-data.
1. No DCEA-style dual attestation transcript (TEE quote cross-bound to TPM quote).
1. No CCxTrust-style composite quote format exposed by Coordinator `/attest`.

Implication for factor model:

1. The current PrivateMode/Contrast flow strengthens Coordinator integrity and manifest policy binding, but does not close the hardware-level CPU identity and CPU↔GPU co-residency gaps described in `gpu_cpu_binding.md`.
1. `cpu_gpu_chain` remains allow-fail by default because Teep cannot independently verify CPU↔GPU same-host binding from `/attest` outputs.
1. If Contrast adds TPM/vTPM-backed dual-attestation evidence in future, Teep should introduce a generalized enforced factor such as `tee_platform_cross_certified` and a dependent binding factor such as `cpu_gpu_chain_bound`.

### Residual Trust Assumptions

After Teep's verifiable checks, the following security properties depend on trusting the PrivateMode and Contrast implementation:

1. **The Contrast Coordinator correctly enforces manifest admission policy.** Teep verifies the Coordinator's TEE attestation and manifest binding. It does not verify that the Coordinator's internal code (written in Go, open source in `edgelesssys/contrast`) correctly implements the admission checks described in the manifest. An auditor can verify this from source code; Teep cannot verify it per-request.

1. **Workers do not share key material with non-admitted pods.** The mesh CA certificate enforces mTLS within the deployment. Teep trusts that the Coordinator only issues mesh CA certificates to pods whose attestation passed. A vulnerability in the Coordinator's certificate issuance logic would be invisible to Teep.

1. **Expected-manifest identity is authentically configured.** Attestation authenticates the Coordinator-provided manifest bytes, but Teep must still authenticate which manifest identity is acceptable. High-assurance deployments must pin manifest hash (or equivalent authenticated policy) in Teep config.

1. **Worker TEE measurements match the manifest's `referenceValues`.** The admission was performed by the Coordinator at pod launch. Teep trusts this was done correctly and that the measurement values in the manifest were set from known-good images.

1. **The Coordinator is the sole issuer of mesh CA certificates.** If the Coordinator's mesh CA private key leaked (or if an alternative CA were trusted by workers), the mTLS binding that secures the internal inference path would be undermined.

### Comparison with Other Providers

| Property | PrivateMode (this plan) | MapleAI (Nitro+Contrast) | Chutes (sek8s) | NearDirect (dstack) |
|---|---|---|---|---|
| TEE platform | AMD SEV-SNP | AWS Nitro (outer) + SEV-SNP (backend) | Intel TDX | Intel TDX |
| Client sees backend quote | No — Coordinator only | No — PCR0 covers sidecar proxy code | No — cosign admission inside TEE | Yes — dstack quote with MRCONFIGID |
| Supply chain transparency | No Sigstore | No Sigstore (OpenSecret/MapleAI) | No (cosign validator-side only) | Yes — Sigstore + Rekor for images |
| Model weight verification | Transitive (manifest → dm-verity) | Transitive (PCR0 → proxy → dm-verity) | Not verifiable externally | Not applicable |
| Nonce freshness | Coordinator `report_data` binding | Nitro `nonce` in COSE_Sign1 | REPORTDATA SHA256(nonce+key) | REPORTDATA SHA256(nonce+key) |
| E2EE key bound to | Secret service (mesh CA) | Nitro enclave (PCR0 covers key code) | Instance (REPORTDATA) | Instance (REPORTDATA) |
| TLS channel binding | CA-delegation (mesh CA) | None (no TLS pinning) | None | SPKI pinned in REPORTDATA |

## Protocol Contract

This section defines an implementation-usable compatibility contract. It is intentionally explicit so implementation does not depend on vendor source checkout.

### Base URLs and Endpoint Families

1. Public API base default: `https://api.privatemode.ai`.
1. Attestation endpoint: `POST /privatemode/v1/attest`.
1. Secret exchange endpoint: `POST /privatemode/v1/secret`.
1. Inference endpoints:
  - OpenAI-compatible: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/audio/transcriptions`, `/v1/models`, `/v1/models/{model}`
  - Anthropic-compatible: `/v1/messages`
  - Provider-native unstructured API: `/unstructured/general/v0/general` (documented here for compatibility awareness; not in Teep routing scope for this plan revision)
1. Manifest default source: `https://cdn.confidential.cloud/privatemode/v2/manifest.json` (with operator pinning support described below).

### Required Request Headers

1. Send `Authorization: Bearer <api-key>` to attestation, secret exchange, and inference endpoints.
1. Send `Privatemode-Version: <teep-version-or-compat-version>`.
1. Send `Privatemode-Client: <client-id>` (recommended values include `SDK` or `Proxy`; Teep should use a stable client identifier).
1. Send `Privatemode-User-Request-ID: <opaque-id>` for request correlation.
1. For inference requests with encrypted fields, send `Privatemode-Secret-ID: <secret_id>` as a routing hint.
1. `Privatemode-NVIDIA-OCSP-Policy` and `Privatemode-NVIDIA-OCSP-Policy-MAC` are optional. If omitted, upstream OCSP verification defaults to allowing only `good` status.
1. Preserve content type by endpoint:
  - JSON endpoints use `application/json`.
  - Transcriptions use `multipart/form-data`.

### Attestation Wire Format

`POST /privatemode/v1/attest`

Request body (canonical key names):

```json
{
  "Nonce": "<base64(32 random bytes)>"
}
```

Response body shape (canonical key names; byte fields are base64-encoded in JSON):

```json
{
  "AttestationDoc": "<base64 bytes>"
}
```

`AttestationDoc` is an opaque attestation transcript blob. Manifests, transition state, root CA, and mesh CA are extracted from this blob by attestation verification logic; they are not top-level HTTP JSON fields in this endpoint contract.

Validation requirements:

1. Nonce must be exactly 32 bytes from `crypto/rand`.
1. Validate coordinator quote/cert chain from `AttestationDoc` against manifest-derived reference values.
1. Require at least one attested manifest in coordinator state after attestation validation.
1. Current deployments typically provide exactly one active manifest. If multiple manifests are returned, use the latest active one for policy comparison.
1. Compute expected report data as:

$$
H = \mathrm{SHA256}(nonce \parallel transitionDigest \parallel \mathrm{SHA256}(rootCA) \parallel \mathrm{SHA256}(meshCA))
$$

and compare against 64-byte `REPORT_DATA` as `H || 0^{256}`.

1. Enforce manifest pinning policy:
  - If `privatemode_manifest_hash` configured: require `SHA256(latest_manifest_bytes)` equals configured hash (constant-time compare).
  - If `privatemode_manifest_hash` not configured: allow CDN-fetched manifest mode but emit high-signal warning in verification details.

### Secret Exchange Wire Format

`POST /privatemode/v1/secret`

Request body (canonical key names):

```json
{
  "PublicKey": "<base64 HPKE ML-KEM-768+X25519 public key bytes>"
}
```

Response body (canonical key names):

```json
{
  "EncapsulatedKey": "<base64 bytes>",
  "Signature": "<base64 ASN.1 ECDSA signature bytes>",
  "MeshCert": "<base64 DER cert bytes>"
}
```

Verification and derivation requirements:

1. Parse `MeshCert` as X.509 DER and verify certificate chain to the attested `mesh_ca` trust anchor.
1. Require that `MeshCert` public key is ECDSA.
1. Compute transcript hash `T = SHA256(PublicKey || EncapsulatedKey)`.
1. Verify `Signature` using ECDSA ASN.1 verification over `T` with the public key from `MeshCert`.
1. Derive 32-byte shared secret via HPKE recipient flow using `ML-KEM-768+X25519` KEM, `HKDF-SHA256` KDF, and export-only mode (`Export("", 32)`).
1. Compute `secret_id = base64(SHA256(PublicKey))`.
1. Fail closed on any missing/empty/invalid field.

### Encrypted Field Envelope (Compatibility-Critical)

Encrypted JSON/form field values use this exact grammar:

```text
"<secret_id>:<request_nonce_hex>:<iv_hex>:<ciphertext_hex>"
```

Rules:

1. The outer quotes are part of the encoded JSON string value.
1. `request_nonce_hex` is 12 random bytes, shared across all encrypted fields in one request/response exchange.
1. `iv_hex` is a unique 12-byte IV per encrypted field.
1. AEAD is AES-GCM with additional authenticated data:

$$
AAD = requestNonce || LE32(sequenceNumber)
$$

1. Sequence numbers start at 0 and increment per encrypted field:
  - client request encryption: 0,1,2,...
  - server response encryption: 0,1,2,...
  - client response decryption expects matching server sequence.
1. Server-side decryptor must parse request nonce from the first encrypted request field, then use that nonce for all remaining request-field decryptions in the exchange.
1. Server-side decryptor must enforce a single `secret_id` across all encrypted fields in the request.
1. Response encryption must reuse the request `secret_id` and the request nonce from the first decrypted request field.

### Deterministic Field Mutation and Sequence Assignment

To remain wire-compatible, sequence-number assignment must be deterministic and match mutation traversal order.

1. JSON mutation order is lexicographic by top-level field name, then recursive lexicographic traversal for nested objects/arrays after skip-field expansion.
1. Multipart mutation order is lexicographic by form field name, then lexicographic by file field name.
1. Unknown JSON/form fields are encrypted by default unless explicitly listed in the endpoint plaintext selector.
1. For repeated multipart fields, current behavior mutates the first value per key; compatibility tests should include repeated-field inputs and enforce fail-closed handling for unsupported multiplicity patterns.

### Endpoint Field-Selection Contract

For compatibility, Teep must preserve plaintext/encrypted field splits below.

`/v1/chat/completions` and `/v1/completions`

1. Plain request fields: `model`, `stream_options`, `max_tokens`, `max_completion_tokens`, `n`, `stream`.
1. Encrypted request fields: all others (including `messages`, `prompt`, `tools`, `temperature`, and unknown extension fields).
1. Plain response fields: `id`, `usage`.
1. Encrypted response fields: all others (including `choices`).
1. Streaming `[DONE]` remains plaintext.

`/v1/messages`

1. Plain request fields: `model`, `stream`.
1. Encrypted request fields: all others (including `messages`, `system`, `tools`, `max_tokens`).
1. Plain response fields: `id`, `type`, `usage`.
1. Encrypted response fields: all others (including content blocks and deltas).

`/v1/embeddings`

1. Plain request fields: `model`.
1. Encrypted request fields: all others (including `input`, `dimensions`, `encoding_format`, `user`).
1. Plain response fields: `id`, `usage`.
1. Encrypted response fields: all others (including embedding vectors).

`/v1/audio/transcriptions` (multipart)

1. Plain form fields: `model`, `stream`, `stream_include_usage`, `stream_continuous_usage_stats`.
1. Encrypted form fields: `language`, `prompt`, `response_format`, `temperature`, and unknown fields.
1. `file` part content is encrypted before forwarding.
1. Plain response fields: `duration`, `usage`.
1. Encrypted response fields: all others (including `text`, `segments`).
1. Enforce request validation: `model` required, non-empty `file` required, and transcription `response_format` restricted to JSON variants for this plan (`json`, `verbose_json`).

`/v1/models`

1. No payload encryption/decryption.

`/v1/models/{model}`

1. No payload encryption/decryption.
1. Provider-native endpoint exists; Teep may choose to leave this unexposed in its OpenAI-compat surface for this plan revision.

`/unstructured/general/v0/general`

1. Entire multipart request body is encrypted as a single ciphertext blob for provider-native unstructured flow.
1. Entire JSON response body is decrypted as one encrypted blob.
1. Not in Teep routing scope for this plan revision, but included for protocol completeness.

### Streaming Contract

1. OpenAI-compatible stream (`/v1/chat/completions` with `stream=true`):
  - Transport: `text/event-stream`.
  - Decrypt only `data:` payload values.
  - `[DONE]` sentinel remains plaintext and terminates stream.
1. Anthropic messages stream (`/v1/messages` with `stream=true`):
  - Transport: `text/event-stream`.
  - Keep envelope event typing intact (`event: message_start`, `event: content_block_delta`, etc.).
  - Never mutate `event:` lines; mutate only `data:` JSON payload lines.
  - Preserve Anthropic event framing (`event:` line + following `data:` line in same event block).
1. Any chunk-level decrypt/auth failure aborts stream immediately (fail closed).

### Unsupported Endpoint Policy

1. Treat `/v1/images/generations`, `/v1/rerank`, and `/v1/score` as unsupported in this plan revision.
1. Return deterministic client-visible error (`HTTP 400`) for unsupported endpoint/provider combinations.
1. If upstream signals plaintext bypass via `Privatemode-Encrypted: false` on an endpoint where this plan requires encryption, Teep must fail closed (do not silently pass plaintext through).

## Endpoint and Encryption Matrix

Planned endpoint support and expected encryption handling.

| Endpoint | Method | Status in Teep Plan | Request Encryption | Response Encryption | Streaming |
|---|---|---|---|---|---|
| `/v1/chat/completions` | POST | Required | Sensitive fields encrypted | Sensitive fields encrypted | Yes |
| `/v1/completions` | POST | New in this plan | Sensitive fields encrypted | Sensitive fields encrypted | Optional |
| `/v1/messages` | POST | New in this plan | Sensitive fields encrypted | Sensitive fields encrypted | Yes |
| `/v1/embeddings` | POST | Required | Sensitive fields encrypted | Sensitive fields encrypted | No |
| `/v1/audio/transcriptions` | POST | Required | Sensitive fields encrypted | Sensitive fields encrypted | No |
| `/v1/models/{model}` | GET | Provider-native only (not required in Teep route set) | Not applicable | Not applicable | No |
| `/v1/images/generations` | POST | Not supported in this plan revision | N/A | N/A | No |
| `/v1/rerank` | POST | Not supported in this plan revision | N/A | N/A | No |
| `/v1/score` | POST | Not supported in this plan revision | N/A | N/A | No |
| `/v1/models` | GET | Required | Not applicable | Not applicable | No |
| `/unstructured/general/v0/general` | POST | Provider-native only (out of Teep scope) | Full-body encrypted blob | Full-body encrypted blob | No |

Field-level maps above are normative for this implementation.

## Verification Factor Design

### Factor Naming Convention

Factor names use the `tee_*` prefix established in the tinfoil and mapleai plans to generalize across TEE hardware platforms (Intel TDX, AMD SEV-SNP, AWS Nitro). The `tee_*` prefix denotes "TEE attestation" rather than a specific platform, so the same factor name is reported and enforced identically regardless of whether the underlying Coordinator runs on TDX or SEV-SNP. This convention was introduced to avoid proliferating platform-specific names (`tdx_*`, `snp_*`) when the verification semantics are identical.

For PrivateMode, all `tee_*` factors apply to the **Contrast Coordinator's** attestation. The Coordinator is the attestation root for the deployment; downstream worker attestation is validated by the Coordinator's policy, not through individual TEE quotes directly visible to the Teep client.

### New Factor: `manifest_policy_match`

`manifest_policy_match` is introduced for PrivateMode to capture the Contrast-specific verification step in which Teep confirms that the Coordinator-enforced manifest equals the expected manifest.

No existing factor covers this check:

- `tee_boot_config` verifies that measurement registers (MRTD, RTMR, PCR) match expected values, but does not verify the policy document that defines those expected values or that the Coordinator is enforcing a known-good manifest.
- `tee_mrseam_mrtd` verifies firmware/enclave identity measurements but does not verify manifest identity or deployment policy scope.
- The Contrast manifest is the trust anchor equivalent of a measurement allowlist: it defines which workloads are admitted, what their measurements must be, and which policies govern key release. A manifest mismatch means the deployment under attestation is not the expected deployment, even if the hardware attestation is otherwise valid.

This factor name generalizes across any attestation system that uses a policy document (manifest, manifest hash, or deployment policy artifact) as the binding artifact between Coordinator identity and workload admission. It is enforced regardless of which TEE platform the Coordinator runs on.

### Reuse of `tls_key_binding` for Mesh CA

The existing `tls_key_binding` factor is reused to cover PrivateMode's mesh CA and secret-service key-exchange identity verification. In TDX/Chutes providers `tls_key_binding` means the TLS public key fingerprint appears in attestation REPORTDATA (direct SPKI pinning). In PrivateMode, the binding mechanism is CA-trust delegation plus transcript signature:

- The Coordinator provides a mesh CA certificate as part of its attested session.
- The secret exchange response includes `mesh_cert` and `signature`.
- Teep verifies `mesh_cert` against the attested mesh CA and verifies `signature` over `SHA256(request_public_key || encapsulated_key)` with the key in `mesh_cert`.

The security goal is identical to SPKI pinning: the key-exchange peer is cryptographically bound to the attested Coordinator identity. `tls_key_binding` captures this step with a PrivateMode-specific detail string explaining the CA-delegation mechanism. No separate `mesh_ca_retrieved` factor is required; mesh CA retrieval and mesh-cert verification are sub-steps within `tls_key_binding` and failures in either must fail that factor.

### Factors

The following table uses the canonical generalized names from the tinfoil and mapleai plans. Inline commentary notes the mapping to PrivateMode protocol steps.

| Factor | Meaning | Default Policy | PrivateMode Step |
|---|---|---|---|
| `tee_quote_present` | Coordinator attestation document received and non-empty | Enforced | `POST /privatemode/v1/attest` returns non-empty `AttestationDoc` |
| `tee_quote_structure` | Attestation document parses correctly; signature and cert chain verify | Enforced | CBOR/JSON structure valid; hardware root signature validates |
| `tee_cert_chain` | Attestation certificate chain validates to a trusted hardware root | Enforced | TDX: Intel PCK→root; SEV-SNP: AMD ARK→ASK→VCEK |
| `tee_mrseam_mrtd` | Coordinator firmware and enclave identity measurements match expected | Enforced | MRTD/RTMR0 or SEV-SNP measurement field matches allowlist |
| `tee_hardware_config` | Platform hardware configuration policy satisfied | Allow-fail initial | TDX: attrs/XFAM/RTMR3; SEV-SNP: guest policy flags |
| `tee_boot_config` | Coordinator boot measurements match expected values | Allow-fail initial | RTMR1/RTMR2 or SEV-SNP measurement matches allowlist |
| `tee_tcb_current` | Coordinator TCB SVN meets minimum threshold | Allow-fail initial | SVN fields compared against platform minimum; requires Intel PCS or AMD KDS |
| `tee_reportdata_binding` | Attested REPORTDATA equals expected digest over nonce + transition + CA state | Enforced | Verify `REPORT_DATA == SHA256(nonce||transitionDigest||SHA256(root_ca)||SHA256(mesh_ca)) || 32 zero bytes` |
| `signing_key_present` | Secret-exchange signature material is present and parseable | Enforced | `signature` and `mesh_cert` fields exist in `/privatemode/v1/secret` response and parse correctly |
| `nonce_match` | Client nonce is bound into attested transcript | Enforced | Nonce participates in validated REPORTDATA construction |
| `manifest_policy_match` | Coordinator-enforced manifest equals the expected manifest | Enforced | Attested manifest bytes equal Teep-configured expected manifest identity (hash or full bytes) |
| `tls_key_binding` | Secret-exchange signer identity bound to Coordinator-attested mesh CA | Enforced | `mesh_cert` chains to attested mesh CA and signs `SHA256(request_public_key || encapsulated_key)` |
| `e2ee_capable` | Required key exchange succeeded and session key derived | Enforced | ML-KEM-768 + X25519 hybrid KEM completes; session key non-zero |
| `e2ee_usable` | Live request encrypted and response decrypted via session key | Enforced | AES-GCM authenticated encryption and decryption succeed for a live request |
| `cpu_gpu_chain` | GPU-CPU hardware evidence binding | Allow-fail | Not externally observable via PrivateMode public API |
| `measured_model_weights` | Model weight integrity evidence | Allow-fail | Transitive through Coordinator manifest; not independently verifiable by client |
| `nvidia_payload_present` | NVIDIA GPU attestation payload received | Allow-fail | Not exposed via PrivateMode public API |
| `nvidia_claims` | NVIDIA GPU attestation claims valid | Allow-fail | Not exposed via PrivateMode public API |
| `nvidia_nras_verified` | NVIDIA NRAS countersignature valid | Allow-fail | Not exposed via PrivateMode public API |

### `PrivatemodeDefaultAllowFail` Profile

The following factors are allowed to fail without blocking requests initially. All other factors are enforced:

```go
// PrivatemodeDefaultAllowFail is the privatemode-specific default allow_fail list.
// tee_hardware_config and tee_boot_config start allow-fail until Coordinator
// measurement allowlists are collected from live deployment.
// tee_tcb_current requires Intel PCS or AMD KDS network access (--offline skips).
// GPU/NVIDIA factors are not exposed via the PrivateMode public API.
var PrivatemodeDefaultAllowFail = []string{
    "tee_hardware_config",       // platform config constraints; enforced after allowlist is populated
    "tee_boot_config",           // boot measurements; enforced after allowlist is populated
    "tee_tcb_current",           // TCB SVN minimums require PCS/KDS; allow-fail under --offline
    "cpu_gpu_chain",             // GPU-CPU binding not externally observable
    "measured_model_weights",    // transitive via Coordinator; not independently verifiable
    "nvidia_payload_present",    // GPU attestation not exposed by PrivateMode public API
    "nvidia_claims",
    "nvidia_nras_verified",
}
```

### Fail-Closed Rules

1. Any enforced factor fail blocks forwarding.
1. Enforced factor `Skip` is promoted to `Fail` unless the factor appears in the provider's `allow_fail` list.
1. `e2ee_usable` fail blocks the request path where E2EE is required.
1. `manifest_policy_match` fail must block forwarding; a mismatched manifest means the attested deployment is not the expected one.
1. Missing/empty `signature`, `mesh_cert`, or `encapsulated_key` in secret exchange response fails `signing_key_present` and `e2ee_capable`.
1. Nonce generation uses `crypto/rand`; any error fails `nonce_match` and blocks the request.

## Detailed Implementation Phases

### Phase 0: Protocol Freeze and Security Invariants

Deliverables:

1. Finalized protocol contract appendix in this file.
1. Verified assumptions list with pass/fail validation experiments.
1. Security invariants checklist copied into implementation PR description template.

Tasks:

1. Execute live protocol probes using `PRIVATEMODE_API_KEY` and capture sanitized traces.
1. Confirm request/response encryption envelope formats for chat, completions, messages, embeddings, and transcription.
1. Confirm streaming event framing and required nonce/sequence metadata.
1. Confirm deterministic fail-closed behavior for currently unsupported endpoints (`/v1/images/generations`, `/v1/rerank`, `/v1/score`).

Blocking criteria:

1. No implementation begins until unknown protocol assumptions are either validated or explicitly marked unsupported.

### Phase 1: Endpoint Plumbing Expansion in Teep

Files:

1. `internal/proxy/proxy.go`
1. `internal/provider/provider.go`
1. `internal/e2ee` endpoint enums and dispatch helpers
1. `internal/proxy/*_test.go`

Tasks:

1. Register new routes for `POST /v1/completions` and `POST /v1/messages`.
1. Extend provider endpoint path surface to include completions/messages.
1. Extend endpoint-type dispatch in encryption and relay logic.
1. Add negative path handling for providers that do not support new routes.

Tests:

1. Route registration tests for both new endpoints.
1. Unsupported provider returns HTTP 400 with deterministic error.
1. Endpoint dispatch coverage tests for encrypted and plaintext modes.

### Phase 2: New Provider Package Skeleton

Files to create:

1. `internal/provider/privatemode/privatemode.go`
1. `internal/provider/privatemode/attester.go`
1. `internal/provider/privatemode/manifest.go`
1. `internal/provider/privatemode/trustchain.go`
1. `internal/provider/privatemode/reportdata.go`
1. `internal/provider/privatemode/e2ee.go`
1. `internal/provider/privatemode/fields.go`
1. `internal/provider/privatemode/models.go`
1. `internal/provider/privatemode/policy.go`
1. `internal/provider/privatemode/session_cache.go`

Tasks:

1. Define all parser bounds for untrusted JSON, certificate blobs, and encrypted payload fields.
1. Keep all mutable state instance-local and mutex protected.
1. Define reusable error classes for fail-closed decision paths.

Tests:

1. One test file per source file with success and malformed-input cases.
1. Fuzz entry points for parser and decryptor functions.

### Phase 3: Attestation and Trust-Chain Integration

Files:

1. `internal/provider/privatemode/attester.go`
1. `internal/provider/privatemode/manifest.go`
1. `internal/provider/privatemode/trustchain.go`
1. `internal/provider/privatemode/reportdata.go`
1. `internal/verify/factory.go`

Tasks:

1. Implement Coordinator attestation flow and manifest matching.
1. Implement mesh CA retrieval plus secret-exchange signer verification (`mesh_cert` chain + transcript signature).
1. Implement key-binding verification from attestation outputs.
1. Emit detailed factor details for report generation.

Tests:

1. Attestation success fixture.
1. Manifest mismatch fixture.
1. Invalid mesh CA fixture.
1. Secret-exchange signer mismatch fixture (invalid `mesh_cert` chain or invalid signature).
1. Binding mismatch fixture.

### Phase 4: E2EE Implementation

Files:

1. `internal/provider/privatemode/e2ee.go`
1. `internal/provider/privatemode/fields.go`
1. `internal/e2ee` helper additions as needed

Tasks:

1. Implement key establishment and session derivation according to validated protocol transcript.
1. Implement AES-GCM request encryption and response decryption for non-stream and stream.
1. Implement endpoint-specific sensitive-field encryption maps.
1. Implement nonce/sequence validation and replay protection.
1. Zero ephemeral keying material after use where feasible.

Tests:

1. Round-trip encryption/decryption test vectors.
1. Missing nonce metadata fails.
1. AEAD auth failure fails.
1. Stream chunk corruption aborts stream.
1. Concurrent encryption requests show no nonce collisions or races.

### Phase 5: Provider Wiring in Proxy, Verify, Defaults, and Config

Files:

1. `internal/proxy/proxy.go`
1. `internal/verify/factory.go`
1. `internal/defaults/defaults.go`
1. `internal/config/config.go`
1. `teep.toml.example`
1. `docs/api_support.md`
1. `Makefile`

Tasks:

1. Add `privatemode` in provider construction switch.
1. Add attester, report verifier, and env map entries.
1. Add default policy and allow-fail profile entries.
1. Add example config with `PRIVATEMODE_API_KEY` and provider base URL.
1. Add make targets for fixture integration and live integration.

Tests:

1. Factory tests for provider registration.
1. Config load tests for API key env resolution and strict validation.
1. Docs matrix consistency test if available; otherwise lint check on table changes.

### Phase 6: Testing Matrix

### Unit Tests

1. Parser bounds and malformed input rejection.
1. Certificate and trust chain verification behavior.
1. Key-binding constant-time comparison logic.
1. E2EE round-trip and error cases.
1. Session cache TTL and eviction.
1. Concurrency race tests using goroutines and shared cache.

### Fixture Integration Tests (No API Key)

1. Add `internal/integration/privatemode_test.go` with replay transport fixtures.
1. Include sanitized captured fixtures for success and failure branches.
1. Assert must-pass and must-fail factor sets.

### Live Integration Tests (Requires API Key)

1. Add `internal/proxy/integration_privatemode_test.go`.
1. Gate by `PRIVATEMODE_API_KEY` and `testing.Short()`.
1. Cover endpoints: chat, completions, messages, embeddings, transcription, models.
1. Add negative tests asserting unsupported endpoints return deterministic `HTTP 400` without plaintext forwarding.
1. Add stream and non-stream tests where supported.
1. Verify `e2ee_usable` with at least one real encrypted response path per endpoint class.

### Phase 7: Verification, Hardening, and Release Gates

Mandatory commands:

1. `make check`
1. `go test -race ./internal/provider/privatemode/...`
1. `go test -race -run TestIntegration_PrivateMode_Fixture ./internal/integration/`
1. `make integration-privatemode-fixture`
1. `source .env && make integration-privatemode`
1. `make report-privatemode`

Release criteria:

1. No new lints or race failures.
1. Enforced factors fail closed in proxy and verify paths.
1. E2EE downgrade is impossible for enforced endpoints.
1. Plan and docs remain source-independent and publicly referenced.

## Risk Assessment

1. Public docs may omit wire-level encryption details.
1. Endpoint field maps can drift as upstream schemas evolve.
1. Backend attestation evidence may remain transitive through Coordinator only.
1. GPU and model-weight factors may be partially observable from public interfaces.
1. Session cache race or stale-state bugs can weaken guarantees if not aggressively tested.

Mitigations:

1. Treat unknown protocol details as blocking assumptions in Phase 0.
1. Add strict schema guards and reject unknown critical fields by policy.
1. Keep conservative default enforcement and explicit allow-fail minimal list.
1. Add fixture and live regression tests per release.

## Comparison Snapshot: PrivateMode vs MapleAI vs Tinfoil Plan Depth

This plan is intentionally aligned with benchmark plan characteristics:

1. Explicit authentication-chain analysis rather than phase-only checklist.
1. Explicit factor policy with enforced and allow-fail defaults.
1. Endpoint matrix including new routes and encryption behavior.
1. File-level implementation guidance and per-phase test obligations.
1. Dedicated risk and release-gate sections.

## Implementation File Map

1. `internal/proxy/proxy.go`
1. `internal/provider/provider.go`
1. `internal/verify/factory.go`
1. `internal/defaults/defaults.go`
1. `internal/config/config.go`
1. `internal/provider/privatemode/*.go`
1. `internal/provider/privatemode/*_test.go`
1. `internal/integration/privatemode_test.go`
1. `internal/proxy/integration_privatemode_test.go`
1. `docs/api_support.md`
1. `teep.toml.example`
1. `Makefile`

## Decisions

1. Include `/v1/completions` and `/v1/messages` in this effort.
1. Use direct attestation and direct E2EE integration in Teep.
1. Keep plan normative references public-only.
1. Maintain fail-closed behavior as first principle.

## Validation Appendix: Required Protocol Experiments

Before final implementation freeze, run and record sanitized outputs for:

1. Coordinator attestation and manifest binding transaction.
1. Mesh CA retrieval and secret-exchange signer verification transaction.
1. Key establishment transaction and key-binding evidence.
1. One non-stream endpoint envelope decode path.
1. One stream endpoint envelope decode path.
1. Negative tests: tampered ciphertext, missing nonce metadata, manifest mismatch.

If any experiment contradicts assumptions in this plan, update this file first, then implement.

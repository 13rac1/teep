# Tinfoil NVSwitch Evidence: JSON Re-encoding Hash Mismatch

Tinfoil's V3 attestation endpoint serves NVSwitch evidence whose
`report_data.nvswitch_evidence_hash` does not match the SHA-256 of the
NVSwitch JSON bytes in the HTTP response. The server computes the hash
over the raw `nvattest` CLI output (serialized by NVIDIA's C++
`nlohmann/json` library), but Go's `json.Marshal` re-encodes the
`json.RawMessage` when embedding it in the response, producing different
bytes. Because the NVSwitch evidence hash is part of the REPORTDATA
preimage, this mismatch prevents the entire REPORTDATA hash from being
verified — meaning the TLS SPKI, HPKE key, nonce, and GPU evidence hash
cannot be authenticated via the hardware-signed attestation report.

This document describes Tinfoil's superseded attestation format. teep
refuses a document in that format. The current format hashes the
base64-decoded bytes of each endorsed section, so this re-encoding
mismatch cannot occur in it. The teep workaround that this document
described was removed when teep moved to the current format. The
[Teep Status](#teep-status) section gives the current results.

## The Problem

The REPORTDATA field in the Tinfoil V3 attestation document is a 64-byte
value where the first 32 bytes are:

```
SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
```

This hash is signed by the CPU hardware (TDX quote or SEV-SNP report),
cryptographically binding the TLS certificate fingerprint, HPKE public
key, client nonce, GPU evidence, and NVSwitch evidence to the enclave
identity. Without verifying this hash, none of these components are
authenticated by the hardware signature — they are only verified by
independent factor checks that do not prove they all belong to the same
enclave.

The server computes `nvswitch_evidence_hash` as `SHA-256(raw_nvattest_output)`,
where the raw output comes from NVIDIA's `nvattest` CLI tool (serialized
by the C++ `nlohmann/json` library). When the server embeds this output
as a `json.RawMessage` in the `Attestation` struct and serializes the
full response with Go's `json.Marshal`, Go re-encodes the
`json.RawMessage` — compacting whitespace and potentially changing
number formatting or string escaping. The hash was computed over the
pre-re-encoding bytes, but the response contains the post-re-encoding
bytes. Any external verifier that hashes the NVSwitch JSON bytes from
the response will compute a different hash than the one in
`report_data.nvswitch_evidence_hash`.

Because the NVSwitch evidence hash is part of the REPORTDATA preimage,
this mismatch is not isolated to NVSwitch verification. If a verifier
rejects the mismatched hash and fails early, the entire REPORTDATA hash
is never computed or compared against the hardware-signed value. This
means the TLS SPKI, HPKE key, nonce, and GPU evidence hash — all of
which are correctly reported and independently verifiable — lose their
hardware-signed authentication. An attacker who could relay a valid
hardware quote from one enclave while serving different TLS/HPKE keys
from another would not be detected by the REPORTDATA check.

## Impact

**Security impact (superseded format):** For a verifier without a
workaround, the NVSwitch hash mismatch prevented hardware-signed
authentication of the TLS SPKI,
HPKE key, nonce, and GPU evidence hash for all 8-GPU Hopper Tinfoil
inference enclaves. While each component is independently verified by
separate factor checks (TLS SPKI by `tls_key_binding`, HPKE key by
`e2ee_capable`/`e2ee_usable`, nonce by `nonce_match`, GPU evidence by
`nvidia_*` factors), the REPORTDATA hash provides transitive
authentication: it proves that the enclave that generated the hardware
quote is the same enclave that holds the TLS private key, HPKE private
key, and GPU evidence. Without it, a relay attack that substitutes
keys or evidence from a different enclave would not be detected by the
hardware binding check.

A verifier that used the reported hash in the preimage, as teep did
before it moved to the current format, authenticated the TLS SPKI, HPKE
key, nonce, and GPU evidence hash via the hardware-signed REPORTDATA.
Only the NVSwitch evidence hash binding remained unverified.

The GPU evidence hash (for the `gpu` field) is NOT affected by this
bug — GPU evidence is collected via `json.Marshal` in Go, which
produces compact JSON from the start, so the hash matches the response
bytes. Only NVSwitch evidence, collected via the external `nvattest`
CLI, is affected.

**Operational impact:** none in the current format, which hashes the
bytes that the enclave sends.

---

## Technical Background

### V3 Attestation Document Structure (superseded format)

The superseded Tinfoil V3 attestation response was a JSON document with
the following structure. teep refuses a document that carries any of
the `report_data`, `certificate`, `signature` or `cpu` members:

```json
{
  "format": "https://tinfoil.sh/predicate/attestation/v3",
  "report_data": {
    "tls_key_fp": "<64 hex>",
    "hpke_key": "<64 hex>",
    "nonce": "<64 hex>",
    "gpu_evidence_hash": "<64 hex>",
    "nvswitch_evidence_hash": "<64 hex>"
  },
  "cpu": { "platform": "tdx|sev-snp", "report": "<base64>" },
  "gpu": { "evidences": [...] },
  "nvswitch": { "evidences": [...], "result_code": 0, "result_message": "..." },
  "certificate": "<PEM>",
  "signature": "<base64 ECDSA>"
}
```

The `report_data.gpu_evidence_hash` and
`report_data.nvswitch_evidence_hash` fields contain SHA-256 hashes of
the raw `gpu` and `nvswitch` JSON field bytes, respectively. These
hashes are included in the REPORTDATA preimage:

```
REPORTDATA[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
REPORTDATA[32:64] = zeros
```

The CPU hardware attestation report (TDX quote or SEV-SNP report) signs
the REPORTDATA, cryptographically binding the GPU and NVSwitch evidence
to the CPU enclave identity.

### Server-Side Evidence Collection

The Tinfoil CVM image collects GPU and NVSwitch evidence differently:

**GPU evidence** is collected via NVML (Go bindings):
- `CollectGPUEvidence` calls `nvml.GetConfComputeGpuAttestationReport`
- The evidence is marshaled with Go's `json.Marshal(gpuEvidence)`,
  producing compact JSON
- The compact JSON is used as `json.RawMessage` for both hashing and
  response embedding
- Hash and response bytes match → verification passes

**NVSwitch evidence** is collected via the `nvattest` CLI:
- `CollectNVSwitchEvidence` runs `nvattest collect-evidence --device
  nvswitch --nonce <hex> --format json`
- The CLI output (serialized by NVIDIA's C++ `nlohmann/json` library)
  is used directly as `json.RawMessage(out)`
- `EvidenceHash(nvswitchJSON)` computes SHA-256 over the raw CLI output
  bytes
- The `Attestation` struct is serialized with
  `json.NewEncoder(w).Encode(fresh)`, which calls `json.Marshal`
  internally
- `json.Marshal` re-encodes the `json.RawMessage`, changing the byte
  sequence
- Hash was computed over pre-re-encoding bytes; response contains
  post-re-encoding bytes → mismatch

### Go's json.RawMessage Re-encoding Behavior

Go's `encoding/json` package treats `json.RawMessage` as a raw JSON
value that implements `MarshalJSON()`. When `json.Marshal` encounters a
`json.RawMessage`, it calls `MarshalJSON()` which returns the raw bytes
as-is. However, `json.Marshal` then validates and potentially re-encodes
the returned bytes to ensure they are valid JSON embedded in the parent
structure.

Specifically, `json.Marshal` compacts `json.RawMessage` bytes: it
strips whitespace (spaces, newlines, tabs) between JSON tokens. If the
`nvattest` CLI outputs pretty-printed JSON (which `nlohmann/json` does
not do by default, but the CLI may configure), the compacted bytes will
differ from the original.

Even if the `nvattest` output is already compact, `nlohmann/json` and
Go's `encoding/json` may produce different byte sequences for the same
data due to:
- Different number formatting (integers vs floats)
- Different string escaping (unicode escape sequences)
- Different key ordering (though both preserve insertion order by
  default)

---

## Detailed Gap Analysis

### Server Source Code Analysis

The bug was in `CollectNVSwitchEvidence`
(`tinfoil/internal/attestation/gpu.go`) in the
[`tinfoilsh/cvmimage`](https://github.com/tinfoilsh/cvmimage) repository,
in the version that served the superseded format:

```go
func CollectNVSwitchEvidence(nonce [32]byte) (json.RawMessage, error) {
    nonceHex := hex.EncodeToString(nonce[:])
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    out, err := exec.CommandContext(ctx, "nvattest", "collect-evidence",
        "--device", "nvswitch",
        "--nonce", nonceHex,
        "--format", "json",
    ).Output()
    if err != nil {
        return nil, fmt.Errorf("nvattest collect-evidence nvswitch: %w", err)
    }

    if !json.Valid(out) {
        return nil, fmt.Errorf("nvattest returned invalid JSON")
    }

    return json.RawMessage(out), nil  // ← raw CLI output, not compacted
}
```

The function returns the raw `nvattest` CLI output as `json.RawMessage`
without normalizing it. This raw output is then:

1. Passed to `BuildAttestation`, which calls
   `EvidenceHash(nvswitchJSON)` — hashing the raw CLI output bytes
2. Set as the `NVSwitch` field on the `Attestation` struct
3. Serialized with `json.NewEncoder(w).Encode(fresh)` — which re-encodes
   the `json.RawMessage`, potentially changing the bytes

The GPU evidence path does not have this issue because
`CollectGPUEvidence` returns a Go struct (`*GPUEvidenceCollection`),
which is marshaled with `json.Marshal(gpuEvidence)` at the call site
in `api.go`, producing compact Go-native JSON. The same
compact bytes are used for both the hash and the response.

### Empirical Verification

Two attestation responses in the superseded format were fetched from
`glm-5-2.tinfoil.containers.tinfoil.dev` (8-GPU Hopper TDX enclave).
These results were not reproduced on 2026-11-15: teep refuses the
superseded format, and `tinfoil_v3_direct` has been disabled since
2026-11-12.
For each response, the NVSwitch JSON bytes were extracted from the raw
HTTP response body and hashed with SHA-256. The computed hash was
compared against the `report_data.nvswitch_evidence_hash` field.

| Attempt | Reported Hash | Computed Hash (from response bytes) | Match? |
|---|---|---|---|
| 1 | `bffc94fd...` | `cd8e37fc...` | ✗ |
| 2 | `985ab210...` | `5e0a6c02...` | ✗ |

Multiple re-encoding strategies were tested against the response bytes:
compact, pretty-printed (2-space, 1-space, tab indent), with/without
trailing newline, re-marshaled via `json.Marshal`, and normalized via
`json.Compact`. None matched the reported hash.

The GPU evidence hash was also checked and matches perfectly in both
responses, confirming the issue is specific to the NVSwitch evidence
collection path.

### Teep Report Factor Behavior

teep no longer evaluates the superseded format. The current results are
in [Teep Status](#teep-status).

### Why the Workaround Was Necessary (superseded format)

The REPORTDATA hash authenticates ALL of these components as a group:

```
REPORTDATA[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
```

This hash is signed by the CPU hardware (TDX quote or SEV-SNP report).
Without verifying it, none of these components are authenticated by the
hardware signature — they are only verified by independent factor checks
(TLS SPKI by `tls_key_binding`, HPKE key by `e2ee_capable`/`e2ee_usable`,
nonce by `nonce_match`, GPU evidence by `nvidia_*` factors).

The independent factor checks are sufficient for individual component
authentication, but the REPORTDATA hash provides **transitive
authentication**: it proves that the enclave that generated the hardware
quote is the same enclave that holds the TLS private key, HPKE private
key, and GPU evidence. Without REPORTDATA verification, an attacker who
could relay a valid hardware quote from one enclave while serving
different TLS/HPKE keys from another would not be detected by the
REPORTDATA check (though the attestation fetch's peer SPKI verification
and the upstream TLS binding verification would still catch this).

The workaround uses the **reported** `nvswitch_evidence_hash` (from
`report_data`) in the preimage instead of the computed hash. This is
safe because:

1. The reported hash is what the server bound into REPORTDATA
2. The REPORTDATA hash is signed by the CPU hardware
3. If the REPORTDATA hash matches, it proves the server used these
   exact values (tls_key_fp, hpke_key, nonce, gpu_evidence_hash,
   nvswitch_evidence_hash) when generating the hardware quote
4. The TLS SPKI, HPKE key, and GPU evidence hash are independently
   verified against the response data, so they cannot be substituted

The only component that is NOT authenticated is the NVSwitch evidence
hash binding — we cannot confirm that the NVSwitch evidence in the
response matches what the server hashed.

---

## Remediation

The current format resolves this mismatch: each endorsed section is
hashed over the bytes that the enclave sends. The fix below applied to
the superseded format.

### Server-Side Fix (Required)

The fix is in `CollectNVSwitchEvidence` in the `cvmimage` repository.
The function must compact the `nvattest` CLI output before returning it
as `json.RawMessage`, ensuring the hash is computed over the same bytes
that `json.Marshal` will produce in the response:

```go
func CollectNVSwitchEvidence(nonce [32]byte) (json.RawMessage, error) {
    // ... existing nvattest call ...

    if !json.Valid(out) {
        return nil, fmt.Errorf("nvattest returned invalid JSON")
    }

    // Compact the JSON to ensure hash consistency: json.Marshal will
    // compact json.RawMessage when embedding it in the response, so
    // the hash must be computed over the compacted form.
    var compacted bytes.Buffer
    if err := json.Compact(&compacted, out); err != nil {
        return nil, fmt.Errorf("compact nvswitch JSON: %w", err)
    }
    return json.RawMessage(compacted.Bytes()), nil
}
```

This ensures `EvidenceHash(nvswitchJSON)` computes the hash over compact
bytes, and `json.Marshal(att)` preserves those exact compact bytes in
the response.

**Important caveat:** `json.Compact` only strips whitespace — it does
not reorder keys, change number formatting, or modify string escaping.
If the `nvattest` CLI output differs from Go's `json.Marshal` output in
any of these aspects, `json.Compact` alone will not fix the mismatch.
In that case, the server should parse the `nvattest` output into a Go
data structure and re-marshal it with `json.Marshal` before hashing:

```go
var parsed interface{}
if err := json.Unmarshal(out, &parsed); err != nil {
    return nil, fmt.Errorf("parse nvswitch JSON: %w", err)
}
compacted, err := json.Marshal(parsed)
if err != nil {
    return nil, fmt.Errorf("re-marshal nvswitch JSON: %w", err)
}
return json.RawMessage(compacted), nil
```

This guarantees the hash is computed over Go-native JSON bytes that
`json.Marshal` will reproduce exactly in the response.

### Client-Side Workaround (removed)

teep removed the workaround, which used the reported
`nvswitch_evidence_hash` in the REPORTDATA preimage, when it moved to
the current format. teep refuses the superseded format.

### Deployment Priority

1. **Server-side fix** (the current format, which hashes the
   base64-decoded section bytes, does not have this mismatch)
2. **teep:** read GPU and NVSwitch evidence in the current format

---

## References

- **Server source code:** `CollectNVSwitchEvidence`
  (`tinfoil/internal/attestation/gpu.go`) and `BuildAttestation`
  (`tinfoil/internal/attestation/attestation.go`) in
  [`tinfoilsh/cvmimage`](https://github.com/tinfoilsh/cvmimage), in the
  version that served the superseded format (not pinned to a commit)
- **nvattest CLI:** Built from
  [NVIDIA/attestation-sdk](https://github.com/NVIDIA/attestation-sdk)
  using `nlohmann/json` for serialization
- **Go json.RawMessage:** [encoding/json documentation](https://pkg.go.dev/encoding/json#RawMessage)
- **Tinfoil SPEC §4.8:** TDX policy validation including XFAM and
  TD_ATTRIBUTES pins

---

## Teep Status

teep refuses the superseded format described above, and the workaround
is removed. On 2026-11-14, every `tinfoil_v3_cloud` model (14 of 14)
gave:

- `tee_reportdata_binding` — **Fail**, allowed: the router answer carries
  no backend TEE quote or report.
- `cpu_gpu_chain` — **Fail**, allowed: the router, the only attested
  machine, serves an empty device evidence section, so no GPU is bound to
  the CPU report.
- `nvswitch_binding` — **Skip**, allowed: no GPU evidence.
- `gateway_tee_reportdata_binding` — **Pass**, enforced:
  `v3: reportdata_hash verified, nonce_bound=true, gpu_bound=false`.

`nvswitch_binding` is in the default allow_fail lists of both Tinfoil
providers. teep does not yet read GPU or NVSwitch evidence in the
current format, and refuses an enclave that serves device evidence.
`tinfoil_v3_direct` has been disabled since 2026-11-12.

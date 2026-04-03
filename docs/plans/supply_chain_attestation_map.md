# Teep Supply Chain & Compose Binding Attestation

## Provider Supply Chain Policies

### Dstack-Based Providers (Venice, Neardirect, Nearcloud, NanoGPT)

All dstack providers use `DstackBaseMeasurementPolicy()` which provides:
- **MRSEAM**: 4 Intel TDX module versions (1.5.08, 1.5.16, 2.0.08, 2.0.02)
- **MRTD**: 2 dstack-nvidia image versions (0.5.4.1, 0.5.5)
- **RTMR**: Provider-specific (hardware + OS + application configuration)

### Venice ([venice/policy.go](internal/provider/venice/policy.go))
- **SupplyChainPolicy** → Delegates to neardirect (same container images)
- **Images** (3 total, all ModelTier):
  1. `datadog/agent` (Sigstore signing required, fingerprint verified)
  2. `certbot/dns-cloudflare` (ComposeBindingOnly)
  3. `nearaidev/compose-manager` (FulcioSigned, GitHub Actions OIDC)

### Neardirect ([neardirect/policy.go](internal/provider/neardirect/policy.go))
- **SupplyChainPolicy** (used by Venice too):
  - `datadog/agent`: Sigstore + fingerprint verification
  - `certbot/dns-cloudflare`: ComposeBindingOnly (digest pinned in compose)
  - `nearaidev/compose-manager`: Fulcio-signed, GitHub Actions build

### Nearcloud ([nearcloud/policy.go](internal/provider/nearcloud/policy.go))
- **SupplyChainPolicy**: Extends neardirect with gateway images:
  - Model tier: inherits Venice/neardirect policy
  - Gateway tier additions (6 total):
    - `datadog/agent` (also GatewayTier)
    - `nearaidev/dstack-vpc-client` (FulcioSigned)
    - `nearaidev/dstack-vpc` (FulcioSigned)
    - `alpine` (SigstorePresent only)
    - `nearaidev/cloud-api` (FulcioSigned)
    - `nearaidev/cvm-ingress` (FulcioSigned)
  - All Fulcio images use NoDSSE=true (DSSE envelope has no signatures as of 2026-03)
  - All use GitHub OIDC issuer

### NanoGPT ([nanogpt/policy.go](internal/provider/nanogpt/policy.go))
- **SupplyChainPolicy**: ComposeBindingOnly for all (10 images):
  - Security relies on MRConfigID binding to compose manifest
  - Uses tag-based references, NOT @sha256 pinning
  - All are ModelTier only
  - Images: alpine, dstacktee/*, haproxy, lmsysorg/sglang, mondaylord/vllm, phalanetwork/vllm, python, redis, vllm/vllm

### Chutes ([chutes/policy.go](internal/provider/chutes/policy.go))
- **NO SupplyChainPolicy** (returns nil)
- Uses cosign image admission + IMA instead of docker-compose binding
- Supply chain verification is validator-side only
- Has distinct Sek8s TDX measurements (not dstack)

## Compose Binding Verification

### How It Works ([internal/attestation/compose.go](internal/attestation/compose.go))

1. **VerifyComposeBinding(appCompose, mrConfigID)**:
   - Calculates SHA-256 hash of raw app_compose JSON
   - Expected MRConfigID prefix: 0x01 (1 byte) + sha256 hash (32 bytes)
   - Uses **const-time comparison** (`subtle.ConstantTimeCompare`)
   - Fails if prefix doesn't match

2. **ExtractDockerCompose(appCompose)**:
   - Parses JSON `app_compose` field
   - Extracts `docker_compose_file` string (YAML content)
   - Returns empty string if field absent (not an error)

3. **ExtractImageDigests(text)**:
   - Regex: `@sha256:[0-9a-f]{64}`
   - Deduplicates digests
   - Limits to 64 images per manifest (defense in depth - F-25)

4. **ExtractImageRepositories(text)**:
   - Normalizes image refs: strips tag, lowercases, trims whitespace
   - Returns deduplicated repo names from @sha256-pinned references

5. **ExtractImageDigestToRepoMap(text)**:
   - Maps digest → normalized repo name
   - Logs if same digest maps to multiple repos

## Attestation Report Factory System

### Verification Factors Architecture

**Tier 3: Supply Chain & Channel Integrity** evaluators:
- `evalBuildTransparencyLog`: Rekor provenance (sigstore/fulcio)
- `evalComposeBinding`: docker-compose hash binding to MRConfigID
- `evalSigstoreVerification`: image digest presence in Sigstore
- `evalCPUIDRegistry`: Proof of Cloud registry check
- `evalTLSKeyBinding`: TLS SPKI binding
- `evalCPUGPUChain`, `evalMeasuredModelWeights`: Stub factors (not implemented)
- `evalEventLogIntegrity`: TDX event log replay verification

### Supply Chain Policy Type ([internal/attestation/report.go](internal/attestation/report.go), line 1628)

```go
type SupplyChainPolicy struct {
	Images []ImageProvenance
}

type ImageProvenance struct {
	Repo           string         // normalized image repo
	ModelTier      bool           // allowed in model compose
	GatewayTier    bool           // allowed in gateway compose
	Provenance     ProvenanceType // FulcioSigned | SigstorePresent | ComposeBindingOnly
	KeyFingerprint string         // SHA-256 hex for SigstorePresent
	OIDCIssuer     string         // required for FulcioSigned
	OIDCIdentity   string         // SAN URI (workflow identity)
	SourceRepos    []string       // expected source repos
	NoDSSE         bool           // skip DSSE envelope validation
}

type ProvenanceType int
// FulcioSigned: must have Fulcio cert, matching OIDC issuer + identity + source repo
// SigstorePresent: in transparency log, optional fingerprint check
// ComposeBindingOnly: NOT in Sigstore, security via compose pinning
```

### Build Transparency Log Evaluation ([evalBuildTransparencyLog](internal/attestation/report.go), line 1001)

Flow:
1. **checkImageRepoPolicy**: Validate all model/gateway image repos against policy
   - Returns FAIL if any repo not in policy
   - Returns FAIL if gateway images present but policy has none

2. **buildTransparencyNoRekor**: When no Rekor entries
   - FAIL if policy configured (expected entries)
   - SKIP if composeHash present but no Rekor data
   - SKIP for Chutes (cosign/IMA model)
   - FAIL if no transparency log at all

3. **rekorProvenanceResult**: Process all Rekor entries
   - **classifyRekorEntry**: Per-entry classification
     - FulcioSigned: verify certificate OIDC issuer, identity, source repo
     - SigstorePresent: fingerprint check if policy has one
     - Fails on policy violation or unexpected signer
   - Accumulates: fulcio count, sigstore count, SET verified, inclusion verified
   - Returns FAIL on any verification failure
   - Returns PASS with count summary

### Enforce-by-Default vs Allow-Fail

**Enforced by default** (factors NOT in allow-fail list):
- `compose_binding` (dstack only)
- `build_transparency_log` (when policy configured)
- `sigstore_verification`
- `event_log_integrity`

**Allowed to fail by default** (per provider):
```go
DefaultAllowFail          // global list
NearcloudDefaultAllowFail // stricter for nearcloud
NeardirectDefaultAllowFail // stricter for neardirect
ChutesDefaultAllowFail    // includes compose_binding, build_transparency_log
```

**Chutes specifically allows**:
- compose_binding (uses cosign/IMA, not compose)
- build_transparency_log
- sigstore_verification
- event_log_integrity

## Key Security Properties

1. **Cryptographic Safety**:
   - All comparisons use `subtle.ConstantTimeCompare` (nonce, REPORTDATA binding, fingerprints, OIDC issuer/identity)

2. **Fail-Closed**:
   - Policy violation = policy check FAIL (not SKIP)
   - Missing policy → no enforcement
   - Enforced factors promoted from Skip → Fail

3. **Constant-Time Compose Binding**:
   - 33-byte prefix comparison (0x01 + 32-byte SHA-256)
   - Protects against timing side-channels on MRConfigID verification

4. **Image Digest Bounding**:
   - maxImageDigests = 64 (prevents regex explosion)

5. **Defense in Depth Layers**:
   - Measurement policy (RTMR binding to deployment)
   - Compose binding (app configuration immutability)
   - Rekor + Fulcio (build provenance)
   - Sigstore transparency log (global audit)
   - Fingerprint checking (keyless signing verification)



## SupplyChainPolicy Flow & Wiring (Updated 2026-04-03)

### Two Parallel Code Paths

**1. VERIFY COMMAND PATH** ([cmd/teep/main.go](cmd/teep/main.go#L607-L618))
- `supplyChainPolicy(providerName)` function is called at attestation build time
- Returns hardcoded provider-specific policy via switch statement
- Passed to `BuildReport(&ReportInput{SupplyChainPolicy: ...})`

**2. PROXY PATH** ([internal/proxy/proxy.go](internal/proxy/proxy.go#L370-L450))
- `fromConfig()` wires Provider struct during proxy initialization
- Calls provider-specific `SupplyChainPolicy()` function in switch statement
- Stores in `Provider.SupplyChainPolicy` field
- Later: passed to `BuildReport()` as `prov.SupplyChainPolicy`

### Provider Wiring Sources

All provider-specific policies are hardcoded in `policy.go` files:
- [internal/provider/venice/policy.go](internal/provider/venice/policy.go#L27)
- [internal/provider/neardirect/policy.go](internal/provider/neardirect/policy.go#L27)
- [internal/provider/nanogpt/policy.go](internal/provider/nanogpt/policy.go#L36)
- [internal/provider/nearcloud/pinned.go](internal/provider/nearcloud/pinned.go#L423) (calls SupplyChainPolicy())

### ReportInput Field

[attestation.ReportInput struct](internal/attestation/report.go#L328-L360) contains:
```go
SupplyChainPolicy *SupplyChainPolicy
```

Both paths (verify/proxy) populate this before calling `BuildReport()`.

### CONFIG INTEGRATION STATUS

**HARDCODED ONLY** - No config.toml integration exists today:
- Zero matches for "SupplyChainPolicy" in [internal/config/](internal/config/) 
- No `config.MergedSupplyChainPolicy()` equivalent (unlike measurement policies)
- Phalacloud returns nil in both paths (awaiting implementation)
- Chutes returns nil in both paths (uses cosign/IMA instead)
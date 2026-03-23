# Section 08 — CVM Image Binding & Component Provenance

## Scope

Audit CVM image binding to TDX evidence and verification of compose-listed component images using Sigstore/Rekor trust signals.

The attestation API will provide a full docker compose stanza, or equivalent podman/cloud config image description, as an auxiliary portion of the attestation API response. The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the TDX MRConfigID field.

The docker compose file (or podman/cloud config) will list a series of sub-images. The teep code MUST provide an enforced allow-list of sub-images and/or sub-image repositories for a given inference provider that are allowed to appear in this docker-compose file. The hashes need not be included in the teep code, but each of these sub-images MUST be checked against Sigstore and Rekor (or equivalent systems) to establish that they are official builds and not custom variations.

Additionally, the teep code MUST provide an expected Sigstore+Rekor Signer set (as OIDC or Fulcio certs). For Sigstore+Rekor checks, only this expected signer set is to be accepted.

## Primary Files

- [`internal/attestation/compose.go`](../../../internal/attestation/compose.go)
- [`internal/attestation/sigstore.go`](../../../internal/attestation/sigstore.go)
- [`internal/attestation/rekor.go`](../../../internal/attestation/rekor.go)

## Secondary Context Files

- [`internal/attestation/report.go`](../../../internal/attestation/report.go)
- [`internal/provider/neardirect/nearai.go`](../../../internal/provider/neardirect/nearai.go)
- [`internal/attestation/compose_test.go`](../../../internal/attestation/compose_test.go)
- [`internal/attestation/sigstore_test.go`](../../../internal/attestation/sigstore_test.go)
- [`internal/attestation/rekor_test.go`](../../../internal/attestation/rekor_test.go)

## Background: Supply Chain Integrity Role

CVM image verification is the critical link that authenticates the inference provider's software identity. Even with all model routing safety controls (domain validation, CT checks), nothing strongly authenticates the list of hostnames as belonging to the inference provider — this gap can only be mitigated by ensuring that the docker images are those expected to be used by the inference provider.

The verification chain works as follows:
1. The `app_compose` field is extracted from the attestation response (potentially from double-encoded JSON in `tcb_info`).
2. `SHA-256(app_compose)` is computed and compared against `MRConfigID` from the TDX quote (which is hardware-attested).
3. Image digests are extracted from the compose content and checked against the provider's allowlist.
4. Each image digest is verified against Sigstore for presence and against Rekor for Fulcio certificate provenance.
5. The Fulcio certificate OIDC issuer and identity are compared against the provider's expected signer set.

The `compose_binding` factor is one of the default enforced factors — failure MUST block request forwarding. The `sigstore_verification` and `build_transparency_log` factors may be additional enforcement candidates — the audit MUST evaluate whether they should be enforced by default and document the rationale.

## Required Checks

### Compose Binding to MRConfigID

Verify and report:
- exact compose-hash-to-`MRConfigID` binding format: the code expects `MRConfigID` to start with byte `0x01` followed by the `SHA-256(app_compose)` hash (33 bytes total prefix within the 48-byte `MRConfigID` field),
- that `VerifyComposeBinding()` uses `subtle.ConstantTimeCompare` for the prefix comparison (constant-time to prevent timing side-channels),
- that `MRConfigID` length is validated (must be at least 33 bytes),
- that an empty `MRConfigID` is explicitly rejected,
- `app_compose` extraction path and support for double-encoded JSON in `tcb_info` (the `tcb_info` field may contain a JSON string that itself contains JSON — verify the extraction handles this correctly),
- assurance that the hash input is the raw extracted compose content (not re-serialized — any re-serialization could alter whitespace or key ordering, changing the hash).

### Image Digest Extraction and Allowlist

Verify and report:
- digest extraction logic from compose content: the code uses regex `@sha256:([0-9a-f]{64})` to extract digests — verify this regex is anchored to exactly 64 lowercase hex characters,
- handling/rejection of non-`sha256` digest formats (e.g., `sha512:` digests — does the regex silently skip them?),
- deduplication behavior for extracted digests (using a `map[string]struct{}` seen-set),
- image repository extraction and normalization logic (`ExtractImageRepositories` strips tags while preserving registry ports),
- provider allowlist enforcement for all compose sub-images — verify that every extracted repository is checked against the provider's allowlist, and that unknown repositories cause a hard failure,
- whether the allowlist matching is case-sensitive or case-insensitive (the code uses `strings.ToLower` normalization).

### Sigstore Verification

Verify and report:
- Sigstore query behavior: the code uses `search.sigstore.dev` to check digest presence via HTTP HEAD (with GET fallback on 405),
- a digest is considered "OK" if HTTP status < 400 — verify this threshold is appropriate (e.g., 3xx redirects are counted as OK),
- Sigstore query failure semantics: whether a network timeout, connection refused, or HTTP 5xx is treated as a hard fail or advisory skip,
- response body handling: verify `resp.Body.Close()` is called even on error paths to prevent resource leaks,
- response body size: the GET fallback does not read the response body — verify no unbounded reads occur,
- the Sigstore search base URL is a package-level `var` (not `const`) to allow test overrides — verify this cannot be manipulated at runtime in production.

### Rekor Provenance Extraction

Verify and report:
- Rekor API interaction: UUID search via `POST /api/v1/index/retrieve`, then entry fetch via `POST /api/v1/log/entries/retrieve`,
- response body size limits: both Rekor API calls use `io.LimitReader(resp.Body, 1<<20)` (1 MiB limit) — confirm this is sufficient but bounded,
- DSSE envelope parsing: the code extracts `spec.signatures[0].verifier` (base64-encoded PEM) — verify only the first signature entry is used and whether ignoring additional signatures is a risk,
- PEM block type classification: `CERTIFICATE` → Fulcio provenance, `PUBLIC KEY` → raw key (no provenance), other → error,
- Fulcio certificate provenance extraction via X.509 extension OIDs (1.3.6.1.4.1.57264.1.*),
- accepted signer identity model: which OIDC issuer values and identity patterns are accepted by the provider configuration, and whether the check is exact-match or prefix/glob,
- behavior when digest appears in Sigstore but the Rekor entry has a raw public key (no Fulcio cert): `HasCert: false` — verify whether this is treated as passing provenance (risky) or only as presence confirmation,
- when multiple Rekor UUIDs are returned for a digest, only the first is fetched — document whether this is a risk (attacker could front-run with a valid-looking entry).

### Outage Behavior and Enforcement Classification

The audit MUST explicitly state:
- whether Sigstore/Rekor checks are soft-fail in default policy,
- what traffic is still allowed during Sigstore/Rekor outage conditions,
- whether the current enforcement policy includes `sigstore_verification` or `build_transparency_log` as enforced factors (or only advisory),
- the residual risk when these checks are advisory-only (a compromised image could pass compose binding if its hash matches, while Sigstore/Rekor would catch that it's not an official build — but only if those checks are enforced).

### Relationship to TDX Measurements

The compose binding (`MRConfigID`) provides application-layer assurance that the docker compose content matches what the TEE measured. However, this does not verify the base CVM image (firmware, kernel, initrd) — those require `MRTD` / `RTMR0-2` verification (see Section 05). The audit MUST document:
- compose binding covers: docker images listed in the compose file,
- compose binding does NOT cover: the host OS, kernel, initrd, firmware, TDX module,
- the combined assurance level when compose binding is enforced but `MRTD`/`RTMR0-2` golden values are absent.

## Go Best-Practice Audit Points

- **Regex compilation**: verify that `imageDigestRe` and `imageRefDigestRe` are compiled at package init time (via `regexp.MustCompile`) and not re-compiled per call.
- **JSON unmarshalling safety**: `ExtractDockerCompose` uses `json.Unmarshal` — verify strict unmarshalling behavior (unknown fields handling) and that the input is bounds-checked before parsing.
- **Error wrapping with `%w`**: verify that all error returns from `VerifyComposeBinding`, `ExtractDockerCompose`, and Rekor/Sigstore functions use `%w` for proper error chain inspection.
- **Nil/empty slice handling**: verify that `ExtractImageDigests` and `ExtractImageRepositories` handle empty input gracefully (return nil/empty slice, not panic).
- **HTTP client context propagation**: verify that `CheckSigstoreDigests` and `FetchRekorProvenance` respect context cancellation (use `http.NewRequestWithContext`) to prevent hanging requests.
- **Resource cleanup**: verify that all HTTP response bodies are closed on every code path (including error branches after `client.Do()`).

## Cryptography Best-Practice Audit Points

- **SHA-256 for compose binding**: confirm `crypto/sha256.Sum256` is used for the `MRConfigID` hash computation, matching the TDX specification.
- **Constant-time comparison**: `VerifyComposeBinding` uses `subtle.ConstantTimeCompare` for the `MRConfigID` prefix comparison — verify the comparison covers exactly the expected prefix length (33 bytes: 1-byte tag + 32-byte SHA-256).
- **X.509 certificate parsing**: Rekor's `parseFulcioProvenance` parses Fulcio certificates — verify `x509.ParseCertificate` is called on the DER block and that parse errors are treated as hard failures.
- **ASN.1 extension value decoding**: the code decodes Fulcio extension OIDs as ASN.1 UTF8String with a fallback to raw bytes — verify the fallback does not mask encoding errors that could allow OID injection.
- **Base64 decoding**: the Rekor entry body and verifier PEM are base64-decoded — verify standard encoding is used (not URL-safe or raw variants) and that decode errors are handled, not panicked on.
- **No cosign bundle verification**: if the code relies on Sigstore search HTTP status rather than performing full cosign bundle signature verification, document this as a gap — a compromised Sigstore search endpoint could return 200 for any digest.

## General Security Audit Points

- **Trust boundary**: Sigstore and Rekor are external services. The audit MUST evaluate what happens if these services are compromised, spoofed, or subject to DNS hijacking. The `SigstoreSearchBase` and `RekorAPIBase` are package-level `var`s — verify they cannot be overridden in production.
- **Supply chain depth**: the Rekor provenance extraction trusts the OIDC issuer string from the Fulcio certificate extension. If the issuer check is insufficient (e.g., accepts any GitHub Actions issuer rather than a specific repository), a build from a different repository could pass. Document the granularity of the identity check.
- **Defense in depth**: compose binding (enforced, hardware-attested) is the primary control. Sigstore/Rekor checks are the secondary control verifying supply-chain provenance. The audit MUST classify each as primary or secondary and note the residual risk if the secondary control is soft-fail.
- **Input validation**: all data from the attestation response (compose content, image references) is untrusted. Verify that the regex-based extraction cannot be confused by crafted compose content (e.g., image references in comments, multi-line strings, YAML anchors).
- **Denial-of-service**: a compose file with thousands of image references could trigger thousands of Sigstore/Rekor API calls. Verify whether the number of extracted digests is bounded.
- **Fail-secure defaults**: if a new image appears in the compose file that is not in the allowlist, verify this is a hard failure — not a warning that allows the connection to proceed.

## Section Deliverable

Provide:
1. findings-first list ordered by severity,
2. explicit enforcement classification for compose binding vs provenance checks (primary/enforced vs secondary/advisory),
3. `MRConfigID` binding byte-layout verification summary,
4. Sigstore/Rekor outage behavior and soft-fail residual risk statement,
5. image allowlist enforcement completeness assessment,
6. include at least one concrete positive control and one concrete negative/residual-risk observation,
7. source citations for all claims.

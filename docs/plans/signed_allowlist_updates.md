# Plan: Signed Allowlist Updates

Status: proposal, no implementation yet.

## Problem

Some factors pass only against an allowlist: MRSEAM and MRTD in
`tee_measurement`, RTMR0 in `tee_hardware_config`, RTMR1 and RTMR2 in
`tee_boot_config`. teep can enforce such a factor only while its allowlist
holds every value that the provider's fleet runs. The provider changes the
values first: a firmware, kernel or Intel TDX module update produces new
values before a teep release can carry them.

Today the allowlists are Go-coded defaults (`internal/defaults/defaults.go`,
`internal/attestation/dstack_defaults.go`, `internal/provider/chutes/policy.go`).
For each field, the local TOML policy replaces the default when it sets
that field ([measurement allowlists](../measurement_allowlists.md#merge-order)).
A new value reaches a running installation only through a new release or a
manual TOML edit.

Example: Chutes' unsigned measurement feed
(<https://api.chutes.ai/servers/tee/measurements>, fetched 2026-11-11) lists
a sek8s 1.5.0 row for each hardware class. NEAR's reviewed mirror, the
source of teep's Chutes values
([`chutes_golden_measurements.json` at commit 8e708a64](https://github.com/nearai/cloud-api/blob/8e708a64bd097905720760da40ecaf0b556be3eb/crates/services/src/attestation/chutes_golden_measurements.json),
2026-10-12), lists releases up to 1.4.1. Today teep allows
`tee_boot_config` to fail for Chutes (`ChutesDefaultAllowFail` in
`internal/attestation/report.go`), so it serves an instance whatever
release it runs, including any on 1.5.0. The "Enforcement
and allow_fail" section of [AGENTS.md](../../AGENTS.md) enforces a factor
when every instance in the fleet passes it. An allowlist that lacks the
values of a new release keeps such a factor allowed until a teep release
carries them; enforcing it needs a way to deliver new values without a
release.

Signed delivery removes the release delay. It does not decide which source
teep accepts for a value (Open decision 5).

## Proposal

teep's allowlists become one file, the allowlist file, published from the
teep repository and signed with Sigstore. teep fetches it and verifies it
from its bundle, with no query to Rekor.

### Publication

- The allowlist file holds every provider's allowlists, a monotonic
  `version`, and the date of publication. Each value names its source (Open
  decision 5).
- If the project chooses the workflow identity (Open decision 1), a GitHub
  Actions workflow of the teep repository signs the allowlist file with
  Sigstore keyless signing. Fulcio issues a short-lived certificate to the
  workflow's OIDC identity, Rekor v2 logs the signature, and an RFC 3161
  timestamp authority timestamps it. The workflow publishes the
  allowlist file with its bundle (`.sigstore.json`), which carries the leaf
  certificate, the signature, the timestamp, and the Rekor entry with its
  inclusion proof and checkpoint.
- A pull request, reviewed like code, makes each change to the allowlist
  file. The workflow signs only a commit of `main`, and the pinned identity
  names the workflow and that ref (verification step 3).

### Fetch and use

- Each teep release embeds the allowlist file current at release time. Its
  `version` is the lowest `version` that teep accepts.
- teep fetches the allowlist file and its bundle at startup and at a fixed
  interval (Open decision 2), one request at a time, from the host of the
  file. It loads the Sigstore trusted root (`TrustedRoot`, a trust root in
  the sense of [docs/writing_style.md](../writing_style.md)) from
  `tuf-repo-cdn.sigstore.dev` at each fetch, as Tinfoil does.
- An allowlist file that verifies and whose `version` is higher than the
  current one replaces the current list. It can add and remove values,
  including values of the embedded file; a removal is a revocation.
- teep refuses a lower `version` as a rollback and logs it at warn level.
  An equal `version` with the same digest is no change. teep refuses an
  equal `version` with a different digest and logs it at error level: it
  shows a defect of the signing workflow.
- A fetch or verification failure keeps the current list and logs at warn
  level, with the reason and the current `version`. It never removes the
  current list.
- The local TOML policy keeps precedence, as today: the fetched list
  replaces the Go-coded default layer of the merge order. A field that the
  TOML sets replaces the fetched list for that field, so the installation
  gets neither new values nor removals for it.
- `--offline` sends no fetch. Which list it uses depends on Open decision 7.

### Verification of the bundle

The steps follow the Sigstore client specification (§4) and the Rekor v2
specification in github.com/sigstore/architecture-docs (`client-spec.md`,
`rekor-v2-spec.md`, at commit d4da33eb, 2026-05-19, the last commit of both
files when fetched on 2026-11-11). sigstore-go, which teep already uses for
Tinfoil (`internal/provider/tinfoil/sigstore.go`), implements them.

1. Trust root. Load the Sigstore trusted root through TUF
   (`root.FetchTrustedRootWithOptions`, sigstore-go v1.2.1
   `pkg/root/trusted_root.go` lines 414-421, as Tinfoil does at
   `sigstore.go` lines 165-166). It holds the Fulcio, timestamp authority,
   CT log and Rekor keys. The Rekor v2 shard and its key come from the
   trusted root, never from a hardcoded URL: "clients must discover, via
   TUF, the correct shard to upload to and the correct key to verify an
   inclusion proof with" (`rekor-v2-spec.md` §5.2, lines 113-123).
2. Timestamp. Verify the RFC 3161 timestamp against the timestamp
   authority's key material, over the signature bytes (`client-spec.md`
   §4.2.1, line 225). Rekor v2 returns no signed entry timestamp, so the
   bundle must carry this timestamp (`rekor-v2-spec.md` §4.2, lines
   64-71).
3. Certificate. Validate the certificate path to the Fulcio root with the
   timestamp as the current time (`client-spec.md` §4.3, line 244). Verify
   the embedded SCT with the CT log key (line 246). Check the identity
   against the pinned signer, as exact values, not patterns: the Issuer
   `https://token.actions.githubusercontent.com` (OID
   1.3.6.1.4.1.57264.1.8) and the SubjectAlternativeName
   `https://github.com/<org>/teep/.github/workflows/<file>@refs/heads/main`
   (line 248).
4. Transparency log entry. Rebuild the entry from the bundle's digest,
   signature and certificate, and hash it. Verify the checkpoint signature
   against the Rekor key and server name. Verify the inclusion proof of that
   hash against the checkpoint root (RFC 6962) (`rekor-v2-spec.md` §6.1.4,
   lines 170-182; §7.2, lines 233-241; `client-spec.md` §4.4, lines
   252-258). sigstore-go checks the checkpoint signature
   (`pkg/verify/tlog.go` lines 131-141); the bundle verification of
   sigstore-java before 1.2.0 did not
   ([CVE-2024-54140](https://github.com/advisories/GHSA-jp26-88mw-89qr)). teep does not verify witness co-signatures: sigstore-go
   checks only the log's checkpoint signature, and the specification makes
   them optional for a verifying client (`rekor-v2-spec.md` §7.2, line 241).
5. Signature. Verify the signature over the allowlist file with the leaf
   certificate's key (`client-spec.md` §4.5, line 282).

In sigstore-go: `verify.NewVerifier(trustedRoot,
verify.WithSignedTimestamps(1), verify.WithSignedCertificateTimestamps(1),
verify.WithTransparencyLog(1))` (`pkg/verify/signed_entity.go` lines 89,
127, 185 and 157). Without `WithSignedCertificateTimestamps`, sigstore-go
does not check the SCT (lines 678-683); Tinfoil sets it (`sigstore.go` line
191). `Verify` takes `verify.NewPolicy(verify.WithArtifact(...),
verify.WithCertificateIdentity(...))` (lines 492 and 433). For a Rekor v2
entry, sigstore-go requires an inclusion proof (`pkg/verify/tlog.go` lines
102-104).

**Does a complete bundle need a network call?** No. The client
specification takes as input only the bundle and the root key material
from the policy (`client-spec.md` §4.1, lines 197-207). It says that newer
clients SHOULD NOT offer online verification of Rekor v2 entries (§4.6, line
294). The Rekor v2 specification says that a verifier SHOULD use the
verification material of the signing client "without performing an online
query of the transparency log" (§4.1, lines 56-62), and that a verifying
client "uses the material it is provided with and the public key of the
log" (§7.2, lines 223-241). In sigstore-go, `VerifyTlogEntry`
(`pkg/verify/tlog.go` lines 48-142) uses only the bundle and the trusted
root; it sends no request.

The design therefore sends two kinds of request: the fetch of the allowlist
file and its bundle, and the TUF fetch of the trusted root. Verification
sends no request to Rekor. It needs the trusted root, and
`tuf.DefaultOptions()` leaves the cache validity at its default of 0
(`pkg/tuf/options.go` lines 42-49 and 131-148), so each load contacts the
TUF repository: an outage of `tuf-repo-cdn.sigstore.dev` stops verification
of a new allowlist file, and teep keeps the current list.

What this cannot tell: these are the texts and the code at the stated
versions. Phase 2 tests real bundles of the public instance.

## Constraints of the public Sigstore instance

Checked on 2026-11-10. Source and date per item.

- Rekor v2 reads: a CDN serves the tiles, which clients can cache, and the
  service supports a higher read rate. Rekor v2 returns the inclusion proof
  at upload; the read API is not for computing proofs
  ([Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/), 2025-10-10). The
  design reads no tile: the proof is in the bundle.
- Rate limits: a search of the Sigstore documentation and blog on
  2026-11-10 found no published rate limit for reads, Fulcio issuance or
  Rekor upload. Fulcio certificates are valid for 10 minutes
  ([Fulcio overview](https://docs.sigstore.dev/certificate_authority/overview/),
  checked 2026-11-11). The design signs
  once per published allowlist file and reads nothing from Rekor at
  runtime.
- Service level: a 99.5% availability objective with on-call, not a
  contractual SLA
  ([Sigstore GA](https://blog.sigstore.dev/sigstore-ga-ddd6ba67894d/),
  2022-10-25; [logging overview](https://docs.sigstore.dev/logging/overview/)).
  Status page: status.sigstore.dev. An outage stops signing and the TUF
  fetch, not the verification of an allowlist file already loaded.
- Trust root: `tuf-repo-cdn.sigstore.dev`, GCS behind a CDN. The project
  documents no refresh interval for clients; sigstore-go's
  `LiveTrustedRoot` uses 24 hours (`pkg/root/trusted_root.go` line 475).
  TUF distributes the Rekor v2 shard URLs, which change about every six
  months; never hardcode them
  ([rekor-tiles README](https://github.com/sigstore/rekor-tiles), checked
  2026-11-10).
- Scale: about 20 million new Rekor entries per week
  ([rekor-tiles wiki](https://github.com/sigstore/rekor-tiles/wiki/Client-statistics),
  2026-02-12). The design adds one entry for each published allowlist
  file.

## Open decisions

1. **Signer identity.** The identity of a GitHub Actions workflow of the
   teep repository, or a maintainer's identity (a person signs each
   allowlist file). The workflow identity ties the file to a reviewed
   commit of `main`; a maintainer identity ties it to a person.
   Recommended: the workflow identity.
2. **Fetch interval.** Recommended: at startup and every 6 hours. A shorter
   interval delivers revocations sooner; each fetch is one request to the
   host of the file and one to the TUF repository.
3. **Host of the file.** A GitHub release asset or the raw file of a tag in
   the teep repository, or a separate host. The host is not trusted: the
   bundle authenticates the file. Recommended: a GitHub release asset of
   the teep repository.
4. **Review of removals.** A removal revokes a value that installations
   accept. Recommended: a removal names the reason and the evidence, and a
   second reviewer approves it.
5. **Source per value.** Whether each value records its trusted source: for
   example the provider's unsigned feed with the content hash of the
   fetched copy, or a reviewed mirror such as NEAR's file at a commit. For
   Chutes the question is open: whether teep takes values from Chutes'
   unsigned feed, pinned by the content hash of each fetched copy, or waits
   for NEAR's mirror. Recommended: record the source and
   its content hash or commit for every value.
6. **Maximum age of the list.** A party that blocks the fetch keeps
   installations on an old list: no new values, and no revocation. Options:
   no expiry (the current list stays valid, and the log shows its age); a
   maximum age after which teep logs at error level; or a maximum age after
   which teep fails the factors that use the list. Failing them is
   fail-closed, but it turns a fetch outage into a service outage.
   Recommended: a maximum age that logs at error level.
7. **Persistence.** Whether teep keeps the last verified allowlist file and
   bundle on disk and verifies them again at startup. Without it, a restart
   goes back to the embedded file: a restart without network loses newer
   values, and the host can serve any older signed file whose `version` is
   above the embedded one, which undoes later removals. Persistence also
   decides whether `--offline` uses the stored file or the embedded file.
   Recommended: persist, verify again at startup, and use the stored file
   with `--offline`.

## Relation to other work

- **Fixtures.** A live capture with signed, content-addressed records must
  keep every signed record, so teep cannot reduce its size; where such
  captures live is a separate open question for the repository. A replay
  must verify against the list that applied at capture time, or a later
  removal fails an old fixture. The capture manifest records the `version`
  and the digest of the allowlist file, and replay uses that file; a place
  that keeps captures outside the repository can also keep the published
  files with their bundles.
- **Measurement allowlists.** The
  [cross-check](../measurement_allowlists.md#2-cross-check-values) and
  [rolling update](../measurement_allowlists.md#rolling-updates) procedures
  become the review of a pull request to the allowlist file: add the new
  values before a rollout, and remove the old values after it. The
  `--update-config` command, which creates a first allowlist from observed
  values, stays a local tool; its output is a local TOML policy, not the
  published file.
- **Enforcement rule.** The "Enforcement and allow_fail" section of
  [AGENTS.md](../../AGENTS.md) enforces a factor when every instance passes
  it. With this delivery path, a missing allowlist value no longer needs a
  release; a factor still needs live fleet data that shows every instance
  passes it before it is enforced.

## Phases (one commit each, after the decisions)

1. The allowlist file format, the embedded file generated from it, and the
   merge order; no fetch. The Go-coded defaults move into the file.
2. The signing workflow, run on a test file, and the bundle verification
   with sigstore-go and the pinned identity; unit tests with bundles
   recorded from that workflow and with changed bundles (signature,
   identity, checkpoint, inclusion proof, timestamp, SCT).
3. The fetch, the `version` rule, the failure behavior, and the decisions
   on the maximum age and persistence; concurrency tests for the
   replacement of the list under load.
4. The publication of the allowlist file; documentation in
   `measurement_allowlists.md`.

package venice

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// aciResponse is the JSON structure returned by Venice's ACI/1 attestation
// format (api_version == "aci/1", vendor "private-ai-gateway-dev"). ACI/1
// includes both a new nested "attestation" block (workload keyset,
// keyset endorsement, source provenance, evidence) and dstack-compatible
// top-level fields (nonce, model, verified, intel_quote, etc.).
//
// ACI/1 has no docker-compose manifest — there is no app_compose/compose_hash
// analog. Supply-chain provenance is expressed instead as a git
// source_provenance (repo_url/repo_commit) plus a cryptographically
// endorsed workload_keyset; see keyset.go for the endorsement verification.
type aciResponse struct {
	// ACI/1-specific fields.
	APIVersion           string         `json:"api_version"`
	WorkloadID           string         `json:"workload_id"`
	WorkloadKeysetDigest string         `json:"workload_keyset_digest"`
	Attestation          aciAttestation `json:"attestation"`
	ServiceCapabilities  aciServiceCaps `json:"service_capabilities"`

	// dstack-compatible top-level fields.
	Verified           bool                `json:"verified"`
	Nonce              string              `json:"nonce"`
	Model              string              `json:"model"`
	TEEProvider        string              `json:"tee_provider"`
	SigningKey         string              `json:"signing_public_key"`
	SigningAddress     string              `json:"signing_address"`
	IntelQuote         string              `json:"intel_quote"`
	NvidiaPayload      string              `json:"nvidia_payload"`
	ServerVerification *ServerVerification `json:"server_verification"`
	UpstreamModel      string              `json:"upstream_model"`
	SigningAlgo        string              `json:"signing_algo"`
	TEEHardware        string              `json:"tee_hardware"`
	NonceSource        string              `json:"nonce_source"`
	CandidatesAvail    int                 `json:"candidates_available"`
	CandidatesEval     int                 `json:"candidates_evaluated"`
}

// aciServiceCaps holds service capability declarations.
type aciServiceCaps struct {
	SupportedE2EEVersions []string `json:"supported_e2ee_versions"`
}

// aciAttestation holds the nested "attestation" object in ACI/1 responses.
type aciAttestation struct {
	Vendor            string               `json:"vendor"`
	TEEType           string               `json:"tee_type"`
	WorkloadKeyset    aciWorkloadKeyset    `json:"workload_keyset"`
	ReportData        string               `json:"report_data"`
	KeysetEndorsement aciKeysetEndorsement `json:"keyset_endorsement"`
	SourceProvenance  aciSourceProvenance  `json:"source_provenance"`
	Freshness         aciFreshness         `json:"freshness"`
	Evidence          aciEvidence          `json:"evidence"`
}

// aciWorkloadKeyset holds the workload_keyset object in ACI/1 responses: the
// workload identity key plus the receipt-signing, E2EE, and TLS public keys
// it endorses. See keyset.go for JCS canonicalization and endorsement
// signature verification.
type aciWorkloadKeyset struct {
	WorkloadIdentity   aciWorkloadIdentity `json:"workload_identity"`
	KeysetEpoch        aciKeysetEpoch      `json:"keyset_epoch"`
	ReceiptSigningKeys []aciKey            `json:"receipt_signing_keys"`
	E2EEPublicKeys     []aciKey            `json:"e2ee_public_keys"`
	TLSPublicKeys      []aciTLSBinding     `json:"tls_public_keys"`
}

// aciWorkloadIdentity holds the workload_identity object.
type aciWorkloadIdentity struct {
	PublicKey aciPublicKey `json:"public_key"`
	Subject   *string      `json:"subject"` // nullable
}

// aciPublicKey holds an algorithm + public key pair.
type aciPublicKey struct {
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

// aciKeysetEpoch holds keyset epoch metadata. NotAfter uses json.Number
// because the wire value may be a float64-rounded representation of u64::MAX
// (e.g. 18446744073709552000) which exceeds uint64 range. The raw JSON number
// is preserved as-is for JCS canonicalization; see keyset.go.
type aciKeysetEpoch struct {
	Version  int         `json:"version"`
	NotAfter json.Number `json:"not_after"`
}

// aciKey holds a named cryptographic key entry.
type aciKey struct {
	KeyID     string `json:"key_id"`
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

// aciKeysetEndorsement holds the keyset endorsement signature.
type aciKeysetEndorsement struct {
	Algo  string `json:"algo"`
	Value string `json:"value"`
}

// aciFreshness holds attestation freshness timestamps.
type aciFreshness struct {
	FetchedAt  int64 `json:"fetched_at"`
	StaleAfter int64 `json:"stale_after"`
}

// aciSourceProvenance holds the source_provenance object in ACI/1 responses.
// ACI/1's supply-chain provenance is expressed as a git repo + commit rather
// than a docker-compose manifest; image_digest/image_provenance are declared
// nullable because Venice does not currently publish verifiable image
// digests for ACI/1 workloads.
type aciSourceProvenance struct {
	RepoURL         string  `json:"repo_url"`
	RepoCommit      string  `json:"repo_commit"`
	ImageDigest     *string `json:"image_digest"`     // nullable
	ImageProvenance *string `json:"image_provenance"` // nullable
}

// aciKeyCustody holds the key_custody object in ACI/1 responses.
type aciKeyCustody struct {
	Provider string          `json:"provider"`
	Keys     []aciCustodyKey `json:"keys"`
}

// aciCustodyKey holds one entry in the key_custody.keys array.
type aciCustodyKey struct {
	Role           string   `json:"role"`
	Path           string   `json:"path"`
	Purpose        string   `json:"purpose"`
	Algo           string   `json:"algo"`
	PublicKey      string   `json:"public_key"`
	SignatureChain []string `json:"signature_chain"`
}

// aciTLSBinding holds a domain + SPKI hash pair (used in both
// downstream_tls_binding and workload_keyset.tls_public_keys). teep never
// connects to the domains these entries name (the gateway does), so no live
// SPKI comparison is possible; their integrity is covered by the keyset
// endorsement check in keyset.go.
type aciTLSBinding struct {
	Domain     string `json:"domain"`
	SPKISHA256 string `json:"spki_sha256"`
}

// aciEvidence holds the evidence object in ACI/1 responses.
type aciEvidence struct {
	Quote                string           `json:"quote"`
	QuoteReportData      string           `json:"quote_report_data"`
	EventLog             eventLogFlexible `json:"event_log"`
	VMConfig             string           `json:"vm_config"`
	KeyCustody           aciKeyCustody    `json:"key_custody"`
	DownstreamTLSBinding aciTLSBinding    `json:"downstream_tls_binding"`
}

// parseACI unmarshals a Venice ACI/1-format attestation JSON response body
// into a RawAttestation.
func parseACI(ctx context.Context, body []byte) (*attestation.RawAttestation, error) {
	var ar aciResponse
	unknown, missing, err := jsonstrict.UnmarshalWarn(body, &ar, "venice aci/1 attestation")
	if err != nil {
		return nil, fmt.Errorf("venice aci/1: unmarshal attestation response: %w", err)
	}
	return aciToRaw(ctx, &ar, unknown, missing, body), nil
}

// aciToRaw converts a parsed ACI/1 attestation response to RawAttestation.
// ACI/1 includes dstack-compatible top-level fields (nonce, model, verified,
// etc.) alongside the new nested "attestation" block. The event log comes
// from the nested evidence object rather than the top level; the TDX quote
// binding (REPORTDATA) is the same keccak256(signing key)+nonce scheme dstack
// uses, so venice.ReportDataVerifier is reused unchanged for ACI/1 — see the
// comment on ReportDataVerifier in reportdata.go.
func aciToRaw(ctx context.Context, ar *aciResponse, unknown, missing []string, body []byte) *attestation.RawAttestation {
	logEventLog(ctx, ar.Attestation.Evidence.EventLog)
	return &attestation.RawAttestation{
		BackendFormat:   attestation.FormatACI1,
		Verified:        ar.Verified,
		Nonce:           ar.Nonce,
		Model:           ar.Model,
		TEEProvider:     ar.TEEProvider,
		SigningKey:      ar.SigningKey,
		SigningAddress:  ar.SigningAddress,
		IntelQuote:      ar.IntelQuote,
		NvidiaPayload:   ar.NvidiaPayload,
		TEEHardware:     ar.TEEHardware,
		SigningAlgo:     ar.SigningAlgo,
		UpstreamModel:   ar.UpstreamModel,
		NonceSource:     ar.NonceSource,
		CandidatesAvail: ar.CandidatesAvail,
		CandidatesEval:  ar.CandidatesEval,
		EventLog:        ar.Attestation.Evidence.EventLog,
		EventLogCount:   len(ar.Attestation.Evidence.EventLog),

		// ACI/1 has no app_compose/compose_hash — AppCompose, ComposeHash,
		// and AppName stay empty so the compose-based supply-chain factors
		// (compose_binding, sigstore_verification, build_transparency_log,
		// provider_signer_recognition, component_signature_recognition)
		// evaluate to Fail rather than being hidden as NotApplicable.
		ACISourceRepoURL:        ar.Attestation.SourceProvenance.RepoURL,
		ACIWorkloadID:           ar.WorkloadID,
		ACIWorkloadKeysetDigest: ar.WorkloadKeysetDigest,
		ACIKeysetEndorsementSig: ar.Attestation.KeysetEndorsement.Value,
		ACIIdentityKeyHex:       ar.Attestation.WorkloadKeyset.WorkloadIdentity.PublicKey.PublicKey,
		ACIWorkloadKeyset:       &ar.Attestation.WorkloadKeyset,

		UnknownFields: unknown,
		MissingFields: missing,
		RawBody:       body,
	}
}

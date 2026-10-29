package aci

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// aciResponse is the JSON structure returned by Venice's ACI/1 attestation
// format (api_version == "aci/1"). ACI/1 includes both a nested
// "attestation" block (workload keyset, source provenance, evidence) and
// dstack-compatible top-level fields (nonce, model, verified, intel_quote,
// etc.).
//
// SEE: spec/aci.md in https://github.com/Dstack-TEE/private-ai-gateway —
// the attested workload named by attestation.source_provenance.repo_url.
type aciResponse struct {
	// ACI/1-specific fields.
	APIVersion           string         `json:"api_version"`
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

	// AllAttestations is the gateway variant's list of attestation objects.
	// teep accepts exactly one entry, equal to the top-level fields
	// (SEE: checkAllAttestations). A nil value means the field is absent
	// (the Venice variant); an empty list is present and fails the check.
	AllAttestations []json.RawMessage `json:"all_attestations,omitempty"`
}

// veniceEchoFields are the dstack-compatible top-level fields that the Venice
// variant of the response carries and the gateway variant omits. In a gateway
// variant response they are not reported as missing.
var veniceEchoFields = map[string]bool{
	"verified": true, "nonce": true, "model": true, "tee_provider": true,
	"server_verification": true, "upstream_model": true, "tee_hardware": true,
	"nonce_source": true, "candidates_available": true, "candidates_evaluated": true,
}

// ServerVerification holds the gateway-level verification result of a Venice response.
// The gateway re-verifies the TDX quote and reports its findings; this is
// an untrusted claim (the gateway is not hardware-attested itself).
type ServerVerification struct {
	TDX struct {
		Valid                 bool   `json:"valid"`
		SignatureValid        bool   `json:"signatureValid"`
		CertificateChainValid bool   `json:"certificateChainValid"`
		RootCAPinned          bool   `json:"rootCaPinned"`
		AttestationKeyMatch   bool   `json:"attestationKeyMatch"`
		ReportData            string `json:"reportData"`
		Measurements          struct {
			MRTD          string `json:"mrtd"`
			MRConfigID    string `json:"mrconfigid"`
			MROwner       string `json:"mrowner"`
			MROwnerConfig string `json:"mrownerconfig"`
			RTMR0         string `json:"rtmr0"`
			RTMR1         string `json:"rtmr1"`
			RTMR2         string `json:"rtmr2"`
			RTMR3         string `json:"rtmr3"`
			TDAttributes  string `json:"tdAttributes"`
			XFAM          string `json:"xfam"`
		} `json:"measurements"`
		CRLCheck struct {
			Checked bool `json:"checked"`
			Revoked bool `json:"revoked"`
		} `json:"crlCheck"`
	} `json:"tdx"`
	Nvidia struct {
		Valid             bool `json:"valid"`
		SignatureVerified bool `json:"signatureVerified"`
		CertificateChain  struct {
			Valid              bool   `json:"valid"`
			IntermediatePinned bool   `json:"intermediatePinned"`
			LeafCertExpiry     string `json:"leafCertExpiry"`
		} `json:"certificateChainStatus"`
	} `json:"nvidia"`
	SigningAddressBinding struct {
		Bound             bool   `json:"bound"`
		ReportDataAddress string `json:"reportDataAddress"`
	} `json:"signingAddressBinding"`
	NonceBinding struct {
		Bound  bool   `json:"bound"`
		Method string `json:"method"`
	} `json:"nonceBinding"`
	NvidiaNonceBinding struct {
		Bound  bool   `json:"bound"`
		Method string `json:"method"`
	} `json:"nvidiaNonceBinding"`
	VerifiedAt             string `json:"verifiedAt"`
	VerificationDurationMs int    `json:"verificationDurationMs"`
}

// aciServiceCaps holds service capability declarations. Serving is
// "aggregator" when the service forwards to upstream inference hosts and
// "direct" when inference runs inside the attested workload.
type aciServiceCaps struct {
	SupportedE2EEVersions []string `json:"supported_e2ee_versions"`
	Serving               string   `json:"serving"`
}

// aciAttestation holds the nested "attestation" object in ACI/1 responses.
type aciAttestation struct {
	TEEType          string              `json:"tee_type"`
	WorkloadKeyset   aciWorkloadKeyset   `json:"workload_keyset"`
	ReportData       string              `json:"report_data"`
	SourceProvenance aciSourceProvenance `json:"source_provenance"`
	Evidence         aciEvidence         `json:"evidence"`
}

// aciWorkloadKeyset holds the workload_keyset object in ACI/1 responses: the
// receipt-signing, E2EE, and TLS public keys the workload serves under. The
// declared workload_keyset_digest is sha256 over the JCS canonicalization of
// this object; see keyset.go.
type aciWorkloadKeyset struct {
	Subject            *string         `json:"subject"` // nullable
	NotAfter           json.Number     `json:"not_after"`
	ReceiptSigningKeys []aciKey        `json:"receipt_signing_keys"`
	E2EEPublicKeys     []aciKey        `json:"e2ee_public_keys"`
	TLSPublicKeys      []aciTLSBinding `json:"tls_public_keys"`
}

// aciKey holds a named cryptographic key entry.
type aciKey struct {
	KeyID     string `json:"key_id"`
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

// aciSourceProvenance holds the source_provenance object in ACI/1 responses.
// ACI/1's supply-chain provenance is a git repo + commit; image_digest and
// image_provenance are declared nullable because Venice does not currently
// publish them. These fields are not bound into the quote; the quote-bound
// provenance is the gateway app_compose (evidence.app_compose), whose hash
// the quote's MRConfigID and RTMR3 compose-hash event measure.
type aciSourceProvenance struct {
	RepoURL         string  `json:"repo_url"`
	RepoCommit      string  `json:"repo_commit"`
	ImageDigest     *string `json:"image_digest"`     // nullable
	ImageProvenance *string `json:"image_provenance"` // nullable
}

// aciKeyCustody holds the key_custody object in ACI/1 responses: the
// dstack-KMS derivation record for each workload key. See keyset.go for the
// signature-chain verification that connects these keys to an accepted KMS
// root.
type aciKeyCustody struct {
	Provider string          `json:"provider"`
	Keys     []aciCustodyKey `json:"keys"`
}

// aciCustodyKey holds one entry in the key_custody.keys array.
// SignatureChain carries two 65-byte recoverable secp256k1 signatures:
// [0] by the app key over "{purpose}:{compressed kms_public_key}", and
// [1] by the KMS root over "dstack-kms-issued:" || app_id || compressed app
// key. SEE: verifyKeyCustody in keyset.go.
type aciCustodyKey struct {
	Role           string   `json:"role"`
	Path           string   `json:"path"`
	Purpose        string   `json:"purpose"`
	Algo           string   `json:"algo"`
	PublicKey      string   `json:"public_key"`
	KMSPublicKey   string   `json:"kms_public_key"`
	SignatureChain []string `json:"signature_chain"`
}

// aciTLSBinding holds a domain + SPKI hash pair (used in both
// downstream_tls_binding and workload_keyset.tls_public_keys). teep never
// connects to the domains these entries name (the gateway does), so no live
// SPKI comparison is possible; their integrity is covered by the keyset
// digest check in keyset.go.
type aciTLSBinding struct {
	Domain     string `json:"domain"`
	SPKISHA256 string `json:"spki_sha256"`
}

// aciEvidence holds the evidence object in ACI/1 responses. EventLog,
// VMConfig, and AppCompose arrive as JSON-encoded strings; the event log is
// decoded here, the compose manifest is passed through for the existing
// dstack compose-binding verification.
type aciEvidence struct {
	Quote                string        `json:"quote"`
	QuoteReportData      string        `json:"quote_report_data"`
	EventLog             string        `json:"event_log"`
	VMConfig             string        `json:"vm_config"`
	AppCompose           string        `json:"app_compose"`
	KeyCustody           aciKeyCustody `json:"key_custody"`
	DownstreamTLSBinding aciTLSBinding `json:"downstream_tls_binding"`
}

// Parse unmarshals an ACI/1-format attestation JSON response body into a
// RawAttestation. provider names the provider in diagnostics and errors.
//
// Two variants of the response exist. The Venice variant carries
// dstack-compatible top-level fields (nonce, model, verified, ...). The
// gateway variant omits them and adds all_attestations, which must hold
// exactly one entry equal to the top-level fields; any other content fails
// the parse. A field that neither variant defines is reported as unknown in a
// Venice variant response, and fails the parse of a gateway variant response,
// because the entry does not carry it.
func Parse(ctx context.Context, body []byte, provider string) (*attestation.RawAttestation, error) {
	var ar aciResponse
	unknown, missing, err := jsonstrict.Unmarshal(body, &ar)
	if err != nil {
		return nil, fmt.Errorf("%s aci/1: unmarshal attestation response: %w", provider, err)
	}
	if ar.AllAttestations != nil {
		if err := checkAllAttestations(body, ar.AllAttestations); err != nil {
			return nil, fmt.Errorf("%s aci/1: %w", provider, err)
		}
		missing = slices.DeleteFunc(missing, func(name string) bool { return veniceEchoFields[name] })
	}
	label := provider + " aci/1 attestation"
	if len(unknown) > 0 {
		slog.WarnContext(ctx, "unexpected JSON fields", "fields", unknown, "label", label)
	}
	if len(missing) > 0 {
		slog.WarnContext(ctx, "missing JSON fields", "fields", missing, "label", label)
	}
	return aciToRaw(ctx, &ar, unknown, missing, body, provider)
}

// checkAllAttestations requires the gateway variant's all_attestations to
// hold exactly one entry whose fields are the top-level fields of the
// response, other than all_attestations, with equal values. The entry is a
// second copy of the attested data; a different copy would leave the
// verifier to choose which one is attested.
func checkAllAttestations(body []byte, entries []json.RawMessage) error {
	if len(entries) != 1 {
		return fmt.Errorf("all_attestations has %d entries, want exactly 1", len(entries))
	}
	top, err := canonicalFields(body)
	if err != nil {
		return fmt.Errorf("canonicalize response: %w", err)
	}
	delete(top, "all_attestations")
	entry, err := canonicalFields(entries[0])
	if err != nil {
		return fmt.Errorf("canonicalize all_attestations[0]: %w", err)
	}
	for name := range entry {
		if _, ok := top[name]; !ok {
			return fmt.Errorf("all_attestations[0].%s is not a top-level field", name)
		}
	}
	for name, value := range top {
		other, ok := entry[name]
		if !ok {
			return fmt.Errorf("all_attestations[0] has no %s field", name)
		}
		if subtle.ConstantTimeCompare(value, other) != 1 {
			return fmt.Errorf("all_attestations[0].%s differs from the top-level field", name)
		}
	}
	return nil
}

// canonicalFields decodes a JSON object and re-encodes each member value in
// one form (object keys sorted, numbers kept as written), so that two
// encodings of the same value compare equal.
func canonicalFields(object []byte) (map[string][]byte, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(object, &members); err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(members))
	for name, raw := range members {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("member %s: %w", name, err)
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("member %s: %w", name, err)
		}
		out[name] = canonical
	}
	return out, nil
}

// LogEventLog logs TDX RTMR event log entries at debug level. provider names
// the provider in the summary record.
func LogEventLog(ctx context.Context, entries []attestation.EventLogEntry, provider string) {
	slog.DebugContext(ctx, provider+" event log", "entries", len(entries))
	for i, e := range entries {
		digest := e.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}
		slog.DebugContext(ctx, "event log entry", "index", i, "imr", e.IMR,
			"event", e.Event, "type", e.EventType, "digest", digest)
	}
}

// aciToRaw converts a parsed ACI/1 attestation response to RawAttestation.
// ACI/1 includes dstack-compatible top-level fields (nonce, model, verified,
// etc.) alongside the nested "attestation" block.
//
// The attested CVM is the private-ai-gateway, not the machine serving
// inference: its vm_config reports zero GPUs, it pins a downstream TLS hop,
// service_capabilities.serving is "aggregator", and its KMS key paths carry
// no model component. The TDX quote, event log, and app_compose therefore
// populate the Gateway* fields and are verified in the gateway tier
// (Tier 4); the core fields stay empty and the core tee_* factors fail,
// stating that teep has no CPU attestation of the inference host.
// TEEHardware is cleared for the same reason — the report must not present
// the gateway's platform as the model endpoint's.
//
// The quote's REPORTDATA binding is the same keccak256(signing key)+nonce
// scheme dstack uses, so venice.ReportDataVerifier is reused unchanged for
// the gateway quote — see the comment on ReportDataVerifier in
// internal/provider/venice/reportdata.go.
func aciToRaw(ctx context.Context, ar *aciResponse, unknown, missing []string, body []byte, provider string) (*attestation.RawAttestation, error) {
	// The gateway TDX quote is the whole of the CPU evidence for ACI/1 — the
	// core tee_* factors are waived on the premise that Tier 4 carries it. An
	// empty quote would build no gateway tier and produce a report with no
	// enforced factor that needs a quote, so reject it here (defense in
	// depth: unverifiedEvidence also fails a nil GatewayTDX for ACI/1).
	if ar.Attestation.Evidence.Quote == "" {
		return nil, fmt.Errorf("%s aci/1: attestation.evidence.quote is empty", provider)
	}
	var eventLog []attestation.EventLogEntry
	if ar.Attestation.Evidence.EventLog != "" {
		if err := json.Unmarshal([]byte(ar.Attestation.Evidence.EventLog), &eventLog); err != nil {
			return nil, fmt.Errorf("%s aci/1: decode evidence.event_log: %w", provider, err)
		}
	}
	LogEventLog(ctx, eventLog, provider)
	if ar.IntelQuote != ar.Attestation.Evidence.Quote {
		// The top-level intel_quote is documented as an echo of
		// attestation.evidence.quote. A divergence means the response is not
		// what the format promises; the nested field is the attested source.
		slog.WarnContext(ctx, provider+" aci/1: top-level intel_quote differs from attestation.evidence.quote; using the nested field")
	}
	return &attestation.RawAttestation{
		BackendFormat:   attestation.FormatACI1,
		Verified:        ar.Verified,
		Nonce:           ar.Nonce,
		Model:           ar.Model,
		TEEProvider:     ar.TEEProvider,
		SigningKey:      ar.SigningKey,
		SigningAddress:  ar.SigningAddress,
		NvidiaPayload:   ar.NvidiaPayload,
		SigningAlgo:     ar.SigningAlgo,
		UpstreamModel:   ar.UpstreamModel,
		NonceSource:     ar.NonceSource,
		CandidatesAvail: ar.CandidatesAvail,
		CandidatesEval:  ar.CandidatesEval,

		// Gateway evidence: the quote, event log, and compose manifest
		// describe the private-ai-gateway CVM. GatewayNonceHex carries the
		// echoed client nonce that the gateway quote's REPORTDATA binds.
		// GatewayAppCompose feeds the existing dstack compose binding:
		// sha256(app_compose) must match the quote's MRConfigID.
		GatewayIntelQuote: ar.Attestation.Evidence.Quote,
		GatewayEventLog:   eventLog,
		GatewayNonceHex:   ar.Nonce,
		GatewayAppCompose: ar.Attestation.Evidence.AppCompose,

		// The model-tier compose fields stay empty: ACI/1 publishes no
		// manifest for the machine serving inference, so the model-tier
		// supply-chain factors evaluate to Fail rather than being hidden as
		// NotApplicable.
		ACISourceRepoURL:        ar.Attestation.SourceProvenance.RepoURL,
		ACIWorkloadKeysetDigest: ar.WorkloadKeysetDigest,
		ACIWorkloadKeyset:       &ar.Attestation.WorkloadKeyset,
		ACIKeyCustody:           &ar.Attestation.Evidence.KeyCustody,
		ACIDownstreamTLSDomain:  ar.Attestation.Evidence.DownstreamTLSBinding.Domain,
		ACIDownstreamTLSSPKI:    ar.Attestation.Evidence.DownstreamTLSBinding.SPKISHA256,

		UnknownFields: unknown,
		MissingFields: missing,
		RawBody:       body,
	}, nil
}

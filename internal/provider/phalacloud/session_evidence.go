package phalacloud

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/chutes"
)

// Verifier ids of the sessions whose evidence teep verifies. A session of
// another verifier is not pinned.
const (
	verifierPhalaDirect = "private-ai-verifier/phala-direct/v1"
	verifierChutes      = "private-ai-verifier/chutes/v1"
)

// sessionEvidence is the evidence of one attested session in the form of
// teep's verifiers: the upstream attestation, the nonce of the gateway's
// evidence request, and the REPORTDATA scheme of the upstream.
type sessionEvidence struct {
	raw        *attestation.RawAttestation
	nonce      attestation.Nonce
	reportData provider.ReportDataVerifier
}

// sessionEvidenceOf parses the evidence of s and checks that the session's
// channel binding and identity name the key in that evidence. The checks of
// the evidence itself (quote, REPORTDATA, GPU evidence) follow in the audit.
func sessionEvidenceOf(ctx context.Context, s *aci.Session) (*sessionEvidence, error) {
	if s.Evidence == nil {
		return nil, errors.New("session has no evidence")
	}
	switch s.VerifierID {
	case verifierPhalaDirect:
		return phalaDirectEvidence(s)
	case verifierChutes:
		return chutesSessionEvidence(ctx, s)
	default:
		return nil, fmt.Errorf("teep does not verify the evidence of %s", s.VerifierID)
	}
}

// phalaDirectReport is the dstack attestation report of the Phala model CVM
// as the gateway's verifier consumed it. all_attestations repeats the
// report as its single entry.
type phalaDirectReport struct {
	AllAttestations []phalaDirectAttestation `json:"all_attestations"`
	phalaDirectAttestation
}

// phalaDirectAttestation holds the members of the report other than
// all_attestations.
type phalaDirectAttestation struct {
	EventLog           string          `json:"event_log"`
	Info               phalaDirectInfo `json:"info"`
	IntelQuote         string          `json:"intel_quote"`
	NvidiaPayload      string          `json:"nvidia_payload"`
	Quote              string          `json:"quote"`
	RequestNonce       string          `json:"request_nonce"`
	SigningAddress     string          `json:"signing_address"`
	SigningAlgo        string          `json:"signing_algo"`
	SigningPublicKey   string          `json:"signing_public_key"`
	TLSCertFingerprint string          `json:"tls_cert_fingerprint"`
	Version            int             `json:"version"`
	VMConfig           string          `json:"vm_config"`
}

type phalaDirectInfo struct {
	AppCert         string             `json:"app_cert"`
	AppID           string             `json:"app_id"`
	AppName         string             `json:"app_name"`
	ComposeHash     string             `json:"compose_hash"`
	DeviceID        string             `json:"device_id"`
	InstanceID      string             `json:"instance_id"`
	KeyProviderInfo string             `json:"key_provider_info"`
	MRAggregated    string             `json:"mr_aggregated"`
	OSImageHash     string             `json:"os_image_hash"`
	TCBInfo         phalaDirectTCBInfo `json:"tcb_info"`
	VMConfig        string             `json:"vm_config"`
}

type phalaDirectTCBInfo struct {
	AppCompose   string                      `json:"app_compose"`
	ComposeHash  string                      `json:"compose_hash"`
	DeviceID     string                      `json:"device_id"`
	EventLog     []attestation.EventLogEntry `json:"event_log"`
	MRAggregated string                      `json:"mr_aggregated"`
	MRTD         string                      `json:"mrtd"`
	OSImageHash  string                      `json:"os_image_hash"`
	RTMR0        string                      `json:"rtmr0"`
	RTMR1        string                      `json:"rtmr1"`
	RTMR2        string                      `json:"rtmr2"`
	RTMR3        string                      `json:"rtmr3"`
}

// phalaDirectEvidence parses the JSON evidence of a phala-direct session:
// one dstack report, which all_attestations repeats as its single entry.
// REPORTDATA binds the signing address and the TLS key with the gateway's
// request nonce (phalaDirectReportData).
func phalaDirectEvidence(s *aci.Session) (*sessionEvidence, error) {
	if s.Evidence.MediaType != "application/json" {
		return nil, fmt.Errorf("phala-direct evidence is %s, not application/json", s.Evidence.MediaType)
	}
	data := s.Evidence.Data
	var report phalaDirectReport
	if err := strictDecode(data, &report); err != nil {
		return nil, fmt.Errorf("phala-direct evidence: %w", err)
	}
	if err := checkSingleAttestation(&report); err != nil {
		return nil, fmt.Errorf("phala-direct evidence: %w", err)
	}
	info, tcb := &report.Info, &report.Info.TCBInfo
	if err := checkPhalaDirectConsistency(&report, info, tcb); err != nil {
		return nil, fmt.Errorf("phala-direct evidence: %w", err)
	}
	nonce, err := attestation.ParseNonce(report.RequestNonce)
	if err != nil {
		return nil, fmt.Errorf("phala-direct evidence request_nonce: %w", err)
	}
	if err := checkPhalaDirectBinding(s, &report); err != nil {
		return nil, err
	}
	raw := &attestation.RawAttestation{
		BackendFormat:  attestation.FormatDstack,
		Nonce:          report.RequestNonce,
		NonceSource:    "aci_session",
		SigningKey:     provider.NormalizeUncompressedKey(report.SigningPublicKey),
		SigningAddress: report.SigningAddress,
		SigningAlgo:    report.SigningAlgo,
		TLSFingerprint: report.TLSCertFingerprint,
		IntelQuote:     report.IntelQuote,
		NvidiaPayload:  report.NvidiaPayload,
		AppName:        info.AppName,
		ComposeHash:    info.ComposeHash,
		OSImageHash:    info.OSImageHash,
		DeviceID:       info.DeviceID,
		AppCompose:     tcb.AppCompose,
		EventLog:       tcb.EventLog,
		EventLogCount:  len(tcb.EventLog),
		RawBody:        data,
	}
	return &sessionEvidence{raw: raw, nonce: nonce, reportData: phalaDirectReportData{}}, nil
}

// checkSingleAttestation requires all_attestations to hold exactly the
// top-level report without all_attestations.
func checkSingleAttestation(r *phalaDirectReport) error {
	if len(r.AllAttestations) != 1 {
		return fmt.Errorf("all_attestations has %d entries, want 1", len(r.AllAttestations))
	}
	if !reflect.DeepEqual(r.AllAttestations[0], r.phalaDirectAttestation) {
		return errors.New("all_attestations[0] is not the top-level report")
	}
	return nil
}

// checkPhalaDirectConsistency requires the fields that the report states
// twice to agree. The top-level event_log is a reduced copy: it leaves the
// payload of firmware events and the digest of RTMR3 events, which dstack
// derives from the event and its payload, empty. tcb_info.event_log
// carries every value, and a value that the top-level copy states must be
// the same.
func checkPhalaDirectConsistency(r *phalaDirectReport, info *phalaDirectInfo, tcb *phalaDirectTCBInfo) error {
	if r.Quote != r.IntelQuote || r.IntelQuote == "" {
		return errors.New("quote and intel_quote differ or are empty")
	}
	if r.VMConfig != info.VMConfig || info.ComposeHash != tcb.ComposeHash || info.DeviceID != tcb.DeviceID ||
		info.OSImageHash != tcb.OSImageHash || info.MRAggregated != tcb.MRAggregated {
		return errors.New("info and tcb_info differ")
	}
	var top []attestation.EventLogEntry
	if err := strictDecodeList([]byte(r.EventLog), &top); err != nil {
		return fmt.Errorf("event_log: %w", err)
	}
	if len(top) != len(tcb.EventLog) {
		return fmt.Errorf("event_log has %d events, tcb_info.event_log %d", len(top), len(tcb.EventLog))
	}
	for i := range top {
		a, b := top[i], tcb.EventLog[i]
		if a.IMR != b.IMR || a.EventType != b.EventType || a.Event != b.Event ||
			(a.Digest != "" && a.Digest != b.Digest) || (a.EventPayload != "" && a.EventPayload != b.EventPayload) {
			return fmt.Errorf("event_log[%d] differs from tcb_info.event_log[%d]", i, i)
		}
	}
	return nil
}

// checkPhalaDirectBinding requires the session's TLS binding to name the
// certificate key of the report and the session's identity to name its
// signing address.
func checkPhalaDirectBinding(s *aci.Session, r *phalaDirectReport) error {
	if len(s.ChannelBindings) != 1 || s.ChannelBindings[0].Type != aci.BindingTLSSPKI {
		return errors.New("a phala-direct session needs exactly one tls_spki_sha256 binding")
	}
	b := s.ChannelBindings[0]
	if s.Endpoint == "" || b.Origin != s.Endpoint {
		return fmt.Errorf("channel binding origin %q is not the session endpoint %q", b.Origin, s.Endpoint)
	}
	if subtle.ConstantTimeCompare([]byte(b.SPKISHA256), []byte(strings.ToLower(r.TLSCertFingerprint))) != 1 {
		return errors.New("channel binding spki_sha256 is not the tls_cert_fingerprint of the evidence")
	}
	var address string
	if raw, ok := s.Identity["signing_address"]; !ok || json.Unmarshal(raw, &address) != nil {
		return errors.New("a phala-direct session needs identity.signing_address")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(address)), []byte(strings.ToLower(r.SigningAddress))) != 1 {
		return errors.New("identity.signing_address is not the signing_address of the evidence")
	}
	return nil
}

// Content-IDs of a Chutes evidence bundle.
const (
	chutesEvidencePart  = "<chutes.attestation_evidence>"
	chutesInstancesPart = "<chutes.e2ee_instances."
	chutesMeasurePart   = "<chutes.measurements>"
)

// chutesSessionEvidence parses the evidence bundle of a Chutes session and
// selects the instance that the session's E2EE binding names. REPORTDATA is
// sha256(nonce_hex + e2e_pubkey) over the nonce of the evidence request.
func chutesSessionEvidence(ctx context.Context, s *aci.Session) (*sessionEvidence, error) {
	if len(s.ChannelBindings) != 1 || s.ChannelBindings[0].Type != aci.BindingE2EEPublicKey {
		return nil, errors.New("a Chutes session needs exactly one e2ee_public_key_sha256 binding")
	}
	b := s.ChannelBindings[0]
	if b.Provider != "chutes" || b.Algorithm != "chutes-ml-kem-768" || b.KeyID == "" {
		return nil, fmt.Errorf("chutes binding is %s/%s with key id %q, want chutes/chutes-ml-kem-768 with a key id", b.Provider, b.Algorithm, b.KeyID)
	}
	parts, err := s.Evidence.Parts()
	if err != nil {
		return nil, err
	}
	var evidence *aci.EvidencePart
	var instances [][]byte
	for i := range parts {
		p := &parts[i]
		mediaType := strings.TrimSpace(strings.Split(p.ContentType, ";")[0])
		if mediaType != "application/json" {
			return nil, fmt.Errorf("chutes evidence part %s is %s, not application/json", p.ContentID, p.ContentType)
		}
		switch {
		case p.ContentID == chutesEvidencePart:
			evidence = p
		case strings.HasPrefix(p.ContentID, chutesInstancesPart):
			instances = append(instances, p.Body)
		case p.ContentID == chutesMeasurePart:
			// The provider's own measurement list; teep applies its policy.
		default:
			return nil, fmt.Errorf("chutes evidence part %s is not a part teep reads", p.ContentID)
		}
	}
	if evidence == nil || len(instances) == 0 {
		return nil, errors.New("chutes evidence bundle lacks the attestation evidence or the instance list")
	}
	nonce, err := chutesEvidenceNonce(evidence.ContentLocation)
	if err != nil {
		return nil, err
	}
	raw, err := parseChutesInstance(ctx, instances, evidence.Body, b.KeyID, nonce)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(raw.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("chutes instance %s e2e_pubkey: %w", b.KeyID, err)
	}
	sum := sha256.Sum256(key)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(b.PublicKeySHA256)) != 1 {
		return nil, errors.New("channel binding public_key_sha256 is not the e2e_pubkey of the bound instance")
	}
	// The Chutes evidence response echoes no nonce, and the parser marks it
	// so (NonceSource not_echoed): the REPORTDATA preimage and the GPU
	// requester nonce bind the session nonce.
	return &sessionEvidence{raw: raw, nonce: nonce, reportData: chutes.ReportDataVerifier{}}, nil
}

// parseChutesInstance parses the attestation of the bound instance from the
// parts of a Chutes evidence bundle. Like the Phala model CVM evidence, the
// parts must have exactly the members that teep reads, including the newer
// members of the evidence response (chutes.ParseInstanceAttestation).
func parseChutesInstance(ctx context.Context, instances [][]byte, evidence []byte, keyID string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	raw, err := chutes.ParseInstanceAttestation(ctx, instances, evidence, keyID, nonce)
	if err != nil {
		return nil, err
	}
	if len(raw.UnknownFields) > 0 || len(raw.MissingFields) > 0 {
		return nil, fmt.Errorf("chutes session evidence: undefined members %q, missing members %q", raw.UnknownFields, raw.MissingFields)
	}
	return raw, nil
}

// chutesEvidenceNonce returns the nonce of the evidence request that the
// part's Content-Location records (/chutes/{chute}/evidence?nonce=<hex>).
func chutesEvidenceNonce(location string) (attestation.Nonce, error) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || !strings.HasPrefix(u.Path, "/chutes/") || !strings.HasSuffix(u.Path, "/evidence") {
		return attestation.Nonce{}, fmt.Errorf("chutes evidence location %q is not a chute evidence request", location)
	}
	values := u.Query()
	if len(values) != 1 || len(values["nonce"]) != 1 {
		return attestation.Nonce{}, errors.New("chutes evidence location needs exactly one nonce parameter")
	}
	return attestation.ParseNonce(values.Get("nonce"))
}

// strictDecode decodes data into v and fails on a duplicate, an unknown or a
// missing member at any depth.
func strictDecode(data []byte, v any) error {
	unknown, missing, err := jsonstrict.Unmarshal(data, v)
	if err != nil {
		return err
	}
	if len(unknown) > 0 || len(missing) > 0 {
		return fmt.Errorf("undefined members %q, missing members %q", unknown, missing)
	}
	return nil
}

// strictDecodeList decodes a JSON list of objects, each strictly.
func strictDecodeList(data []byte, out *[]attestation.EventLogEntry) error {
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil || items == nil {
		return errors.New("expected a list")
	}
	*out = make([]attestation.EventLogEntry, len(items))
	for i, item := range items {
		if err := strictDecode(item, &(*out)[i]); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
	}
	return nil
}

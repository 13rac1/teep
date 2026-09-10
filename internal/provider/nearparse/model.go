package nearparse

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// ModelFields is the required NEAR model report structure.
type ModelFields struct {
	ModelName          string      `json:"model_name"`
	IntelQuote         string      `json:"intel_quote"`
	NvidiaPayload      string      `json:"nvidia_payload"`
	SigningPublicKey   string      `json:"signing_public_key"`
	SigningAddress     string      `json:"signing_address"`
	SigningAlgo        string      `json:"signing_algo"`
	TLSCertFingerprint string      `json:"tls_cert_fingerprint"`
	RequestNonce       string      `json:"request_nonce"`
	EventLog           EventLog    `json:"event_log"`
	Info               DecodedInfo `json:"info"`
}

// Model retains every supported model field after nested validation.
type Model struct {
	Fields  ModelFields
	unknown []string
}

// UnmarshalJSON validates the report and its typed nested evidence.
func (m *Model) UnmarshalJSON(data []byte) error {
	var fields ModelFields
	unknown, err := Object(data, &fields, "model")
	if err != nil {
		return err
	}
	*m = Model{Fields: fields, unknown: unknown}
	return nil
}

// UnknownFields returns fully qualified diagnostics for every nested value.
func (m *Model) UnknownFields(path string) []string {
	out := make([]string, 0, len(m.unknown))
	for _, field := range m.unknown {
		out = append(out, path+"."+strings.TrimPrefix(field, "model."))
	}
	out = append(out, m.Fields.Info.UnknownFields(path)...)
	return append(out, m.Fields.EventLog.UnknownFields(path+".event_log")...)
}

// Models validates the bounded array before model selection.
type Models []Model

// UnmarshalJSON rejects null and validates every array entry.
func (m *Models) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '[' || len(data) > MaxEvidenceBytes {
		return errors.New("model_attestations: expected bounded array")
	}
	var wrapped struct {
		Value []json.RawMessage `json:"value"`
	}
	if _, _, err := jsonstrict.Unmarshal(append(append([]byte(`{"value":`), data...), '}'), &wrapped); err != nil {
		return err
	}
	if len(wrapped.Value) == 0 || len(wrapped.Value) > 256 {
		return errors.New("model_attestations: expected 1 to 256 reports")
	}
	out := make(Models, len(wrapped.Value))
	for i, raw := range wrapped.Value {
		if err := out[i].UnmarshalJSON(raw); err != nil {
			return fmt.Errorf("model_attestations[%d]: %w", i, err)
		}
	}
	*m = out
	return nil
}

// Select rejects duplicate or missing model identities after complete decoding.
func (m Models) Select(requested, path string) (Model, []string, error) {
	seen := make(map[string]bool, len(m))
	var selected Model
	var unknown []string
	found := false
	for i := range m {
		entry := &m[i]
		unknown = append(unknown, entry.UnknownFields(fmt.Sprintf("%s[%d]", path, i))...)
		name := entry.Fields.ModelName
		if name == "" || seen[name] {
			return Model{}, unknown, errors.New("empty or duplicate attestation model")
		}
		seen[name] = true
		if name == requested {
			selected, found = *entry, true
		}
	}
	if !found {
		return Model{}, unknown, errors.New("requested model absent from attestation")
	}
	return selected, unknown, nil
}

// Raw builds verification inputs only from supported validated fields.
func (m *Model) Raw(body []byte) *attestation.RawAttestation {
	f, info := m.Fields, m.Fields.Info.Info
	return &attestation.RawAttestation{
		BackendFormat: attestation.FormatNear, Model: f.ModelName,
		TEEProvider: "TDX+NVIDIA", TEEHardware: "intel-tdx", Nonce: f.RequestNonce,
		SigningKey: f.SigningPublicKey, SigningAddress: f.SigningAddress, SigningAlgo: f.SigningAlgo,
		TLSFingerprint: f.TLSCertFingerprint, IntelQuote: f.IntelQuote, NvidiaPayload: f.NvidiaPayload,
		AppCompose: info.TCBInfo.AppCompose, AppName: info.AppName, ComposeHash: info.ComposeHash,
		OSImageHash: info.OSImageHash, DeviceID: info.DeviceID,
		EventLog: f.EventLog.Values(), EventLogCount: len(f.EventLog), RawBody: body,
	}
}

func equalText(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func equalHex(a, b string) bool {
	x, err := hex.DecodeString(strings.TrimPrefix(a, "0x"))
	if err != nil {
		return false
	}
	y, err := hex.DecodeString(strings.TrimPrefix(b, "0x"))
	return err == nil && subtle.ConstantTimeCompare(x, y) == 1
}

// Equal compares every typed field, with byte comparison for supported hex
// encodings. Unknown fields are excluded from authenticated inputs.
func (m *Model) Equal(other *Model) bool {
	a, b := m.Fields, other.Fields
	return equalText(a.ModelName, b.ModelName) && equalText(a.SigningAlgo, b.SigningAlgo) &&
		equalText(a.IntelQuote, b.IntelQuote) && equalText(a.NvidiaPayload, b.NvidiaPayload) &&
		equalHex(a.SigningPublicKey, b.SigningPublicKey) && equalHex(a.SigningAddress, b.SigningAddress) &&
		equalHex(a.TLSCertFingerprint, b.TLSCertFingerprint) && equalHex(a.RequestNonce, b.RequestNonce) &&
		equalInfo(&a.Info, &b.Info) && equalEvents(a.EventLog, b.EventLog)
}

func equalInfo(a, b *DecodedInfo) bool {
	x, y := a.Info, b.Info
	return equalText(x.AppName, y.AppName) && equalText(x.AppCert, y.AppCert) &&
		equalText(x.KeyProviderInfo, y.KeyProviderInfo) && equalText(x.VMConfig, y.VMConfig) &&
		equalHex(x.ComposeHash, y.ComposeHash) && equalHex(x.OSImageHash, y.OSImageHash) &&
		equalHex(x.DeviceID, y.DeviceID) && equalHex(x.AppID, y.AppID) &&
		equalHex(x.InstanceID, y.InstanceID) && equalHex(x.MRAggregated, y.MRAggregated) &&
		equalTCB(&a.Info.TCBInfo, &b.Info.TCBInfo) && equalEvents(a.Info.TCBInfo.EventLog, b.Info.TCBInfo.EventLog)
}

func equalTCB(a, b *TCB) bool {
	return equalText(a.AppCompose, b.AppCompose) && equalHex(a.ComposeHash, b.ComposeHash) &&
		equalHex(a.DeviceID, b.DeviceID) && equalHex(a.OSImageHash, b.OSImageHash) &&
		equalHex(a.MRTD, b.MRTD) && equalHex(a.RTMR0, b.RTMR0) && equalHex(a.RTMR1, b.RTMR1) &&
		equalHex(a.RTMR2, b.RTMR2) && equalHex(a.RTMR3, b.RTMR3)
}

func equalEvents(a, b EventLog) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i].Value, b[i].Value
		if x.IMR != y.IMR || x.EventType != y.EventType || !equalText(x.Event, y.Event) ||
			!equalHex(x.Digest, y.Digest) || !equalHex(x.EventPayload, y.EventPayload) {
			return false
		}
	}
	return true
}

package phalacloud

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
)

const (
	phalaDirectSessionID = "4d849e211f7078bd8d27a748a7ac0ddfe164d2ef5c0e29e6e30292a371276320"
	chutesSessionID      = "299f127652dcdb0edddda771afc55c80b31de39de1c38e26b7b57fd777ef68a1"
)

func loadSession(t *testing.T, name, id string) *aci.Session {
	t.Helper()
	body, err := os.ReadFile("../aci/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := aci.ParseSession(body, id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// reportDataOf verifies the quote offline at the session's establishment
// time and returns its REPORTDATA.
func reportDataOf(t *testing.T, s *aci.Session, quote string) [64]byte {
	t.Helper()
	result := attestation.VerifyTDXQuoteOffline(context.Background(), quote, time.Unix(s.EstablishedAt, 0))
	if result.ParseErr != nil || result.SignatureErr != nil || result.CertChainErr != nil {
		t.Fatalf("quote: parse %v, signature %v, cert chain %v", result.ParseErr, result.SignatureErr, result.CertChainErr)
	}
	return result.ReportData
}

// The phala-direct evidence is a dstack report whose REPORTDATA binds the
// signing address and the TLS key with the gateway's request nonce; the
// session's binding and identity name that key and address.
func TestSessionEvidencePhalaDirect(t *testing.T) {
	s := loadSession(t, "session_phala_direct.json", phalaDirectSessionID)
	ev, err := sessionEvidenceOf(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if ev.raw.TLSFingerprint != s.ChannelBindings[0].SPKISHA256 || ev.raw.NvidiaPayload == "" || len(ev.raw.EventLog) != 30 {
		t.Errorf("raw: tls %s, nvidia %d bytes, events %d", ev.raw.TLSFingerprint, len(ev.raw.NvidiaPayload), len(ev.raw.EventLog))
	}
	if ev.nonce.Hex() != "cf6d46747de337983bdec6b0e17bd908ce47050466750fc6215f7578301f103a" {
		t.Errorf("nonce = %s", ev.nonce.Hex())
	}
	if _, err := ev.reportData.VerifyReportData(reportDataOf(t, s, ev.raw.IntelQuote), ev.raw, ev.nonce); err != nil {
		t.Errorf("REPORTDATA: %v", err)
	}
	if _, err := ev.reportData.VerifyReportData(reportDataOf(t, s, ev.raw.IntelQuote), ev.raw, attestation.NewNonce()); err == nil {
		t.Error("REPORTDATA passed with another nonce")
	}
}

// The Chutes evidence bundle yields the instance that the session's E2EE
// binding names, whose REPORTDATA binds that key with the nonce of the
// gateway's evidence request.
func TestSessionEvidenceChutes(t *testing.T) {
	s := loadSession(t, "session_chutes.json", chutesSessionID)
	ev, err := sessionEvidenceOf(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if ev.raw.InstanceID != "fa2cbed2-284e-4ace-9de0-b003a928c000" || len(ev.raw.GPUEvidence) == 0 {
		t.Errorf("raw: instance %s, GPUs %d", ev.raw.InstanceID, len(ev.raw.GPUEvidence))
	}
	if !strings.HasPrefix(ev.nonce.Hex(), "34ad5b0ef1a3fa06") {
		t.Errorf("nonce = %s", ev.nonce.Hex())
	}
	if _, err := ev.reportData.VerifyReportData(reportDataOf(t, s, ev.raw.IntelQuote), ev.raw, ev.nonce); err != nil {
		t.Errorf("REPORTDATA: %v", err)
	}
}

// A session whose binding or identity does not name the key of its evidence
// fails, as does a verifier whose evidence teep does not verify.
func TestSessionEvidenceRefusesOtherBindings(t *testing.T) {
	for _, tc := range []struct {
		name, file, id string
		change         func(*aci.Session)
	}{
		{"other TLS key", "session_phala_direct.json", phalaDirectSessionID, func(s *aci.Session) {
			s.ChannelBindings[0].SPKISHA256 = strings.Repeat("ab", 32)
		}},
		{"other origin", "session_phala_direct.json", phalaDirectSessionID, func(s *aci.Session) {
			s.ChannelBindings[0].Origin = "https://other.example"
		}},
		{"other signing address", "session_phala_direct.json", phalaDirectSessionID, func(s *aci.Session) {
			s.Identity["signing_address"] = []byte(`"0x0000000000000000000000000000000000000001"`)
		}},
		{"no identity", "session_phala_direct.json", phalaDirectSessionID, func(s *aci.Session) { s.Identity = nil }},
		{"E2EE binding on a phala-direct session", "session_phala_direct.json", phalaDirectSessionID, func(s *aci.Session) {
			s.ChannelBindings[0] = aci.ChannelBinding{Type: aci.BindingE2EEPublicKey}
		}},
		{"other ML-KEM key", "session_chutes.json", chutesSessionID, func(s *aci.Session) {
			s.ChannelBindings[0].PublicKeySHA256 = strings.Repeat("ab", 32)
		}},
		{"instance not in the bundle", "session_chutes.json", chutesSessionID, func(s *aci.Session) {
			s.ChannelBindings[0].KeyID = "00000000-0000-0000-0000-000000000000"
		}},
		{"other algorithm", "session_chutes.json", chutesSessionID, func(s *aci.Session) {
			s.ChannelBindings[0].Algorithm = "x25519"
		}},
		{"other verifier", "session_chutes.json", chutesSessionID, func(s *aci.Session) {
			s.VerifierID = "private-ai-verifier/other/v1"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loadSession(t, tc.file, tc.id)
			tc.change(s)
			if _, err := sessionEvidenceOf(context.Background(), s); err == nil {
				t.Fatal("session accepted")
			}
		})
	}
}

// The phala-direct REPORTDATA binds the signing key through its address,
// the TLS key and the nonce: a change to any of them fails.
func TestPhalaDirectReportDataRefusesOtherBindings(t *testing.T) {
	s := loadSession(t, "session_phala_direct.json", phalaDirectSessionID)
	ev, err := sessionEvidenceOf(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	rd := reportDataOf(t, s, ev.raw.IntelQuote)
	for _, tc := range []struct {
		name   string
		change func(*attestation.RawAttestation)
	}{
		{"other algorithm", func(r *attestation.RawAttestation) { r.SigningAlgo = "ed25519" }},
		{"other signing key", func(r *attestation.RawAttestation) { r.SigningKey = "04" + strings.Repeat("11", 64) }},
		{"compressed key", func(r *attestation.RawAttestation) { r.SigningKey = "02" + strings.Repeat("11", 32) }},
		{"other address", func(r *attestation.RawAttestation) { r.SigningAddress = "0x" + strings.Repeat("11", 20) }},
		{"other TLS key", func(r *attestation.RawAttestation) { r.TLSFingerprint = strings.Repeat("11", 32) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := *ev.raw
			tc.change(&raw)
			if _, err := (phalaDirectReportData{}).VerifyReportData(rd, &raw, ev.nonce); err == nil {
				t.Fatal("REPORTDATA passed")
			}
		})
	}
}

// The phala-direct report must have every member at every depth, one
// all_attestations entry equal to the top level, and agreeing copies of the
// fields it states twice.
func TestPhalaDirectEvidenceRefusesMalformedReports(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(top map[string]any)
	}{
		{"absent nested member", func(top map[string]any) {
			delete(top["info"].(map[string]any)["tcb_info"].(map[string]any), "mrtd")
		}},
		{"two attestations", func(top map[string]any) {
			list := top["all_attestations"].([]any)
			top["all_attestations"] = append(list, list[0])
		}},
		{"attestation entry differs", func(top map[string]any) {
			top["all_attestations"].([]any)[0].(map[string]any)["request_nonce"] = strings.Repeat("00", 32)
		}},
		{"quote differs from intel_quote", func(top map[string]any) {
			q := top["quote"].(string)
			flipped := "0"
			if q[10] == '0' {
				flipped = "1"
			}
			top["quote"] = q[:10] + flipped + q[11:]
			top["all_attestations"].([]any)[0].(map[string]any)["quote"] = top["quote"]
		}},
		{"event log differs", func(top map[string]any) {
			var events []map[string]any
			if err := json.Unmarshal([]byte(top["event_log"].(string)), &events); err != nil {
				t.Fatal(err)
			}
			events[0]["imr"] = 3
			b, _ := json.Marshal(events)
			top["event_log"] = string(b)
			top["all_attestations"].([]any)[0].(map[string]any)["event_log"] = string(b)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loadSession(t, "session_phala_direct.json", phalaDirectSessionID)
			var top map[string]any
			if err := json.Unmarshal(s.Evidence.Data, &top); err != nil {
				t.Fatal(err)
			}
			tc.change(top)
			data, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			s.Evidence.Data = data
			if _, err := sessionEvidenceOf(context.Background(), s); err == nil {
				t.Fatal("malformed report accepted")
			}
		})
	}
}

func TestChutesEvidenceNonce(t *testing.T) {
	good := "https://api.chutes.ai/chutes/9ecb73cc-909b-5334-9cd8-74985945cff5/evidence?nonce=" + strings.Repeat("ab", 32)
	if _, err := chutesEvidenceNonce(good); err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{
		"",
		"http://api.chutes.ai/chutes/x/evidence?nonce=" + strings.Repeat("ab", 32),
		"https://api.chutes.ai/e2e/instances/x?nonce=" + strings.Repeat("ab", 32),
		good + "&nonce=" + strings.Repeat("cd", 32),
		good + "&other=1",
		"https://api.chutes.ai/chutes/x/evidence?nonce=zz",
	} {
		if _, err := chutesEvidenceNonce(location); err == nil {
			t.Errorf("location %q accepted", location)
		}
	}
}

package phalacloud

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/google/go-tdx-guest/pcs"
)

// offlineAuditor verifies quotes offline at the session's establishment
// time: the fixtures hold no Intel PCS collateral.
func offlineAuditor(s *aci.Session) SessionAuditor {
	return SessionAuditor{TDX: attestation.NewTDXVerifier(true, nil, time.Unix(s.EstablishedAt, 0)), Offline: true}
}

// The session of the Phala model CVM passes every check: quote, MRTD and
// MRSEAM, REPORTDATA, binding, GPU evidence, compose binding and event-log
// replay.
func TestSessionAuditPhalaModelCVM(t *testing.T) {
	s := loadSession(t, "session_phala_direct.json", phalaDirectSessionID)
	if err := offlineAuditor(s).Audit(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// The session of a Phala model CVM on dstack-0.6.3 passes every check:
// MRTD of dstack-0.6.3, MRSEAM of TDX module 2.0.20, and an MRConfigID of
// version 3.
func TestSessionAuditPhalaModelCVMDstack063(t *testing.T) {
	s := loadSession(t, "session_phala_direct_0_6_3.json", phalaDirect063SessionID)
	if err := offlineAuditor(s).Audit(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// An MRConfigID of version 3 binds the document that the dstack VMM builds;
// each change to its inputs, or a second event of one name, fails.
func TestComposeBindingV3Refuses(t *testing.T) {
	s := loadSession(t, "session_phala_direct_0_6_3.json", phalaDirect063SessionID)
	ev, err := sessionEvidenceOf(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	tdx := offlineAuditor(s).TDX(context.Background(), ev.raw.IntelQuote)
	if err := attestation.VerifyComposeBindingV3(ev.raw.AppCompose, ev.raw.EventLog, true, tdx.MRConfigID); err != nil {
		t.Fatal(err)
	}
	event := func(name string) int {
		for i, e := range ev.raw.EventLog {
			if e.IMR == 3 && e.Event == name {
				return i
			}
		}
		t.Fatalf("no %s event", name)
		return 0
	}
	withEvent := func(name, payload string) []attestation.EventLogEntry {
		events := slices.Clone(ev.raw.EventLog)
		events[event(name)].EventPayload = payload
		return events
	}
	for _, tc := range []struct {
		name       string
		appCompose string
		events     []attestation.EventLogEntry
		gpu        bool
		want       string
	}{
		{"app compose", ev.raw.AppCompose + " ", ev.raw.EventLog, true, "does not bind"},
		{"no GPU policy", ev.raw.AppCompose, ev.raw.EventLog, false, "does not bind"},
		{"instance id", ev.raw.AppCompose, withEvent("instance-id", strings.Repeat("00", 20)), true, "does not bind"},
		{"app id", ev.raw.AppCompose, withEvent("app-id", strings.Repeat("00", 20)), true, "does not bind"},
		{"second app id", ev.raw.AppCompose, append(slices.Clone(ev.raw.EventLog), ev.raw.EventLog[event("app-id")]), true, "2 app-id events"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := attestation.VerifyComposeBindingV3(tc.appCompose, tc.events, tc.gpu, tdx.MRConfigID)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// The Chutes session passes every check: quote, MRTD and MRSEAM (sek8s
// 1.4.x on TDX module 1.5.34), REPORTDATA, binding and GPU evidence.
func TestSessionAuditChutes(t *testing.T) {
	s := loadSession(t, "session_chutes.json", chutesSessionID)
	if err := offlineAuditor(s).Audit(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// Each check refuses a session that fails it.
func TestSessionAuditRefuses(t *testing.T) {
	s := loadSession(t, "session_phala_direct.json", phalaDirectSessionID)
	auditor := offlineAuditor(s)
	quote := func(change func(*attestation.TDXVerifyResult)) attestation.TDXVerifier {
		return func(ctx context.Context, hexQuote string) *attestation.TDXVerifyResult {
			r := auditor.TDX(ctx, hexQuote)
			change(r)
			return r
		}
	}
	for _, tc := range []struct {
		name    string
		auditor SessionAuditor
		change  func(*sessionEvidence)
		want    string
	}{
		{"signature", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.SignatureErr = errors.New("bad") }), Offline: true}, nil, "signature"},
		{"certificate chain", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.CertChainErr = errors.New("bad") }), Offline: true}, nil, "certificate chain"},
		{"debug", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.DebugEnabled = true }), Offline: true}, nil, "debug"},
		{"TCB out of date online", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.TcbStatus = pcs.TcbComponentStatusOutOfDate })}, nil, "TCB"},
		{"no collateral online", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.CollateralErr = errors.New("PCS down") })}, nil, "collateral"},
		{"MRSEAM", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.MRSeam = make([]byte, 48) }), Offline: true}, nil, "MRSEAM"},
		{"REPORTDATA", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.ReportData[0] ^= 1 }), Offline: true}, nil, "REPORTDATA"},
		{"RTMR", SessionAuditor{TDX: quote(func(r *attestation.TDXVerifyResult) { r.RTMRs[2][0] ^= 1 }), Offline: true}, nil, "RTMR2"},
		{"compose", auditor, func(ev *sessionEvidence) { ev.raw.AppCompose += " " }, "compose binding"},
		{"session nonce", auditor, func(ev *sessionEvidence) { ev.nonce[0] ^= 1 }, "REPORTDATA"},
		{"no GPU evidence", SessionAuditor{TDX: auditor.TDX, Offline: true}, func(ev *sessionEvidence) { ev.raw.NvidiaPayload = "" }, "no GPU evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := sessionEvidenceOf(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if tc.change != nil {
				tc.change(ev)
			}
			err = tc.auditor.auditEvidence(context.Background(), s, ev)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// The GPU check refuses evidence that answers another nonce.
func TestSessionGPUChecksNonce(t *testing.T) {
	for _, tc := range []struct{ file, id string }{
		{"session_phala_direct.json", phalaDirectSessionID},
		{"session_chutes.json", chutesSessionID},
	} {
		s := loadSession(t, tc.file, tc.id)
		ev, err := sessionEvidenceOf(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		ev.nonce = attestation.NewNonce()
		ev.raw.Nonce = ev.nonce.Hex()
		if err := checkSessionGPU(context.Background(), ev); err == nil {
			t.Errorf("%s: GPU evidence accepted with another nonce", tc.file)
		}
	}
}

// A GPU result that states the session nonce fails unless its signatures
// verified, whatever produced it: nvidia_signature requires the same.
func TestCheckSessionGPUResultRequiresVerifiedSignatures(t *testing.T) {
	nonce := attestation.NewNonce()
	verified := attestation.NvidiaVerifyResult{SignaturesVerified: true, GPUCount: 1, Nonce: nonce.Hex()}
	if err := checkSessionGPUResult(&verified, nonce); err != nil {
		t.Fatalf("verified result: %v", err)
	}
	unverified := verified
	unverified.SignaturesVerified = false
	err := checkSessionGPUResult(&unverified, nonce)
	if err == nil || !strings.Contains(err.Error(), "signatures were not verified") {
		t.Fatalf("err = %v, want the unverified signatures refused", err)
	}
}

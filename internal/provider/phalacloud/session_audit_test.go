package phalacloud

import (
	"context"
	"errors"
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

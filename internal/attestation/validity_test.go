package attestation

import (
	"errors"
	"testing"
	"time"
)

func TestEvidenceValidity(t *testing.T) {
	if _, ok := (EvidenceValidity{}).Expiry(); ok {
		t.Fatal("absent validity has expiry")
	}
	if _, err := verifiedEvidenceValidity(time.Time{}); err == nil {
		t.Fatal("zero validity accepted")
	}
	early := time.Now().Add(time.Hour)
	a, _ := verifiedEvidenceValidity(early)
	b, _ := verifiedEvidenceValidity(early.Add(time.Hour))
	for _, pair := range [][2]EvidenceValidity{{a, b}, {b, a}, {a, {}}, {{}, a}} {
		got, ok := minimumEvidenceValidity(pair[0], pair[1]).Expiry()
		if !ok || !got.Equal(early) {
			t.Fatal("minimum validity lost")
		}
	}
}

func TestReportEvidenceValidity(t *testing.T) {
	at := time.Now().Add(time.Hour)
	bound, _ := verifiedEvidenceValidity(at)
	factors := []FactorResult{{Name: FactorNvidiaSignature, Status: Pass}, {Name: FactorNvidiaClaims, Status: Pass}}
	result := &NvidiaVerifyResult{Validity: bound, ExpiresAt: at}
	in := &ReportInput{Nvidia: result}
	if got, ok := reportEvidenceValidity(in, factors).Expiry(); !ok || !got.Equal(at) {
		t.Fatal("verified expiry lost")
	}
	result.SignatureErr = errors.New("untrusted signature")
	if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
		t.Fatal("failed signature supplied expiry")
	}
	result.SignatureErr = nil
	factors[0].Status = Fail
	if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
		t.Fatal("allowed failed factor supplied expiry")
	}
	factors[0].Status = NotApplicable
	if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
		t.Fatal("inapplicable factor supplied expiry")
	}
	in.Nvidia = nil
	in.TDX = &TDXVerifyResult{Validity: bound}
	if _, ok := reportEvidenceValidity(in, nil).Expiry(); ok {
		t.Fatal("offline TDX supplied expiry")
	}
	factors = []FactorResult{{Name: FactorTEETCBCurrent, Status: Pass}}
	if _, ok := reportEvidenceValidity(in, factors).Expiry(); !ok {
		t.Fatal("online TDX expiry lost")
	}
	in.TDX.CollateralErr = errors.New("collateral invalid")
	if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
		t.Fatal("failed collateral supplied expiry")
	}
}

func TestSEVReportEvidenceValidity(t *testing.T) {
	at := time.Now().Add(time.Hour)
	bound, _ := verifiedEvidenceValidity(at)
	for _, gateway := range []bool{false, true} {
		name, certFactor, signatureFactor := "backend", FactorTEECertChain, FactorTEEQuoteSignature
		if gateway {
			name, certFactor, signatureFactor = "gateway", FactorGWCertChain, FactorGWQuoteSignature
		}
		t.Run(name, func(t *testing.T) {
			result := &SEVVerifyResult{OnlineVerified: true, Validity: bound}
			in := &ReportInput{SEV: result}
			if gateway {
				in = &ReportInput{GatewaySEV: result}
			}
			factors := []FactorResult{{Name: certFactor, Status: Pass}, {Name: signatureFactor, Status: Pass}}
			if got, ok := reportEvidenceValidity(in, factors).Expiry(); !ok || !got.Equal(at) {
				t.Fatal("verified SEV expiry lost")
			}
			for _, status := range []Status{Fail, Skip, NotApplicable} {
				factors[0].Status = status
				if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
					t.Fatal("unverified chain supplied expiry")
				}
			}
			factors[0].Status = Pass
			result.OnlineVerified = false
			if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
				t.Fatal("offline SEV supplied expiry")
			}
			result.OnlineVerified = true
			result.SignatureErr = errors.New("invalid signature")
			if _, ok := reportEvidenceValidity(in, factors).Expiry(); ok {
				t.Fatal("failed signature supplied expiry")
			}
		})
	}
}

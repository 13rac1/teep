package attestation

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

// realTDXQuoteRaw is the raw bytes of a real TDX production quote from Intel
// hardware. Used for structural parsing and cert chain tests.
//
//go:embed testdata/tdx_prod_quote_SPR_E4.dat
var realTDXQuoteRaw []byte

// realTDXQuoteHex is the real quote encoded as lowercase hex, matching
// how Venice returns it in the intel_quote field.
func realTDXQuoteHex() string {
	return hex.EncodeToString(realTDXQuoteRaw)
}

// TestVerifyTDXQuoteParseRealQuote verifies that the real TDX fixture quote
// parses successfully as a QuoteV4.
func TestVerifyTDXQuoteParseRealQuote(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), realTDXQuoteHex())

	if result.ParseErr != nil {
		t.Fatalf("VerifyTDXQuoteOffline: unexpected parse error: %v", result.ParseErr)
	}

	// The quote should have a 16-byte TEE_TCB_SVN.
	if len(result.TeeTCBSVN) != 16 {
		t.Errorf("TeeTCBSVN length: got %d, want 16", len(result.TeeTCBSVN))
	}

	t.Logf("REPORTDATA (hex): %s", hex.EncodeToString(result.ReportData[:]))
	t.Logf("debug enabled: %v", result.DebugEnabled)
	t.Logf("TEE_TCB_SVN (hex): %s", hex.EncodeToString(result.TeeTCBSVN))
}

// TestVerifyTDXQuoteMeasurements verifies that MRTD, RTMRs, and other
// measurement registers are extracted from the real production quote.
func TestVerifyTDXQuoteMeasurements(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), realTDXQuoteHex())

	if result.ParseErr != nil {
		t.Fatalf("parse failed: %v", result.ParseErr)
	}

	// MRTD should be 48 bytes and non-zero.
	if len(result.MRTD) != 48 {
		t.Errorf("MRTD length: got %d, want 48", len(result.MRTD))
	}
	allZero := true
	for _, b := range result.MRTD {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("MRTD is all zeros; expected a non-zero VM image measurement")
	}

	// RTMR0 should be 48 bytes and non-zero (firmware measurement).
	rtmr0 := result.RTMRs[0]
	rtmr0Zero := true
	for _, b := range rtmr0 {
		if b != 0 {
			rtmr0Zero = false
			break
		}
	}
	if rtmr0Zero {
		t.Error("RTMR0 is all zeros; expected a non-zero firmware measurement")
	}

	// MRSeam should be 48 bytes.
	if len(result.MRSeam) != 48 {
		t.Errorf("MRSeam length: got %d, want 48", len(result.MRSeam))
	}

	t.Logf("MRTD:           %s", hex.EncodeToString(result.MRTD))
	for i, r := range result.RTMRs {
		t.Logf("RTMR%d:          %s", i, hex.EncodeToString(r[:]))
	}
	t.Logf("MRSeam:         %s", hex.EncodeToString(result.MRSeam))
	t.Logf("MRSignerSeam:   %s", hex.EncodeToString(result.MRSignerSeam))
	t.Logf("MRConfigID:     %s", hex.EncodeToString(result.MRConfigID))
	t.Logf("MROwner:        %s", hex.EncodeToString(result.MROwner))
	t.Logf("MROwnerConfig:  %s", hex.EncodeToString(result.MROwnerConfig))
}

// TestVerifyTDXQuoteCertChain verifies the cert chain and signature verification
// against the real quote. Because these certs may be expired, we check that
// CertChainErr is set or not — we do not require it to pass (production quote
// is from 2023 hardware and its cert chain TTL may have lapsed).
func TestVerifyTDXQuoteCertChain(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), realTDXQuoteHex())

	if result.ParseErr != nil {
		t.Fatalf("parse failed, cannot test cert chain: %v", result.ParseErr)
	}

	if result.CertChainErr != nil {
		t.Logf("CertChainErr (expected for expired test fixture): %v", result.CertChainErr)
	} else {
		t.Log("CertChainErr: nil (cert chain verified successfully)")
	}

	// SignatureErr should match CertChainErr: same root cause in our implementation.
	if (result.CertChainErr == nil) != (result.SignatureErr == nil) {
		t.Errorf("CertChainErr and SignatureErr should be nil/non-nil together; got CertChainErr=%v, SignatureErr=%v",
			result.CertChainErr, result.SignatureErr)
	}
}

// TestVerifyTDXQuoteDebugFlagRealQuote verifies the real production quote has
// debug disabled (it's a production quote, not a debug quote).
func TestVerifyTDXQuoteDebugFlagRealQuote(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), realTDXQuoteHex())

	if result.ParseErr != nil {
		t.Fatalf("parse failed: %v", result.ParseErr)
	}

	if result.DebugEnabled {
		t.Error("production TDX quote has debug bit set — this should never happen for real hardware")
	}
}

// TestVerifyTDXQuoteInvalidHex verifies parse error on garbage input.
func TestVerifyTDXQuoteInvalidHex(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), "not-hex!@#$%")

	if result.ParseErr == nil {
		t.Error("expected ParseErr for invalid hex input, got nil")
	}
}

// TestVerifyTDXQuoteTooShort verifies parse error when bytes are too short to be a quote.
func TestVerifyTDXQuoteTooShort(t *testing.T) {
	short := hex.EncodeToString([]byte("too short"))
	result := VerifyTDXQuoteOffline(context.Background(), short)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for too-short quote bytes, got nil")
	}
}

// TestVerifyTDXQuoteEmptyString verifies parse error on empty input.
func TestVerifyTDXQuoteEmptyString(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), "")

	if result.ParseErr == nil {
		t.Error("expected ParseErr for empty quote string, got nil")
	}
}

// TestPPIDExtraction verifies PPID and FMSPC are extracted from the real
// production quote's PCK certificate chain.
func TestPPIDExtraction(t *testing.T) {
	result := VerifyTDXQuoteOffline(context.Background(), realTDXQuoteHex())

	if result.ParseErr != nil {
		t.Fatalf("parse failed: %v", result.ParseErr)
	}

	// The real SPR_E4 quote should have a PCK cert with PPID.
	if result.PPID == "" {
		t.Error("PPID is empty; expected extraction from PCK cert")
	} else {
		// PPID should be 32 hex chars (16 bytes).
		if len(result.PPID) != 32 {
			t.Errorf("PPID length: got %d, want 32 hex chars", len(result.PPID))
		}
		t.Logf("PPID: %s", result.PPID)
	}

	if result.FMSPC == "" {
		t.Error("FMSPC is empty; expected extraction from PCK cert")
	} else {
		// FMSPC should be 12 hex chars (6 bytes).
		if len(result.FMSPC) != 12 {
			t.Errorf("FMSPC length: got %d, want 12 hex chars", len(result.FMSPC))
		}
		t.Logf("FMSPC: %s", result.FMSPC)
	}
}

// noopGetter is a trust.HTTPSGetter that immediately returns an error.
// Used for race tests to avoid network calls.
type noopGetter struct{}

func (*noopGetter) Get(_ string) (headers map[string][]string, body []byte, err error) {
	return nil, nil, errors.New("noop getter")
}
func (*noopGetter) GetContext(_ context.Context, _ string) (headers map[string][]string, body []byte, err error) {
	return nil, nil, errors.New("noop getter")
}

// TestVerifyTDXQuoteOfflineNoRace verifies that concurrent offline calls to
// VerifyTDXQuoteOffline are race-free. Before this fix, verify.Run mutated the
// TDXCollateralGetter global per-call, causing a data race under concurrent
// load. The split into Offline/Online eliminates the global entirely.
func TestVerifyTDXQuoteOfflineNoRace(t *testing.T) {
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			result := VerifyTDXQuoteOffline(context.Background(), realTDXQuoteHex())
			t.Logf("result.ParseErr: %v", result.ParseErr)
		})
	}
	wg.Wait()
}

// TestVerifyTDXQuoteOnlineNoRace verifies that concurrent Online calls are
// race-free. Uses a no-op getter to avoid network calls; CollateralErr is
// expected non-nil.
func TestVerifyTDXQuoteOnlineNoRace(t *testing.T) {
	getter := &noopGetter{}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			result := VerifyTDXQuoteOnline(context.Background(), realTDXQuoteHex(), getter)
			t.Logf("result.CollateralErr: %v", result.CollateralErr)
		})
	}
	wg.Wait()
}

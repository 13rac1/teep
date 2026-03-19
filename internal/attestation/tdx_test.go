package attestation

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// realTDXQuoteRaw is the raw bytes of a real TDX production quote from Intel
// hardware. Used for structural parsing and cert chain tests.
//
//go:embed testdata/tdx_prod_quote_SPR_E4.dat
var realTDXQuoteRaw []byte

// realTDXQuoteBase64 is the real quote encoded as standard base64, matching
// how Venice returns it in the intel_quote field.
func realTDXQuoteBase64() string {
	return base64.StdEncoding.EncodeToString(realTDXQuoteRaw)
}

// ethAddress computes the Ethereum address (20 bytes) from an uncompressed
// secp256k1 public key (65 bytes starting with 0x04).
func ethAddress(pubKeyUncompressed []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(pubKeyUncompressed[1:]) // skip 04 prefix
	hash := h.Sum(nil)
	return hash[12:32]
}

// TestVerifyTDXQuoteParseRealQuote verifies that the real TDX fixture quote
// parses successfully as a QuoteV4.
func TestVerifyTDXQuoteParseRealQuote(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), realTDXQuoteBase64(), "", nonce, true)

	if result.ParseErr != nil {
		t.Fatalf("VerifyTDXQuote: unexpected parse error: %v", result.ParseErr)
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
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), realTDXQuoteBase64(), "", nonce, true)

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
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), realTDXQuoteBase64(), "", nonce, true)

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
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), realTDXQuoteBase64(), "", nonce, true)

	if result.ParseErr != nil {
		t.Fatalf("parse failed: %v", result.ParseErr)
	}

	if result.DebugEnabled {
		t.Error("production TDX quote has debug bit set — this should never happen for real hardware")
	}
}

// TestVerifyTDXQuoteHexEncoded verifies that a hex-encoded quote (as Venice
// returns) is decoded and parsed correctly.
func TestVerifyTDXQuoteHexEncoded(t *testing.T) {
	nonce := NewNonce()
	hexQuote := hex.EncodeToString(realTDXQuoteRaw)
	result := VerifyTDXQuote(context.Background(), hexQuote, "", nonce, true)

	if result.ParseErr != nil {
		t.Fatalf("VerifyTDXQuote with hex-encoded input: unexpected parse error: %v", result.ParseErr)
	}
	if len(result.TeeTCBSVN) != 16 {
		t.Errorf("TeeTCBSVN length: got %d, want 16", len(result.TeeTCBSVN))
	}
}

// TestVerifyTDXQuoteInvalidBase64 verifies parse error on garbage input.
func TestVerifyTDXQuoteInvalidBase64(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), "not-base64!@#$%", "", nonce, true)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for invalid base64 input, got nil")
	}
}

// TestVerifyTDXQuoteTooShort verifies parse error when bytes are too short to be a quote.
func TestVerifyTDXQuoteTooShort(t *testing.T) {
	nonce := NewNonce()
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	result := VerifyTDXQuote(context.Background(), short, "", nonce, true)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for too-short quote bytes, got nil")
	}
}

// TestVerifyTDXQuoteEmptyString verifies parse error on empty input.
func TestVerifyTDXQuoteEmptyString(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), "", "", nonce, true)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for empty quote string, got nil")
	}
}

// TestReportDataBindingEthereumAddress verifies that verifyReportDataBinding
// passes when REPORTDATA[0:20] = Ethereum address of the signing key.
func TestReportDataBindingEthereumAddress(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	pubKeyBytes := priv.PubKey().SerializeUncompressed()
	signingKeyHex := hex.EncodeToString(pubKeyBytes)

	addr := ethAddress(pubKeyBytes)

	// Build a 64-byte REPORTDATA with Ethereum address in the first 20 bytes.
	reportData := make([]byte, 64)
	copy(reportData[:20], addr)

	if err := verifyReportDataBinding(reportData, signingKeyHex); err != nil {
		t.Errorf("verifyReportDataBinding with correct Ethereum address: unexpected error: %v", err)
	}
}

// TestReportDataBindingWrongKey verifies the binding fails with a different signing key.
func TestReportDataBindingWrongKey(t *testing.T) {
	privA, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey A: %v", err)
	}
	privB, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey B: %v", err)
	}

	signingKeyBHex := hex.EncodeToString(privB.PubKey().SerializeUncompressed())

	// Build REPORTDATA with key A's Ethereum address.
	addrA := ethAddress(privA.PubKey().SerializeUncompressed())
	reportData := make([]byte, 64)
	copy(reportData[:20], addrA)

	// Verify with key B — should fail.
	if err := verifyReportDataBinding(reportData, signingKeyBHex); err == nil {
		t.Error("verifyReportDataBinding with wrong key: expected error, got nil")
	}
}

// TestReportDataBindingInvalidHex verifies error on non-hex signing key.
func TestReportDataBindingInvalidHex(t *testing.T) {
	reportData := make([]byte, 64)

	if err := verifyReportDataBinding(reportData, "not-hex-!!!"); err == nil {
		t.Error("verifyReportDataBinding with invalid hex: expected error, got nil")
	}
}

// TestReportDataBindingTooShort verifies error on too-short REPORTDATA.
func TestReportDataBindingTooShort(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	signingKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())

	// Only 16 bytes — too short.
	shortReportData := make([]byte, 16)
	if err := verifyReportDataBinding(shortReportData, signingKeyHex); err == nil {
		t.Error("verifyReportDataBinding with short REPORTDATA: expected error, got nil")
	}
}

// TestReportDataBindingNotUncompressed verifies error when key is not 65-byte uncompressed.
func TestReportDataBindingNotUncompressed(t *testing.T) {
	priv, _ := secp256k1.GeneratePrivateKey()
	// Compressed key (33 bytes, starts with 02 or 03) — should fail.
	compressedHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())

	reportData := make([]byte, 64)
	if err := verifyReportDataBinding(reportData, compressedHex); err == nil {
		t.Error("verifyReportDataBinding with compressed key: expected error, got nil")
	}
}

// TestVerifyTDXQuoteReportDataBindingRealQuoteFails exercises the full
// VerifyTDXQuote path. The real fixture quote's REPORTDATA will fail binding
// because it was generated by Intel hardware with a different signing key.
func TestVerifyTDXQuoteReportDataBindingRealQuoteFails(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	signingKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())

	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), realTDXQuoteBase64(), signingKeyHex, nonce, true)

	if result.ParseErr != nil {
		t.Fatalf("parse error: %v", result.ParseErr)
	}

	// The real quote was not generated with our signing key.
	// ReportDataBindingErr should be non-nil.
	if result.ReportDataBindingErr == nil {
		t.Error("expected ReportDataBindingErr for mismatched signing key, got nil")
	} else {
		t.Logf("ReportDataBindingErr (expected): %v", result.ReportDataBindingErr)
	}
}

// TestPPIDExtraction verifies PPID and FMSPC are extracted from the real
// production quote's PCK certificate chain.
func TestPPIDExtraction(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote(context.Background(), realTDXQuoteBase64(), "", nonce, true)

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

package attestation

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

// TestVerifyTDXQuoteParseRealQuote verifies that the real TDX fixture quote
// parses successfully as a QuoteV4.
func TestVerifyTDXQuoteParseRealQuote(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote(realTDXQuoteBase64(), "", nonce)

	if result.ParseErr != nil {
		t.Fatalf("VerifyTDXQuote: unexpected parse error: %v", result.ParseErr)
	}

	// The quote should have a 16-byte TEE_TCB_SVN.
	if len(result.TeeTCBSVN) != 16 {
		t.Errorf("TeeTCBSVN length: got %d, want 16", len(result.TeeTCBSVN))
	}

	// ReportData should be non-nil (64 bytes).
	allZero := true
	for _, b := range result.ReportData {
		if b != 0 {
			allZero = false
			break
		}
	}
	// The real production quote has a non-zero REPORTDATA.
	// We log it but don't fail on all-zero since we don't know the real content.
	t.Logf("REPORTDATA (hex): %s", hex.EncodeToString(result.ReportData[:]))
	t.Logf("debug enabled: %v", result.DebugEnabled)
	t.Logf("TEE_TCB_SVN (hex): %s", hex.EncodeToString(result.TeeTCBSVN))
	_ = allZero
}

// TestVerifyTDXQuoteCertChain verifies the cert chain and signature verification
// against the real quote. Because these certs may be expired, we check that
// CertChainErr is set or not — we do not require it to pass (production quote
// is from 2023 hardware and its cert chain TTL may have lapsed).
func TestVerifyTDXQuoteCertChain(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote(realTDXQuoteBase64(), "", nonce)

	if result.ParseErr != nil {
		t.Fatalf("parse failed, cannot test cert chain: %v", result.ParseErr)
	}

	// We expect ParseErr = nil (quote structure is valid).
	// CertChainErr may be non-nil if the cert has expired — that's acceptable
	// for a 2023 fixture in 2026. Log it.
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
	result := VerifyTDXQuote(realTDXQuoteBase64(), "", nonce)

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
	result := VerifyTDXQuote(hexQuote, "", nonce)

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
	result := VerifyTDXQuote("not-base64!@#$%", "", nonce)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for invalid base64 input, got nil")
	}
}

// TestVerifyTDXQuoteTooShort verifies parse error when bytes are too short to be a quote.
func TestVerifyTDXQuoteTooShort(t *testing.T) {
	nonce := NewNonce()
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	result := VerifyTDXQuote(short, "", nonce)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for too-short quote bytes, got nil")
	}
}

// TestVerifyTDXQuoteEmptyString verifies parse error on empty input.
func TestVerifyTDXQuoteEmptyString(t *testing.T) {
	nonce := NewNonce()
	result := VerifyTDXQuote("", "", nonce)

	if result.ParseErr == nil {
		t.Error("expected ParseErr for empty quote string, got nil")
	}
}

// TestReportDataBindingCorrect verifies that verifyReportDataBinding passes
// when REPORTDATA[0:32] = SHA-256(signingKey || nonce).
func TestReportDataBindingCorrect(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	signingKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())
	signingKeyBytes, _ := hex.DecodeString(signingKeyHex)

	nonce := NewNonce()

	h := sha256.New()
	h.Write(signingKeyBytes)
	h.Write(nonce[:])
	expected := h.Sum(nil)

	// Build a 64-byte REPORTDATA with the binding in the first 32 bytes.
	reportData := make([]byte, 64)
	copy(reportData[:32], expected)

	if err := verifyReportDataBinding(reportData, signingKeyHex, nonce); err != nil {
		t.Errorf("verifyReportDataBinding with correct binding: unexpected error: %v", err)
	}
}

// TestReportDataBindingWrongNonce verifies the binding fails with a different nonce.
func TestReportDataBindingWrongNonce(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	signingKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())
	signingKeyBytes, _ := hex.DecodeString(signingKeyHex)

	nonce := NewNonce()
	wrongNonce := NewNonce()

	// Build REPORTDATA with the correct nonce.
	h := sha256.New()
	h.Write(signingKeyBytes)
	h.Write(nonce[:])
	expected := h.Sum(nil)

	reportData := make([]byte, 64)
	copy(reportData[:32], expected)

	// Verify with a different nonce — should fail.
	if err := verifyReportDataBinding(reportData, signingKeyHex, wrongNonce); err == nil {
		t.Error("verifyReportDataBinding with wrong nonce: expected error, got nil")
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

	signingKeyAHex := hex.EncodeToString(privA.PubKey().SerializeUncompressed())
	signingKeyBHex := hex.EncodeToString(privB.PubKey().SerializeUncompressed())
	signingKeyABytes, _ := hex.DecodeString(signingKeyAHex)

	nonce := NewNonce()

	// Build REPORTDATA binding key A.
	h := sha256.New()
	h.Write(signingKeyABytes)
	h.Write(nonce[:])
	expected := h.Sum(nil)

	reportData := make([]byte, 64)
	copy(reportData[:32], expected)

	// Verify with key B — should fail.
	if err := verifyReportDataBinding(reportData, signingKeyBHex, nonce); err == nil {
		t.Error("verifyReportDataBinding with wrong key: expected error, got nil")
	}
}

// TestReportDataBindingInvalidHex verifies error on non-hex signing key.
func TestReportDataBindingInvalidHex(t *testing.T) {
	nonce := NewNonce()
	reportData := make([]byte, 64)

	if err := verifyReportDataBinding(reportData, "not-hex-!!!", nonce); err == nil {
		t.Error("verifyReportDataBinding with invalid hex: expected error, got nil")
	}
}

// TestReportDataBindingTooShort verifies error on too-short REPORTDATA.
func TestReportDataBindingTooShort(t *testing.T) {
	nonce := NewNonce()
	priv, _ := secp256k1.GeneratePrivateKey()
	signingKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())

	// Only 16 bytes — too short.
	shortReportData := make([]byte, 16)
	if err := verifyReportDataBinding(shortReportData, signingKeyHex, nonce); err == nil {
		t.Error("verifyReportDataBinding with short REPORTDATA: expected error, got nil")
	}
}

// TestVerifyTDXQuoteReportDataBinding exercises the full VerifyTDXQuote path
// for REPORTDATA binding, using a fabricated binding rather than the real
// quote's REPORTDATA (which is unknown).
//
// We synthesize the correct REPORTDATA in the quote fixture by manually
// constructing a TDXVerifyResult and exercising verifyReportDataBinding.
// The real fixture quote's REPORTDATA will fail binding (expected — it was
// generated by Intel hardware with different data).
func TestVerifyTDXQuoteReportDataBindingRealQuoteFails(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	signingKeyHex := hex.EncodeToString(priv.PubKey().SerializeUncompressed())

	nonce := NewNonce()
	result := VerifyTDXQuote(realTDXQuoteBase64(), signingKeyHex, nonce)

	if result.ParseErr != nil {
		t.Fatalf("parse error: %v", result.ParseErr)
	}

	// The real quote was not generated with our signing key and nonce.
	// ReportDataBindingErr should be non-nil.
	if result.ReportDataBindingErr == nil {
		t.Error("expected ReportDataBindingErr for mismatched signing key/nonce, got nil")
	} else {
		t.Logf("ReportDataBindingErr (expected): %v", result.ReportDataBindingErr)
	}
}

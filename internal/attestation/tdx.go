package attestation

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"

	tdxabi "github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

// TDXVerifyResult holds the structured outcome of TDX quote parsing and
// verification. Fields are populated even on partial failure so the report
// builder can produce precise per-factor results.
type TDXVerifyResult struct {
	// ParseErr is non-nil if the base64 decode or quote parse step failed.
	// When ParseErr is set, all downstream fields are zero/nil.
	ParseErr error

	// CertChainErr is non-nil if PCK certificate chain verification failed.
	CertChainErr error

	// SignatureErr is non-nil if the quote signature verification failed.
	SignatureErr error

	// DebugEnabled is true if TD_ATTRIBUTES byte 0 bit 0 is set (debug enclave).
	DebugEnabled bool

	// ReportData is the raw 64-byte REPORTDATA field from the TDX quote body.
	ReportData [64]byte

	// ReportDataBindingErr is non-nil if REPORTDATA does not match the expected
	// binding of SHA-256(signing_key_bytes || nonce_bytes).
	ReportDataBindingErr error

	// TeeTCBSVN is the raw 16-byte TEE_TCB_SVN field for TCB currency checks.
	TeeTCBSVN []byte

	// quote is the successfully parsed quote proto (QuoteV4 or QuoteV5).
	quote any
}

// tdxDebugBit is bit 0 of byte 0 of TD_ATTRIBUTES. When set the TD is in
// debug mode and its memory can be inspected by the host.
const tdxDebugBit = 0x01

// VerifyTDXQuote decodes the base64-encoded intel_quote, parses it as a TDX
// QuoteV4, checks the certificate chain and signature (without fetching Intel
// PCS collateral — that would require a network call), checks the debug flag,
// and validates REPORTDATA binding to the signing key and nonce.
//
// signingKeyHex is the raw.SigningKey value (130 hex chars, uncompressed
// secp256k1 public key). It is used to compute the expected REPORTDATA binding.
//
// This function never panics. All errors are captured in the returned result.
func VerifyTDXQuote(base64Quote, signingKeyHex string, nonce Nonce) *TDXVerifyResult {
	result := &TDXVerifyResult{}

	raw, err := decodeQuoteBytes(base64Quote)
	if err != nil {
		result.ParseErr = err
		return result
	}

	slog.Debug("TDX quote decoded", "raw_bytes", len(raw))

	// Parse raw bytes into a QuoteV4 or QuoteV5 proto.
	quoteAny, err := tdxabi.QuoteToProto(raw)
	if err != nil {
		result.ParseErr = fmt.Errorf("TDX quote parse failed: %w", err)
		return result
	}
	result.quote = quoteAny

	// Extract common fields from whichever quote version we got.
	var reportData, tdAttrs, teeTCBSVN []byte
	switch q := quoteAny.(type) {
	case *pb.QuoteV4:
		slog.Debug("TDX quote version", "version", 4)
		body := q.GetTdQuoteBody()
		if body == nil {
			result.ParseErr = fmt.Errorf("TDX QuoteV4 body is nil after parse")
			return result
		}
		reportData = body.GetReportData()
		tdAttrs = body.GetTdAttributes()
		teeTCBSVN = body.GetTeeTcbSvn()
	case *pb.QuoteV5:
		slog.Debug("TDX quote version", "version", 5)
		desc := q.GetTdQuoteBodyDescriptor()
		if desc == nil {
			result.ParseErr = fmt.Errorf("TDX QuoteV5 body descriptor is nil after parse")
			return result
		}
		body := desc.GetTdQuoteBodyV5()
		if body == nil {
			result.ParseErr = fmt.Errorf("TDX QuoteV5 body is nil after parse")
			return result
		}
		reportData = body.GetReportData()
		tdAttrs = body.GetTdAttributes()
		teeTCBSVN = body.GetTeeTcbSvn()
	default:
		result.ParseErr = fmt.Errorf("unexpected quote type %T", quoteAny)
		return result
	}

	// Extract REPORTDATA (64 bytes).
	copy(result.ReportData[:], reportData)

	// Extract TEE_TCB_SVN.
	result.TeeTCBSVN = teeTCBSVN

	// Factor 6: debug flag. TD_ATTRIBUTES is 8 bytes; bit 0 of byte 0 is debug.
	if len(tdAttrs) > 0 && (tdAttrs[0]&tdxDebugBit) != 0 {
		result.DebugEnabled = true
	}

	// Factors 4 + 5: certificate chain and signature verification.
	// We use verify.TdxQuote without collateral fetching (GetCollateral=false).
	// This checks the PCK cert chain against Intel's embedded root CA and
	// verifies the quote signature, but does not fetch CRLs or TCB info.
	opts := &tdxverify.Options{
		GetCollateral:    false,
		CheckRevocations: false,
	}
	if verifyErr := tdxverify.TdxQuote(quoteAny, opts); verifyErr != nil {
		// The verify library does cert chain + signature in one call.
		// Record both as failed; they share the same root cause.
		result.CertChainErr = verifyErr
		result.SignatureErr = verifyErr
	}

	// Factor 8: REPORTDATA binding.
	// Expected: SHA-256(signing_key_bytes || nonce_bytes) in the first 32 bytes,
	// with the remaining 32 bytes zero-padded.
	// This is the binding scheme documented in Venice's attestation design.
	if signingKeyHex != "" {
		result.ReportDataBindingErr = verifyReportDataBinding(result.ReportData[:], signingKeyHex, nonce)
	}

	return result
}

// decodeQuoteBytes tries hex, base64, and base64url decoding.
// Venice returns hex-encoded quotes; other providers may use base64.
func decodeQuoteBytes(s string) ([]byte, error) {
	if raw, err := hex.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.URLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return nil, fmt.Errorf("quote decode failed (tried hex, base64, base64url)")
}

// verifyReportDataBinding checks whether reportData (64 bytes) contains the
// expected binding of SHA-256(signing_key_bytes || nonce_bytes).
//
// Venice's scheme: REPORTDATA[0:32] = SHA-256(signingKey || nonce)
// REPORTDATA[32:64] may be zeros or additional data — we only check the first half.
func verifyReportDataBinding(reportData []byte, signingKeyHex string, nonce Nonce) error {
	if len(reportData) < 32 {
		return fmt.Errorf("REPORTDATA too short: %d bytes, expected at least 32", len(reportData))
	}

	signingKeyBytes, err := hex.DecodeString(signingKeyHex)
	if err != nil {
		return fmt.Errorf("signing key is not valid hex: %w", err)
	}

	// Compute SHA-256(signing_key_bytes || nonce_bytes).
	h := sha256.New()
	h.Write(signingKeyBytes)
	h.Write(nonce[:])
	expected := h.Sum(nil) // 32 bytes

	if subtle.ConstantTimeCompare(expected, reportData[:32]) != 1 {
		return fmt.Errorf("REPORTDATA[0:32] = %s, expected SHA-256(signing_key||nonce) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected))
	}
	return nil
}

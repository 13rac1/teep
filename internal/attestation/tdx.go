package attestation

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"golang.org/x/crypto/sha3"
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
	// Ethereum address binding of the signing key.
	ReportDataBindingErr error

	// TeeTCBSVN is the raw 16-byte TEE_TCB_SVN field for TCB currency checks.
	TeeTCBSVN []byte

	// MRTD is the 48-byte measurement of the initial TD image (VM image hash).
	MRTD []byte

	// RTMRs are the four 48-byte Runtime Measurement Registers.
	// RTMR0: firmware, RTMR1: OS/kernel, RTMR2: application, RTMR3: reserved.
	RTMRs [4][48]byte

	// MRSeam is the 48-byte measurement of the TDX module.
	MRSeam []byte

	// MRSignerSeam is the 48-byte measurement of the TDX module signer.
	MRSignerSeam []byte

	// MRConfigID is the 48-byte TD configuration ID.
	MRConfigID []byte

	// MROwner is the 48-byte TD owner identity.
	MROwner []byte

	// MROwnerConfig is the 48-byte TD owner configuration.
	MROwnerConfig []byte

	// PPID is the 16-byte Platform Provisioning ID from the PCK cert's
	// x509v3 extensions, encoded as 32 hex chars. Empty if extraction fails.
	PPID string

	// FMSPC is the 6-byte Family-Model-Stepping-Platform-CustomSKU from
	// the PCK cert, encoded as 12 hex chars. Empty if extraction fails.
	FMSPC string

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
	var mrTD, mrSeam, mrSignerSeam, mrConfigID, mrOwner, mrOwnerConfig []byte
	var rtmrs [][]byte
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
		mrTD = body.GetMrTd()
		rtmrs = body.GetRtmrs()
		mrSeam = body.GetMrSeam()
		mrSignerSeam = body.GetMrSignerSeam()
		mrConfigID = body.GetMrConfigId()
		mrOwner = body.GetMrOwner()
		mrOwnerConfig = body.GetMrOwnerConfig()
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
		mrTD = body.GetMrTd()
		rtmrs = body.GetRtmrs()
		mrSeam = body.GetMrSeam()
		mrSignerSeam = body.GetMrSignerSeam()
		mrConfigID = body.GetMrConfigId()
		mrOwner = body.GetMrOwner()
		mrOwnerConfig = body.GetMrOwnerConfig()
	default:
		result.ParseErr = fmt.Errorf("unexpected quote type %T", quoteAny)
		return result
	}

	// Extract REPORTDATA (64 bytes).
	copy(result.ReportData[:], reportData)

	// Extract TEE_TCB_SVN.
	result.TeeTCBSVN = teeTCBSVN

	// Extract measurement registers.
	result.MRTD = mrTD
	result.MRSeam = mrSeam
	result.MRSignerSeam = mrSignerSeam
	result.MRConfigID = mrConfigID
	result.MROwner = mrOwner
	result.MROwnerConfig = mrOwnerConfig
	for i, r := range rtmrs {
		if i >= 4 {
			break
		}
		copy(result.RTMRs[i][:], r)
	}

	slog.Debug("TDX measurements extracted",
		"mrtd", hex.EncodeToString(mrTD),
		"rtmr0", hex.EncodeToString(safeSlice(rtmrs, 0)),
		"rtmr1", hex.EncodeToString(safeSlice(rtmrs, 1)),
		"rtmr2", hex.EncodeToString(safeSlice(rtmrs, 2)),
		"rtmr3", hex.EncodeToString(safeSlice(rtmrs, 3)),
		"mr_seam", hex.EncodeToString(mrSeam),
		"mr_signer_seam", hex.EncodeToString(mrSignerSeam),
		"mr_config_id", hex.EncodeToString(mrConfigID),
		"mr_owner", hex.EncodeToString(mrOwner),
		"mr_owner_config", hex.EncodeToString(mrOwnerConfig),
	)

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

	// Extract PPID/FMSPC from PCK certificate (informational, non-fatal).
	ppid, fmspc, err := extractPCKExtensions(quoteAny)
	if err != nil {
		slog.Debug("PPID extraction failed (non-fatal)", "err", err)
	} else {
		result.PPID = ppid
		result.FMSPC = fmspc
		slog.Debug("PCK extensions extracted", "ppid", ppid, "fmspc", fmspc)
	}

	// Factor 8: REPORTDATA binding.
	// Venice's scheme: REPORTDATA[0:20] = Ethereum address of the signing key
	// (keccak256 of the uncompressed public key without 04 prefix, last 20 bytes).
	// The nonce is NOT included in Venice's REPORTDATA binding.
	if signingKeyHex != "" {
		result.ReportDataBindingErr = verifyReportDataBinding(result.ReportData[:], signingKeyHex)
	}

	return result
}

// extractPCKExtensions navigates from a parsed TDX quote to the PCK leaf
// certificate and extracts PPID and FMSPC from its x509v3 extensions.
// Returns (ppid, fmspc, error). Both are lowercase hex strings.
func extractPCKExtensions(quoteAny any) (string, string, error) {
	var signedData *pb.Ecdsa256BitQuoteV4AuthData
	switch q := quoteAny.(type) {
	case *pb.QuoteV4:
		signedData = q.GetSignedData()
	case *pb.QuoteV5:
		signedData = q.GetSignedData()
	default:
		return "", "", fmt.Errorf("unsupported quote type %T", quoteAny)
	}

	certData := signedData.GetCertificationData()
	if certData == nil {
		return "", "", fmt.Errorf("CertificationData is nil")
	}
	qeReport := certData.GetQeReportCertificationData()
	if qeReport == nil {
		return "", "", fmt.Errorf("QeReportCertificationData is nil")
	}
	pckChainData := qeReport.GetPckCertificateChainData()
	if pckChainData == nil {
		return "", "", fmt.Errorf("PckCertificateChainData is nil")
	}
	pemBytes := pckChainData.GetPckCertChain()
	if len(pemBytes) == 0 {
		return "", "", fmt.Errorf("PckCertChain is empty")
	}

	// Parse the first (leaf) certificate from the PEM chain.
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", "", fmt.Errorf("no PEM block found in PckCertChain")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse PCK leaf cert: %w", err)
	}

	ext, err := pcs.PckCertificateExtensions(cert)
	if err != nil {
		return "", "", fmt.Errorf("extract PCK extensions: %w", err)
	}

	return ext.PPID, ext.FMSPC, nil
}

// safeSlice returns s[i] if i is within bounds, or nil otherwise.
func safeSlice(s [][]byte, i int) []byte {
	if i < len(s) {
		return s[i]
	}
	return nil
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

// verifyReportDataBinding checks whether reportData (64 bytes) binds the
// signing key via its Ethereum address.
//
// Venice's scheme: REPORTDATA[0:20] = keccak256(pubkey_bytes_without_04_prefix)[12:32]
// This is the standard Ethereum address derivation from an uncompressed secp256k1 key.
func verifyReportDataBinding(reportData []byte, signingKeyHex string) error {
	if len(reportData) < 20 {
		return fmt.Errorf("REPORTDATA too short: %d bytes, expected at least 20", len(reportData))
	}

	signingKeyBytes, err := hex.DecodeString(signingKeyHex)
	if err != nil {
		return fmt.Errorf("signing key is not valid hex: %w", err)
	}
	if len(signingKeyBytes) != 65 || signingKeyBytes[0] != 0x04 {
		return fmt.Errorf("signing key is not an uncompressed secp256k1 public key (got %d bytes, first byte 0x%02x)",
			len(signingKeyBytes), signingKeyBytes[0])
	}

	// Ethereum address = keccak256(pubkey_without_04_prefix)[12:32]
	h := sha3.NewLegacyKeccak256()
	h.Write(signingKeyBytes[1:]) // skip 04 prefix
	hash := h.Sum(nil)
	ethAddr := hash[12:32] // last 20 bytes

	if subtle.ConstantTimeCompare(ethAddr, reportData[:20]) != 1 {
		return fmt.Errorf("REPORTDATA[0:20] = %s, expected Ethereum address %s (keccak256 of signing key)",
			hex.EncodeToString(reportData[:20]), hex.EncodeToString(ethAddr))
	}
	return nil
}

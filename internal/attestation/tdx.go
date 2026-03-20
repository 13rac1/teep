package attestation

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	tdxabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// TDXVerifyResult holds the structured outcome of TDX quote parsing and
// verification. Fields are populated even on partial failure so the report
// builder can produce precise per-factor results.
type TDXVerifyResult struct {
	// ParseErr is non-nil if the hex decode or quote parse step failed.
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
	// binding. Set by the provider's ReportDataVerifier after VerifyTDXQuote.
	ReportDataBindingErr error

	// ReportDataBindingDetail is a human-readable description of the binding
	// that was verified (e.g. "REPORTDATA binds signing key via Ethereum address").
	// Set by the provider's ReportDataVerifier on success.
	ReportDataBindingDetail string

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

	// CollateralErr is non-nil if Intel PCS collateral fetch or validation failed.
	// When set, TcbStatus and AdvisoryIDs are empty.
	CollateralErr error

	// TcbStatus is the Intel-determined TCB level: UpToDate, SWHardeningNeeded,
	// OutOfDate, Revoked, etc. Empty when collateral is not fetched.
	TcbStatus pcs.TcbComponentStatus

	// AdvisoryIDs lists Intel Security Advisory IDs applicable to this TCB level.
	AdvisoryIDs []string

	// quote is the successfully parsed quote proto (QuoteV4 or QuoteV5).
	quote any
}

// tdxDebugBit is bit 0 of byte 0 of TD_ATTRIBUTES. When set the TD is in
// debug mode and its memory can be inspected by the host.
const tdxDebugBit = 0x01

// VerifyTDXQuote decodes the hex-encoded intel_quote, parses it as a TDX
// QuoteV4, checks the certificate chain and signature, optionally fetches Intel
// PCS collateral for TCB currency checks, and checks the debug flag.
//
// REPORTDATA binding is NOT checked here — it is provider-specific and must be
// performed by the provider's ReportDataVerifier after this function returns.
//
// When offline is false, collateral is fetched from api.trustedservices.intel.com
// in a second verification pass. This populates TcbStatus and AdvisoryIDs.
// When offline is true, collateral is not fetched and those fields remain empty.
//
// This function never panics. All errors are captured in the returned result.
func VerifyTDXQuote(ctx context.Context, hexQuote string, nonce Nonce, offline bool) *TDXVerifyResult {
	result := &TDXVerifyResult{}

	raw, err := decodeQuoteBytes(hexQuote)
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
			result.ParseErr = errors.New("TDX QuoteV4 body is nil after parse")
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
			result.ParseErr = errors.New("TDX QuoteV5 body descriptor is nil after parse")
			return result
		}
		body := desc.GetTdQuoteBodyV5()
		if body == nil {
			result.ParseErr = errors.New("TDX QuoteV5 body is nil after parse")
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
	// Pass 1: verify cert chain + signature without collateral (no network).
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

	// Pass 2 (online only): fetch Intel PCS collateral for TCB currency checks.
	// This is a separate pass so a collateral network error doesn't mask
	// a successful cert chain / signature verification from pass 1.
	if !offline {
		collateralOpts := &tdxverify.Options{
			GetCollateral:    true,
			CheckRevocations: true,
			Getter: &trust.RetryHTTPSGetter{
				Timeout:       30 * time.Second,
				MaxRetryDelay: 5 * time.Second,
				Getter:        &trust.SimpleHTTPSGetter{},
			},
		}
		if err := tdxverify.TdxQuoteContext(ctx, quoteAny, collateralOpts); err != nil {
			result.CollateralErr = fmt.Errorf("intel PCS collateral: %w", err)
			slog.Debug("TDX collateral verification failed (non-fatal for cert chain)", "err", err)
		} else {
			tcbLevel, _, err := tdxverify.SupportedTcbLevelsFromCollateral(quoteAny, collateralOpts)
			if err != nil {
				result.CollateralErr = fmt.Errorf("TCB level extraction: %w", err)
				slog.Debug("TCB level extraction failed", "err", err)
			} else {
				result.TcbStatus = tcbLevel.TcbStatus
				result.AdvisoryIDs = tcbLevel.AdvisoryIDs
				slog.Debug("TCB level extracted", "status", tcbLevel.TcbStatus, "date", tcbLevel.TcbDate, "advisories", tcbLevel.AdvisoryIDs)
			}
		}
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

	return result
}

// extractPCKExtensions navigates from a parsed TDX quote to the PCK leaf
// certificate and extracts PPID and FMSPC from its x509v3 extensions.
// Returns (ppid, fmspc, error). Both are lowercase hex strings.
func extractPCKExtensions(quoteAny any) (ppid, fmspc string, err error) {
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
		return "", "", errors.New("CertificationData is nil")
	}
	qeReport := certData.GetQeReportCertificationData()
	if qeReport == nil {
		return "", "", errors.New("QeReportCertificationData is nil")
	}
	pckChainData := qeReport.GetPckCertificateChainData()
	if pckChainData == nil {
		return "", "", errors.New("PckCertificateChainData is nil")
	}
	pemBytes := pckChainData.GetPckCertChain()
	if len(pemBytes) == 0 {
		return "", "", errors.New("PckCertChain is empty")
	}

	// Parse the first (leaf) certificate from the PEM chain.
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", "", errors.New("no PEM block found in PckCertChain")
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

// decodeQuoteBytes decodes a hex-encoded TDX quote.
func decodeQuoteBytes(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("TDX quote hex decode failed: %w", err)
	}
	return raw, nil
}

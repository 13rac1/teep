package attestation

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

// AMDKDSHost is the hostname for AMD's Key Distribution Service.
// Used to route KDS requests through a TLS 1.2 fallback transport,
// since KDS does not support TLS 1.3.
const AMDKDSHost = "kdsintf.amd.com"

// sevClientHTTPSGetter adapts an *http.Client to the trust.HTTPSGetter
// interface used by go-sev-guest (which differs from go-tdx-guest's interface).
type sevClientHTTPSGetter struct{ client *http.Client }

func (g *sevClientHTTPSGetter) Get(url string) ([]byte, error) {
	return g.GetContext(context.Background(), url)
}

func (g *sevClientHTTPSGetter) GetContext(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	tlsct.SetUserAgent(req)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve %s, status code received %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCertResponseSize {
		return nil, fmt.Errorf("KDS response body exceeds %d bytes", maxCertResponseSize)
	}
	return body, nil
}

// maxCertResponseSize is the maximum body size accepted from any
// AMD KDS or Intel PCS certificate endpoint.
const maxCertResponseSize = 256 << 10 // 256 KiB — typical cert chains are well under 10 KiB

// NewSEVCertGetter adapts the shared attestation client to certificate retrieval.
// The client owns retry policy, including immediate capacity-error rejection.
func NewSEVCertGetter(client *http.Client) trust.HTTPSGetter {
	return &sevClientHTTPSGetter{client: client}
}

// SEVTCBVersion contains the TCB version components from an SEV-SNP report.
type SEVTCBVersion struct {
	BlSpl    uint8
	TeeSpl   uint8
	SnpSpl   uint8
	UcodeSpl uint8
}

// SEVVerifyResult holds the structured outcome of SEV-SNP report parsing and
// verification. Fields are populated even on partial failure so the report
// builder can produce precise per-factor results.
type SEVVerifyResult struct {
	// Validity bounds reuse by the successfully verified AMD certificate chain.
	Validity EvidenceValidity

	// ParseErr is non-nil if the binary report parse step failed.
	ParseErr error

	// SignatureErr is non-nil if the report signature verification failed.
	SignatureErr error

	// CertChainErr is non-nil if VCEK certificate chain verification failed.
	CertChainErr error

	// DebugEnabled is true if the guest policy debug bit is set.
	DebugEnabled bool

	// ReportData is the raw 64-byte REPORT_DATA field from the SEV-SNP report.
	ReportData [64]byte

	// Measurement is the 48-byte launch measurement from the report.
	Measurement []byte

	// GuestPolicy is the raw 8-byte guest policy from the report.
	GuestPolicy uint64

	// PolicyErr is non-nil if guest policy validation failed.
	PolicyErr error

	// TCBErr is non-nil if TCB minimum validation failed.
	TCBErr error

	// CurrentTCB contains the TCB version components from the report.
	CurrentTCB SEVTCBVersion

	// OnlineVerified is true when AMD KDS was contacted and the report
	// signature and VCEK cert chain were verified against the AMD root.
	OnlineVerified bool

	// ReportDataBindingErr is non-nil if REPORTDATA does not match the
	// expected binding. Set by the provider's ReportDataVerifier.
	ReportDataBindingErr error

	// ReportDataBindingDetail describes the verified binding on success.
	ReportDataBindingDetail string
}

// Guest policy minimums.
const (
	sevMinBuild        = 21
	sevMinMajorVersion = 1
	sevMinMinorVersion = 55
)

// TCB component minimums.
const (
	sevMinBlSpl    = 0x07
	sevMinTeeSpl   = 0x00
	sevMinSnpSpl   = 0x0e
	sevMinUcodeSpl = 0x48
)

// VerifySEVReportOffline parses the raw binary SEV-SNP attestation report,
// validates the guest policy and TCB version, and checks the debug flag.
// Signature and certificate chain verification are NOT performed offline
// because they require the VCEK certificate from AMD KDS.
//
// This function never panics. All errors are captured in the returned result.
func VerifySEVReportOffline(ctx context.Context, report []byte) *SEVVerifyResult {
	result := &SEVVerifyResult{}

	// Parse the binary report into a proto.
	parsed, err := sevabi.ReportToProto(report)
	if err != nil {
		result.ParseErr = fmt.Errorf("SEV-SNP report parse failed: %w", err)
		return result
	}

	slog.DebugContext(ctx, "SEV-SNP report parsed",
		"version", parsed.GetVersion(),
		"policy", parsed.GetPolicy(),
	)

	// Extract REPORT_DATA (64 bytes).
	copy(result.ReportData[:], parsed.GetReportData())

	// Extract measurement (48 bytes).
	result.Measurement = parsed.GetMeasurement()

	// Extract guest policy.
	result.GuestPolicy = parsed.GetPolicy()

	// Extract and decompose TCB version.
	tcb := kds.DecomposeTCBVersion(kds.TCBVersion(parsed.GetCurrentTcb()))
	result.CurrentTCB = SEVTCBVersion{
		BlSpl:    tcb.BlSpl,
		TeeSpl:   tcb.TeeSpl,
		SnpSpl:   tcb.SnpSpl,
		UcodeSpl: tcb.UcodeSpl,
	}

	slog.DebugContext(ctx, "SEV-SNP fields extracted",
		"measurement", hex.EncodeToString(result.Measurement),
		"report_data", hex.EncodeToString(result.ReportData[:]),
		"current_tcb_bl", tcb.BlSpl,
		"current_tcb_tee", tcb.TeeSpl,
		"current_tcb_snp", tcb.SnpSpl,
		"current_tcb_ucode", tcb.UcodeSpl,
	)

	// Check debug bit via parsed policy.
	policy, err := sevabi.ParseSnpPolicy(result.GuestPolicy)
	if err != nil {
		result.PolicyErr = fmt.Errorf("SEV-SNP policy parse failed: %w", err)
		return result
	}

	result.DebugEnabled = policy.Debug

	// Log the raw guest policy and platform_info bitmasks plus their
	// hazard/identity bits, decoded by name, so a changed value can be found by
	// text search in every attestation without decoding raw report bytes by
	// hand. platform_info is
	// a separate 8-byte little-endian field at report offset 0x40; go-sev-guest
	// parses it directly off the report proto.
	platformInfo := parsed.GetPlatformInfo()
	logArgs := []any{
		"guest_policy", fmt.Sprintf("0x%016x", result.GuestPolicy),
		"snp_debug", policy.Debug,
		"migrate_ma", policy.MigrateMA,
		"smt_allowed", policy.SMT,
		"platform_info", fmt.Sprintf("0x%016x", platformInfo),
	}
	platInfo, platErr := sevabi.ParseSnpPlatformInfo(platformInfo)
	if platErr != nil {
		slog.DebugContext(ctx, "SEV-SNP platform_info parse failed (non-fatal)", "err", platErr, "platform_info", fmt.Sprintf("0x%016x", platformInfo))
	} else {
		logArgs = append(logArgs, "smt_en", platInfo.SMTEnabled, "tsme_en", platInfo.TSMEEnabled)
	}
	slog.DebugContext(ctx, "SEV-SNP guest policy and platform info extracted", logArgs...)

	// Validate guest policy.
	result.PolicyErr = validateSEVPolicy(policy, parsed)

	// Validate TCB minimums.
	result.TCBErr = validateSEVTCB(result.CurrentTCB)

	return result
}

// validateSEVPolicy checks that the guest policy meets our security requirements.
func validateSEVPolicy(policy sevabi.SnpPolicy, report *pb.Report) error {
	if policy.MigrateMA {
		return errors.New("SEV-SNP policy: MigrateMA must be disabled")
	}
	if !policy.SMT {
		return errors.New("SEV-SNP policy: SMT must be enabled")
	}
	if policy.Debug {
		return errors.New("SEV-SNP policy: debug must be disabled")
	}
	if policy.SingleSocket {
		return errors.New("SEV-SNP policy: SingleSocket must be disabled")
	}

	build := report.GetCurrentBuild()
	if build < sevMinBuild {
		return fmt.Errorf("SEV-SNP policy: build %d < minimum %d", build, sevMinBuild)
	}

	major := report.GetCurrentMajor()
	minor := report.GetCurrentMinor()
	if major < sevMinMajorVersion || (major == sevMinMajorVersion && minor < sevMinMinorVersion) {
		return fmt.Errorf("SEV-SNP policy: version %d.%d < minimum %d.%d", major, minor, sevMinMajorVersion, sevMinMinorVersion)
	}

	return nil
}

// validateSEVTCB checks that the TCB version components meet minimum thresholds.
func validateSEVTCB(tcb SEVTCBVersion) error {
	if tcb.BlSpl < sevMinBlSpl {
		return fmt.Errorf("SEV-SNP TCB: BlSpl 0x%02x < minimum 0x%02x", tcb.BlSpl, sevMinBlSpl)
	}
	if tcb.TeeSpl < sevMinTeeSpl {
		return fmt.Errorf("SEV-SNP TCB: TeeSpl 0x%02x < minimum 0x%02x", tcb.TeeSpl, sevMinTeeSpl)
	}
	if tcb.SnpSpl < sevMinSnpSpl {
		return fmt.Errorf("SEV-SNP TCB: SnpSpl 0x%02x < minimum 0x%02x", tcb.SnpSpl, sevMinSnpSpl)
	}
	if tcb.UcodeSpl < sevMinUcodeSpl {
		return fmt.Errorf("SEV-SNP TCB: UcodeSpl 0x%02x < minimum 0x%02x", tcb.UcodeSpl, sevMinUcodeSpl)
	}
	return nil
}

// VerifySEVReportOnline calls VerifySEVReportOffline for policy/TCB validation,
// then uses the AMD Key Distribution Service to fetch the VCEK certificate and
// verify the report signature and certificate chain.
//
// This function never panics. All errors are captured in the returned result.
func VerifySEVReportOnline(ctx context.Context, report []byte, getter trust.HTTPSGetter) *SEVVerifyResult {
	result := VerifySEVReportOffline(ctx, report)
	if result.ParseErr != nil {
		return result
	}

	validity, err := verifySEVEvidence(ctx, report, getter)
	if err != nil {
		result.CertChainErr = err
		result.SignatureErr = err
		slog.DebugContext(ctx, "SEV-SNP online verification failed", "err", err)
	} else {
		result.OnlineVerified = true
		result.Validity = validity
	}

	return result
}

// SEVVerifier verifies a raw binary SEV-SNP attestation report.
// Obtain via NewSEVVerifier.
type SEVVerifier func(ctx context.Context, report []byte) *SEVVerifyResult

// NewSEVVerifier returns a SEVVerifier for the given mode. If offline is true,
// AMD KDS certs are not fetched and signature/cert chain verification is skipped.
func NewSEVVerifier(offline bool, getter trust.HTTPSGetter) SEVVerifier {
	if offline {
		return VerifySEVReportOffline
	}
	return func(ctx context.Context, report []byte) *SEVVerifyResult {
		return VerifySEVReportOnline(ctx, report, getter)
	}
}

// verifySEVEvidence retains the certificates used by successful verification.
func verifySEVEvidence(ctx context.Context, raw []byte, getter trust.HTTPSGetter) (validity EvidenceValidity, retErr error) {
	report, err := sevabi.ReportToProto(raw)
	if err != nil {
		return EvidenceValidity{}, err
	}
	if getter == nil {
		return EvidenceValidity{}, errors.New("SEV certificate getter is required")
	}
	// go-sev-guest converts certificate fetch errors to text. Preserve their
	// causes within this verification, without sharing failure state across callers.
	observed := &sevEvidenceGetter{base: getter}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, observed.failure())
		}
	}()
	opts := &sevverify.Options{Getter: observed}
	evidence, err := sevverify.GetAttestationFromReportContext(ctx, report, opts)
	if err != nil {
		return EvidenceValidity{}, err
	}
	if err := sevverify.SnpAttestationContext(ctx, evidence, opts); err != nil {
		return EvidenceValidity{}, err
	}
	return verifiedSEVCertificateValidity(evidence)
}

// verifiedSEVCertificateValidity is called only after SnpAttestationContext
// succeeds with the default embedded AMD roots. Supplied ASK/ARK certificates
// are not trust anchors and must not determine the authorization lifetime.
func verifiedSEVCertificateValidity(evidence *pb.Attestation) (EvidenceValidity, error) {
	info, err := sevabi.ParseSignerInfo(evidence.GetReport().GetSignerInfo())
	if err != nil {
		return EvidenceValidity{}, err
	}
	productLine := kds.ProductLine(evidence.GetProduct())
	if fms := evidence.GetReport().GetCpuid1EaxFms(); fms != 0 {
		productLine = kds.ProductLineFromFms(fms)
	}
	root, err := trust.GetDefaultRootCerts(productLine)
	if err != nil {
		return EvidenceValidity{}, err
	}
	der, intermediate := evidence.GetCertificateChain().GetVcekCert(), root.ProductCerts.Ask
	if info.SigningKey == sevabi.VlekReportSigner {
		der, intermediate = evidence.GetCertificateChain().GetVlekCert(), root.ProductCerts.Asvk
	}
	leaf, err := trust.ParseCert(der)
	if err != nil {
		return EvidenceValidity{}, err
	}
	if intermediate == nil || root.ProductCerts.Ark == nil {
		return EvidenceValidity{}, errors.New("verified SEV chain is missing its trusted issuer")
	}
	bound, err := verifiedEvidenceValidity(leaf.NotAfter)
	if err != nil {
		return EvidenceValidity{}, err
	}
	for _, expiry := range []time.Time{intermediate.NotAfter, root.ProductCerts.Ark.NotAfter} {
		issuerBound, err := verifiedEvidenceValidity(expiry)
		if err != nil {
			return EvidenceValidity{}, err
		}
		bound = minimumEvidenceValidity(bound, issuerBound)
	}
	return bound, nil
}

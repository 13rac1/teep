package attestation

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

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

// NewSEVCertGetter wraps an *http.Client as a trust.HTTPSGetter with retry
// logic for AMD KDS certificate fetches.
func NewSEVCertGetter(client *http.Client) trust.HTTPSGetter {
	return &trust.RetryHTTPSGetter{
		Timeout:       30 * time.Second,
		MaxRetryDelay: 5 * time.Second,
		Getter:        &sevClientHTTPSGetter{client: client},
	}
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

	// Validate guest policy.
	result.PolicyErr = validateSEVPolicy(policy, parsed)

	// Validate TCB minimums.
	result.TCBErr = validateSEVTCB(result.CurrentTCB)

	return result
}

// validateSEVPolicy checks that the guest policy meets our security requirements.
func validateSEVPolicy(policy sevabi.SnpPolicy, report *pb.Report) error {
	if policy.MigrateMA {
		return fmt.Errorf("SEV-SNP policy: MigrateMA must be disabled")
	}
	if !policy.SMT {
		return fmt.Errorf("SEV-SNP policy: SMT must be enabled")
	}
	if policy.Debug {
		return fmt.Errorf("SEV-SNP policy: debug must be disabled")
	}
	if policy.SingleSocket {
		return fmt.Errorf("SEV-SNP policy: SingleSocket must be disabled")
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

	// Use RawSnpReportContext which handles VCEK cert fetching, chain
	// verification, and signature verification in one call.
	opts := &sevverify.Options{
		Getter: getter,
	}
	if err := sevverify.RawSnpReportContext(ctx, report, opts); err != nil {
		// Record both cert chain and signature as failed; they share the
		// same root cause from the unified verify call.
		result.CertChainErr = err
		result.SignatureErr = err
		slog.DebugContext(ctx, "SEV-SNP online verification failed", "err", err)
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

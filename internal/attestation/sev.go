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
//
// Online verification invariant: assuming ParseErr == nil, at most one of
// the following holds after VerifySEVReportOnline returns: FetchErr != nil
// (AMD KDS unreachable and no cached chain — an availability failure, not a
// forgery signal); SignatureErr != nil and/or CertChainErr != nil (the
// fetched or cached chain was obtained, but cryptographic verification
// failed — a forgery signal); or OnlineVerified == true (verification
// succeeded). This lets the report builder distinguish an unreachable AMD
// KDS from AMD KDS rejecting this chip/report as fraudulent.
type SEVVerifyResult struct {
	// ParseErr is non-nil if the binary report parse step failed.
	ParseErr error

	// FetchErr is non-nil when the VCEK certificate chain could not be
	// obtained: AMD KDS was unreachable (or returned an error) and no
	// unexpired cached chain was available. This is an availability
	// signal, not a cryptographic forgery signal, and is mutually
	// exclusive with SignatureErr/CertChainErr.
	FetchErr error

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

	// OnlineVerified is true when a VCEK certificate chain (freshly
	// fetched from AMD KDS or served from cache) was obtained and the
	// report signature and VCEK cert chain both verified against the AMD
	// root.
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

// VerifySEVReportOnline calls VerifySEVReportOffline for policy/TCB
// validation, then verifies the report's signature and VCEK certificate
// chain in two phases:
//
//  1. Fetch: obtain the VCEK/ASK/ARK certificate chain, either from cache
//     (sevFetchChain) or freshly from AMD KDS. If both the cache misses and
//     the KDS fetch fails, this is recorded as FetchErr (an availability
//     failure) and verification stops there — a chain that was never
//     obtained cannot be cryptographically attributed as forged.
//  2. Crypto-verify: with the chain in hand, verify the report signature and
//     certificate chain against the embedded AMD root — no network access
//     (sevAttributeCryptoResult). Success sets OnlineVerified and populates
//     the cache; failure attributes the fault to SignatureErr or
//     CertChainErr.
//
// This function never panics. All errors are captured in the returned result.
func VerifySEVReportOnline(ctx context.Context, report []byte, cache *SEVCertCache, getter trust.HTTPSGetter, verifyNow time.Time) *SEVVerifyResult {
	result := VerifySEVReportOffline(ctx, report)
	if result.ParseErr != nil {
		return result
	}

	// Offline parsing above already succeeded on these exact bytes, so this
	// re-parse cannot fail in practice; handled defensively rather than
	// panicking or ignoring the error.
	reportProto, err := sevabi.ReportToProto(report)
	if err != nil {
		result.ParseErr = fmt.Errorf("SEV-SNP report re-parse failed: %w", err)
		return result
	}

	key := sevCacheKey(reportProto.GetChipId(), reportProto.GetReportedTcb())
	chain, err := sevFetchChain(ctx, cache, key, reportProto, getter, verifyNow)
	if err != nil {
		result.FetchErr = fmt.Errorf("VCEK certificate chain unavailable: %w", err)
		slog.WarnContext(ctx, "SEV-SNP VCEK fetch failed and no cached chain available; cannot verify", "err", err)
		return result
	}

	sevAttributeCryptoResult(ctx, result, reportProto, chain, verifyNow)
	if result.OnlineVerified {
		cache.Put(key, chain)
	}
	return result
}

// sevFetchChain returns the VCEK certificate chain for reportProto, either
// from cache or freshly fetched from AMD KDS via GetAttestationFromReportContext.
// Every error returned here is a fetch/availability error (per the
// go-sev-guest v0.15.0 API: VCEK fetch failures are wrapped in
// trust.AttestationRecreationErr); no cryptographic verification happens in
// this step.
func sevFetchChain(ctx context.Context, cache *SEVCertCache, key string, reportProto *pb.Report, getter trust.HTTPSGetter, verifyNow time.Time) (*pb.CertificateChain, error) {
	if chain, ok := cache.Get(key); ok {
		return chain, nil
	}
	att, err := sevverify.GetAttestationFromReportContext(ctx, reportProto, &sevverify.Options{
		Getter: getter,
		Now:    verifyNow,
	})
	if err != nil {
		return nil, err
	}
	return att.GetCertificateChain(), nil
}

// sevAttributeCryptoResult runs the offline (no-network) cryptographic
// verification of reportProto against chain and records the outcome on
// result: OnlineVerified on success, or SignatureErr/CertChainErr on
// failure. On failure, the report signature is independently re-checked via
// SnpProtoReportSignature to attribute the fault: if the signature alone is
// bad, SignatureErr is set; otherwise the fault is attributed to the
// certificate chain. If both are bad, SnpAttestationContext's chain check
// runs first, so only SignatureErr is set (CertChainErr renders Skip via
// cross-fault in the report) — security is unaffected, since at least one
// crypto factor blocks; only the human-readable attribution is imprecise.
func sevAttributeCryptoResult(ctx context.Context, result *SEVVerifyResult, reportProto *pb.Report, chain *pb.CertificateChain, verifyNow time.Time) {
	att := &pb.Attestation{Report: reportProto, CertificateChain: chain}
	combErr := sevverify.SnpAttestationContext(ctx, att, &sevverify.Options{
		DisableCertFetching: true,
		Now:                 verifyNow,
	})
	if combErr == nil {
		result.OnlineVerified = true
		return
	}

	vcek, parseErr := trust.ParseCert(chain.GetVcekCert())
	if parseErr != nil {
		result.CertChainErr = fmt.Errorf("VCEK cert chain verification failed: %w", combErr)
		slog.DebugContext(ctx, "SEV-SNP online verification failed; VCEK cert unparseable for attribution", "err", combErr, "parse_err", parseErr)
		return
	}
	if sigErr := sevverify.SnpProtoReportSignature(reportProto, vcek); sigErr != nil {
		result.SignatureErr = fmt.Errorf("SEV-SNP report signature invalid: %w", sigErr)
	} else {
		result.CertChainErr = fmt.Errorf("VCEK cert chain verification failed: %w", combErr)
	}
	slog.DebugContext(ctx, "SEV-SNP online verification failed", "err", combErr)
}

// SEVVerifier verifies a raw binary SEV-SNP attestation report.
// Obtain via NewSEVVerifier.
type SEVVerifier func(ctx context.Context, report []byte) *SEVVerifyResult

// NewSEVVerifier returns a SEVVerifier for the given mode. If offline is
// true, AMD KDS certs are not fetched and signature/cert chain verification
// is skipped. In online mode, a dedicated *SEVCertCache is constructed and
// captured by the returned closure — owned per-verifier (no package-level
// state) so repeated calls through the same SEVVerifier reuse it, absorbing
// AMD KDS flakiness after the first successful fetch/verify.
//
// verifyNow is the time used for certificate validity checks; the zero
// value means "use the real wall clock" (matches go-sev-guest's own
// Options.Now default), which is what replay/fixture verification threads
// through to keep aging fixtures verifying correctly regardless of when the
// test runs.
func NewSEVVerifier(offline bool, getter trust.HTTPSGetter, verifyNow time.Time) SEVVerifier {
	if offline {
		return VerifySEVReportOffline
	}
	cache := NewSEVCertCache()
	return func(ctx context.Context, report []byte) *SEVVerifyResult {
		return VerifySEVReportOnline(ctx, report, cache, getter, verifyNow)
	}
}

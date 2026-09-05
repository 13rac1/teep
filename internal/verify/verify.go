package verify

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

// Options holds all parameters for Run.
type Options struct {
	Config         *config.Config
	Provider       *config.Provider
	ProviderName   string
	ModelName      string
	CaptureDir     string
	Offline        bool
	Client         *http.Client                // nil = use default
	Nonce          attestation.Nonce           // zero = generate new
	CapturedE2EE   *attestation.E2EETestResult // nil = run live test
	NVIDIAVerifier *attestation.NVIDIAVerifier // nil = use default
	// VerificationTime is the time used for cryptographic validity checks
	// during replay. Zero means use the verifier's live wall clock. It must
	// not affect context deadlines, HTTP timeouts, cache TTLs, or timing logs.
	VerificationTime time.Time

	capture *verificationCapture
}

// CfgLoader loads config and provider for the named provider.
type CfgLoader func(providerName string) (*config.Config, *config.Provider, error)

// Run loads the attester, fetches attestation, verifies TDX/NVIDIA/PoC,
// runs E2EE test, builds and returns the report.
//
// When opts.CaptureDir is non-empty, route discovery and the final attestation
// attempt are recorded and saved there. The E2EE self-test uses its own
// transport and is not captured. When opts.Client is non-nil, it replaces the default attestation
// client (used for replay). When opts.Nonce is non-zero, it replaces the
// generated nonce.
func Run(ctx context.Context, opts *Options) (report *attestation.VerificationReport, retErr error) {
	local := *opts
	if local.Client == nil {
		local.Client = config.NewAttestationClient(local.Offline)
		defer local.Client.CloseIdleConnections()
	}
	if nonceIsZero(local.Nonce) {
		local.Nonce = attestation.NewNonce()
	}
	var result verificationOutcome
	if local.CaptureDir != "" {
		local.capture = &verificationCapture{discovery: capture.WrapRecording(local.Client.Transport)}
		client := *local.Client
		client.Transport = local.capture.discovery
		local.Client = &client
		defer func() {
			retErr = saveCapture(ctx, opts, local.capture.entries(), local.Nonce, result.e2ee, report, retErr)
		}()
	}
	route := provider.ResolvedRoute{}
	if isTinfoilProvider(local.ProviderName) {
		result, retErr = runTLSVerification(ctx, &local, &route)
	} else {
		result, retErr = runEvidence(ctx, &local, &route)
	}
	return result.report, retErr
}

type verificationOutcome struct {
	report *attestation.VerificationReport
	raw    *attestation.RawAttestation
	e2ee   *attestation.E2EETestResult
}

func runEvidence(ctx context.Context, opts *Options, route *provider.ResolvedRoute) (out verificationOutcome, retErr error) {
	var report *attestation.VerificationReport
	cfg := opts.Config

	attester, err := newAttester(opts.ProviderName, opts.Provider, opts.Offline)
	if err != nil {
		return verificationOutcome{}, fmt.Errorf("attester init: %w", err)
	}

	client := opts.Client
	if client == nil {
		client = config.NewAttestationClient(opts.Offline)
		defer client.CloseIdleConnections()
	}

	nonce := opts.Nonce
	if nonceIsZero(nonce) {
		nonce = attestation.NewNonce()
	}

	var e2eeResult *attestation.E2EETestResult

	// Build per-call verifiers so concurrent Run calls don't race on a global.
	verifier := attestation.NewTDXVerifier(opts.Offline, attestation.NewCollateralGetter(client), opts.VerificationTime)
	sevVerifier := attestation.NewSEVVerifier(opts.Offline, attestation.NewSEVCertGetter(client))

	// Inject shared client into attester for capture/replay.
	type clientSetter interface{ SetClient(*http.Client) }
	if cs, ok := attester.(clientSetter); ok {
		cs.SetClient(client)
	}

	if isTinfoilProvider(opts.ProviderName) {
		attester, err = standaloneAttesterForRoute(ctx, opts, attester, route)
		if err != nil {
			return verificationOutcome{}, err
		}
	}

	if opts.capture != nil {
		opts.capture.beginEvidence(client)
	}

	slog.Debug("nonce generated", "provider", opts.ProviderName, "model", opts.ModelName, "nonce", nonce.Hex()[:16]+"...")

	raw, err := fetchAttestation(ctx, attester, opts.ProviderName, opts.ModelName, nonce)
	if err != nil {
		return verificationOutcome{}, fmt.Errorf("fetch attestation: %w", err)
	}

	tdxResult := verifyTDX(ctx, raw, nonce, opts.ProviderName, verifier)
	sevResult := verifySEV(ctx, raw, nonce, opts.ProviderName, sevVerifier)
	gatewaySEVResult := verifyGatewaySEV(ctx, raw, nonce, opts.ProviderName, sevVerifier)
	nv := opts.NVIDIAVerifier
	if nv == nil {
		nv = attestation.DefaultNVIDIAVerifier()
	}
	nvidiaResult, nrasResult := verifyNVIDIA(ctx, raw, nonce, client, opts.Offline, nv, nrasJWTParserOptions(opts.VerificationTime)...)
	pocResult := checkPoC(ctx, raw.IntelQuote, client, opts.Offline, opts.VerificationTime)

	// Model compose evidence (requires a parsed TDX quote).
	var composeResult *attestation.ComposeBindingResult
	var modelCD attestation.ComposeDigests
	if raw.AppCompose != "" && tdxResult != nil && tdxResult.ParseErr == nil {
		composeResult = &attestation.ComposeBindingResult{Checked: true}
		composeResult.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
		if composeResult.Err == nil {
			slog.Info("compose binding verified", "mr_config_id", hex.EncodeToString(tdxResult.MRConfigID[:min(33, len(tdxResult.MRConfigID))]))
			modelCD = attestation.ExtractComposeDigests(raw.AppCompose)
		} else {
			slog.Warn("compose binding failed", "err", composeResult.Err)
		}
	}

	// Gateway verification (nearcloud-specific fields).
	gatewayTDX, gatewayCompose, gatewayPoCResult := verifyNearcloudGateway(ctx, raw, nonce, client, opts.Offline, verifier, opts.VerificationTime)
	var gatewayCD attestation.ComposeDigests
	if gatewayCompose != nil && gatewayCompose.Err == nil {
		gatewayCD = attestation.ExtractComposeDigests(raw.GatewayAppCompose)
	}

	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, gatewayCD)
	scPolicy, err := supplyChainPolicy(opts.ProviderName)
	if err != nil {
		return verificationOutcome{}, fmt.Errorf("supply chain policy: %w", err)
	}
	// SYNC: proxy.fromConfig validates the same way at config load, so a
	// malformed policy fails before evaluation on both entry points.
	if err := scPolicy.Validate(); err != nil {
		return verificationOutcome{}, fmt.Errorf("supply chain policy: %w", err)
	}
	sigstoreResults, rekorResults := checkSigstore(ctx, allDigests, digestToRepo, scPolicy, client, opts.Offline)

	if opts.CapturedE2EE != nil {
		e2eeResult = opts.CapturedE2EE
	} else if !isTinfoilProvider(opts.ProviderName) || opts.Offline || opts.Provider.APIKey == "" {
		e2eeResult = testE2EE(ctx, raw, opts.ProviderName, opts.Provider, opts.ModelName, opts.Offline)
	}
	if e2eeResult != nil && e2eeResult.KeyType == "" {
		e2eeResult.KeyType = raw.E2EEKeyType()
	}

	mDefaults, gwDefaults := defaults.MeasurementDefaults(opts.ProviderName)
	mergedPolicy := config.MergedMeasurementPolicy(opts.ProviderName, cfg, mDefaults)
	mergedGWPolicy := config.MergedGatewayMeasurementPolicy(opts.ProviderName, cfg, gwDefaults)

	scSEV := attestation.SupplyChainSEVResult(sevResult, gatewaySEVResult)
	tinfoilSC := verifyTinfoilSupplyChain(ctx, raw, tdxResult, scSEV, opts.ProviderName, opts.ModelName, mergedPolicy, opts.Offline, client)

	report = attestation.BuildReport(&attestation.ReportInput{
		Provider:               opts.ProviderName,
		Model:                  opts.ModelName,
		Raw:                    raw,
		Nonce:                  nonce,
		AllowFail:              config.MergedAllowFail(opts.ProviderName, cfg, opts.Offline),
		Policy:                 mergedPolicy,
		GatewayPolicy:          mergedGWPolicy,
		SupplyChainPolicy:      scPolicy,
		TDX:                    tdxResult,
		SEV:                    sevResult,
		Nvidia:                 nvidiaResult,
		NvidiaNRAS:             nrasResult,
		PoC:                    pocResult,
		Compose:                composeResult,
		ImageRepos:             modelCD.Repos,
		GatewayImageRepos:      gatewayCD.Repos,
		DigestToRepo:           digestToRepo,
		Sigstore:               sigstoreResults,
		Rekor:                  rekorResults,
		GatewayTDX:             gatewayTDX,
		GatewaySEV:             gatewaySEVResult,
		GatewayPoC:             gatewayPoCResult,
		GatewayNonceHex:        raw.GatewayNonceHex,
		GatewayNonce:           nonce,
		GatewayCompose:         gatewayCompose,
		GatewayEventLog:        raw.GatewayEventLog,
		TinfoilSC:              tinfoilSC,
		E2EETest:               e2eeResult,
		E2EEConfigured:         isTinfoilProvider(opts.ProviderName) && opts.Provider.E2EE,
		Inapplicable:           inapplicableFactors(opts.ProviderName),
		ProviderUsesTLSBinding: providerUsesTLSBinding(opts.ProviderName),
		E2EEKeyBoundByGateway:  providerE2EEKeyBoundByGateway(opts.ProviderName),
	})

	return verificationOutcome{report: report, raw: raw, e2ee: e2eeResult}, nil
}

// Replay loads a capture directory, replays all HTTP traffic, and returns the
// verification report and formatted text.
func Replay(ctx context.Context, captureDir string, cfgLoader CfgLoader) (report *attestation.VerificationReport, reportText string, err error) {
	manifest, entries, err := capture.Load(captureDir)
	if err != nil {
		return nil, "", fmt.Errorf("load capture: %w", err)
	}
	slog.Info("replaying capture",
		"provider", manifest.Provider,
		"model", manifest.Model,
		"captured_at", manifest.CapturedAt.Format(time.RFC3339),
		"responses", len(entries),
	)

	nonce, err := attestation.ParseNonce(manifest.NonceHex)
	if err != nil {
		return nil, "", fmt.Errorf("invalid nonce in manifest: %w", err)
	}

	cfg, cp, err := cfgLoader(manifest.Provider)
	if err != nil {
		return nil, "", fmt.Errorf("load config for replay: %w", err)
	}

	replayClient := &http.Client{
		CheckRedirect: tlsct.RejectRedirect,
		Transport:     capture.NewReplayTransport(entries),
		Timeout:       config.AttestationTimeout,
	}

	capturedE2EE := e2eeResultFromOutcome(manifest.E2EE)
	report, err = Run(ctx, &Options{
		Config:           cfg,
		Provider:         cp,
		ProviderName:     manifest.Provider,
		ModelName:        manifest.Model,
		Offline:          false,
		Client:           replayClient,
		Nonce:            nonce,
		CapturedE2EE:     capturedE2EE,
		VerificationTime: verificationTimeForCapture(&manifest),
	})
	if err != nil {
		return nil, "", fmt.Errorf("replay verification: %w", err)
	}
	reportText = FormatReport(report)
	return report, reportText, nil
}

func verificationTimeForCapture(manifest *capture.Manifest) time.Time {
	if manifest == nil || manifest.CapturedAt.IsZero() {
		return time.Time{}
	}
	if manifest.DurationMS <= 0 {
		return manifest.CapturedAt
	}
	return manifest.CapturedAt.Add(time.Duration(manifest.DurationMS) * time.Millisecond)
}

// saveCapture writes the capture to disk and returns the error to set as retErr.
// It preserves a pre-existing run error over a save error so the caller always
// sees the primary failure.
func saveCapture(
	ctx context.Context,
	opts *Options,
	entries []capture.RecordedEntry,
	nonce attestation.Nonce,
	e2eeResult *attestation.E2EETestResult,
	report *attestation.VerificationReport,
	runErr error,
) error {
	reportText := ""
	if report != nil {
		reportText = FormatReport(report)
	} else if runErr != nil {
		reportText = "Error: " + runErr.Error() + "\n"
	}
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	var totalDuration time.Duration
	for i := range entries {
		totalDuration += entries[i].Duration
	}
	capturedAt := time.Now().UTC()
	if !opts.VerificationTime.IsZero() {
		capturedAt = opts.VerificationTime.Add(-totalDuration).UTC()
	}
	subdir, saveErr := capture.Save(opts.CaptureDir, &capture.Manifest{
		Provider:   opts.ProviderName,
		Model:      opts.ModelName,
		NonceHex:   nonce.Hex(),
		CapturedAt: capturedAt,
		DurationMS: totalDuration.Milliseconds(),
		E2EE:       outcomeFromE2EEResult(e2eeResult),
		Error:      errMsg,
	}, reportText, entries)
	if saveErr != nil {
		slog.Error("save capture failed", "err", saveErr)
		if runErr == nil {
			return fmt.Errorf("save capture: %w", saveErr)
		}
		return runErr
	}
	if errMsg != "" {
		slog.Info("capture saved on error", "dir", subdir, "responses", len(entries))
	} else {
		slog.Info("capture saved", "dir", subdir, "responses", len(entries))
	}
	// Self-check only on success — partial captures can't round-trip.
	if runErr != nil {
		return runErr
	}
	cfgLoader := func(_ string) (*config.Config, *config.Provider, error) {
		return opts.Config, opts.Provider, nil
	}
	if err := verifyCapture(ctx, subdir, reportText, cfgLoader); err != nil {
		return fmt.Errorf("capture self-check: %w", err)
	}
	return nil
}

// verifyCapture loads a just-saved capture and re-verifies it to confirm the
// capture round-trips cleanly.
func verifyCapture(ctx context.Context, captureDir, originalReport string, cfgLoader CfgLoader) error {
	_, reverifyText, err := Replay(ctx, captureDir, cfgLoader)
	if err != nil {
		return fmt.Errorf("verify capture: %w", err)
	}
	if err := CompareReports(originalReport, reverifyText); err != nil {
		return err
	}
	slog.Info("capture verified", "dir", captureDir)
	return nil
}

const reportFactorNameWidth = 33

// FormatReport renders a VerificationReport as a human-readable string.
func FormatReport(r *attestation.VerificationReport) string {
	var b strings.Builder

	title := r.Title
	if title == "" {
		title = "Attestation Report"
	}
	header := fmt.Sprintf("%s: %s / %s", title, r.Provider, r.Model)
	separator := strings.Repeat("\u2550", utf8.RuneCountInString(header)) // U+2550 BOX DRAWINGS DOUBLE HORIZONTAL

	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(separator)
	b.WriteString("\n\n")

	if len(r.Metadata) > 0 {
		writeMetadataBlock(&b, r.Metadata)
		b.WriteString("\n")
	}

	var currentTier string
	for _, f := range r.Factors {
		if f.Tier != currentTier {
			if currentTier != "" {
				b.WriteString("\n")
			}
			b.WriteString(f.Tier)
			b.WriteString("\n")
			currentTier = f.Tier
		}
		icon := statusIcon(f.Status)
		line := fmt.Sprintf("  %s %-*s %s", icon, reportFactorNameWidth, f.Name, f.Detail)
		switch {
		case f.Status == attestation.NotApplicable:
			// no enforcement tag for N/A factors
		case f.Enforced:
			line += "  [ENFORCED]"
		default:
			line += "  [ALLOWED]"
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	total := r.Passed + r.Failed + r.Skipped
	fmt.Fprintf(&b, "Score: %d/%d passed, %d skipped, %d failed",
		r.Passed, total, r.Skipped, r.Failed)
	if r.Failed > 0 {
		fmt.Fprintf(&b, " (%d enforced, %d allowed)", r.EnforcedFailed, r.AllowedFailed)
	}
	if r.NotApplicableCount > 0 {
		fmt.Fprintf(&b, ", %d n/a", r.NotApplicableCount)
	}
	b.WriteString("\n")
	b.WriteString("\nRun 'teep help tiers' for scoring or 'teep help factors' for details.\n")

	return b.String()
}

// statusIcon returns the display character for a factor's status.
func statusIcon(s attestation.Status) string {
	switch s {
	case attestation.Pass:
		return "\u2713" // ✓
	case attestation.Fail:
		return "\u2717" // ✗
	case attestation.Skip:
		return "-"
	case attestation.NotApplicable:
		return "\u2014" // — (em dash)
	}
	return "?"
}

// metadataDisplayOrder defines the order and labels for the metadata block.
var metadataDisplayOrder = []struct {
	key   string
	label string
}{
	{"hardware", "Hardware"},
	{"upstream", "Upstream"},
	{"app", "App"},
	{"compose_hash", "Compose hash"},
	{"os_image", "OS image"},
	{"device", "Device"},
	{"ppid", "PPID"},
	{"nonce_source", "Nonce source"},
	{"candidates", "Candidates"},
	{"event_log", "Event log"},
	// Self-check metadata
	{"version", "Version"},
	{"commit", "Commit"},
	{"vcs_revision", "VCS revision"},
	{"vcs_time", "VCS time"},
	{"go_version", "Go version"},
	{"module", "Module"},
	{"binary", "Binary"},
}

// writeMetadataBlock renders the metadata key-value pairs into b. Only keys
// present in the metadata map are printed, in the order defined above. Long
// hash values are truncated to keep lines under 80 columns.
func writeMetadataBlock(b *strings.Builder, meta map[string]string) {
	for _, entry := range metadataDisplayOrder {
		val, ok := meta[entry.key]
		if !ok {
			continue
		}
		// Truncate long hex hashes for display.
		if (entry.key == "compose_hash" || entry.key == "os_image" || entry.key == "device" || entry.key == "ppid" || entry.key == "commit" || entry.key == "vcs_revision") && len(val) > 16 {
			val = val[:16] + "..."
		}
		fmt.Fprintf(b, "  %-14s %s\n", entry.label+":", val)
	}
}

// CompareReports compares two formatted report strings exactly.
// On mismatch, prints a line-by-line diff to stderr and returns an error.
func CompareReports(captured, reverify string) error {
	if captured == reverify {
		return nil
	}
	fmt.Fprintln(os.Stderr, "--- MISMATCH: reverify report differs from capture ---")
	PrintReportDiff(captured, reverify)
	return errors.New("reverify report differs from capture")
}

// PrintReportDiff prints a positional line-by-line diff. This is correct
// because both reports are produced by FormatReport over the same factor
// list — lines cannot shift, only change in content.
func PrintReportDiff(a, b string) {
	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")
	for i := range max(len(aLines), len(bLines)) {
		var aLine, bLine string
		if i < len(aLines) {
			aLine = aLines[i]
		}
		if i < len(bLines) {
			bLine = bLines[i]
		}
		if aLine != bLine {
			if aLine != "" {
				fmt.Fprintf(os.Stderr, "- %s\n", aLine)
			}
			if bLine != "" {
				fmt.Fprintf(os.Stderr, "+ %s\n", bLine)
			}
		}
	}
}

func nonceIsZero(nonce attestation.Nonce) bool {
	var zero attestation.Nonce
	return subtle.ConstantTimeCompare(nonce[:], zero[:]) == 1
}

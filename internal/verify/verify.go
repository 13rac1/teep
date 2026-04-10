package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/defaults"
)

// Options holds all parameters for Run.
type Options struct {
	Config       *config.Config
	Provider     *config.Provider
	ProviderName string
	ModelName    string
	CaptureDir   string
	Offline      bool
	Client       *http.Client                // nil = use default
	Nonce        attestation.Nonce           // zero = generate new
	CapturedE2EE *attestation.E2EETestResult // nil = run live test
}

// CfgLoader loads config and provider for the named provider.
type CfgLoader func(providerName string) (*config.Config, *config.Provider, error)

// Run loads the attester, fetches attestation, verifies TDX/NVIDIA/PoC,
// runs E2EE test, builds and returns the report.
//
// When opts.CaptureDir is non-empty, all HTTP traffic is recorded and saved
// there. When opts.Client is non-nil, it replaces the default attestation
// client (used for replay). When opts.Nonce is non-zero, it replaces the
// generated nonce.
func Run(ctx context.Context, opts *Options) (*attestation.VerificationReport, error) {
	cfg := opts.Config
	cfg.Offline = opts.Offline

	attester, err := newAttester(opts.ProviderName, opts.Provider, opts.Offline)
	if err != nil {
		return nil, fmt.Errorf("attester init: %w", err)
	}

	client := opts.Client
	if client == nil {
		client = config.NewAttestationClient(opts.Offline)
	}
	attestation.TDXCollateralGetter = attestation.NewCollateralGetter(client)
	defer func() { attestation.TDXCollateralGetter = nil }()

	// Wrap transport with recording when capturing.
	var recorder *capture.RecordingTransport
	if opts.CaptureDir != "" {
		recorder = capture.WrapRecording(client.Transport)
		client.Transport = recorder
	}

	// Inject shared client into attester for capture/replay.
	type clientSetter interface{ SetClient(*http.Client) }
	if cs, ok := attester.(clientSetter); ok {
		cs.SetClient(client)
	}

	nonce := opts.Nonce
	if nonce == (attestation.Nonce{}) {
		nonce = attestation.NewNonce()
	}

	slog.Debug("nonce generated", "provider", opts.ProviderName, "model", opts.ModelName, "nonce", nonce.Hex()[:16]+"...")

	raw, err := fetchAttestation(ctx, attester, opts.ProviderName, opts.ModelName, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation: %w", err)
	}

	tdxResult := verifyTDX(ctx, raw, nonce, opts.ProviderName, opts.Offline)
	nvidiaResult, nrasResult := verifyNVIDIA(ctx, raw, nonce, client, opts.Offline)
	pocResult := checkPoC(ctx, raw.IntelQuote, client, opts.Offline)

	// Model compose evidence (gated on TDX).
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
	gatewayTDX, gatewayCompose, gatewayPoCResult := verifyNearcloudGateway(ctx, raw, nonce, client, opts.Offline)
	var gatewayCD attestation.ComposeDigests
	if gatewayCompose != nil && gatewayCompose.Err == nil {
		gatewayCD = attestation.ExtractComposeDigests(raw.GatewayAppCompose)
	}

	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, gatewayCD)
	sigstoreResults, rekorResults := checkSigstore(ctx, allDigests, client, opts.Offline)

	var e2eeResult *attestation.E2EETestResult
	if opts.CapturedE2EE != nil {
		e2eeResult = opts.CapturedE2EE
	} else {
		e2eeResult = testE2EE(ctx, raw, opts.ProviderName, opts.Provider, opts.ModelName, opts.Offline)
	}

	mDefaults, gwDefaults := defaults.MeasurementDefaults(opts.ProviderName)
	mergedPolicy := config.MergedMeasurementPolicy(opts.ProviderName, cfg, mDefaults)
	mergedGWPolicy := config.MergedGatewayMeasurementPolicy(opts.ProviderName, cfg, gwDefaults)

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          opts.ProviderName,
		Model:             opts.ModelName,
		Raw:               raw,
		Nonce:             nonce,
		AllowFail:         config.MergedAllowFail(opts.ProviderName, cfg),
		Policy:            mergedPolicy,
		GatewayPolicy:     mergedGWPolicy,
		SupplyChainPolicy: supplyChainPolicy(opts.ProviderName),
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           composeResult,
		ImageRepos:        modelCD.Repos,
		GatewayImageRepos: gatewayCD.Repos,
		DigestToRepo:      digestToRepo,
		Sigstore:          sigstoreResults,
		Rekor:             rekorResults,
		GatewayTDX:        gatewayTDX,
		GatewayPoC:        gatewayPoCResult,
		GatewayNonceHex:   raw.GatewayNonceHex,
		GatewayNonce:      nonce,
		GatewayCompose:    gatewayCompose,
		GatewayEventLog:   raw.GatewayEventLog,
		E2EETest:          e2eeResult,
	})

	// Save capture after building report so report.txt is available.
	if opts.CaptureDir != "" {
		reportText := FormatReport(report)
		subdir, saveErr := capture.Save(opts.CaptureDir, &capture.Manifest{
			Provider:   opts.ProviderName,
			Model:      opts.ModelName,
			NonceHex:   nonce.Hex(),
			CapturedAt: time.Now().UTC(),
			E2EE:       outcomeFromE2EEResult(e2eeResult),
		}, reportText, recorder.Entries)
		if saveErr != nil {
			return nil, fmt.Errorf("save capture: %w", saveErr)
		}
		slog.Info("capture saved", "dir", subdir, "responses", len(recorder.Entries))
		cfgLoader := func(_ string) (*config.Config, *config.Provider, error) {
			return opts.Config, opts.Provider, nil
		}
		if err := verifyCapture(ctx, subdir, reportText, cfgLoader); err != nil {
			return report, fmt.Errorf("capture self-check: %w", err)
		}
	}

	return report, nil
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
		Transport: capture.NewReplayTransport(entries),
		Timeout:   config.AttestationTimeout,
	}

	capturedE2EE := e2eeResultFromOutcome(manifest.E2EE)
	report, err = Run(ctx, &Options{
		Config:       cfg,
		Provider:     cp,
		ProviderName: manifest.Provider,
		ModelName:    manifest.Model,
		Offline:      false,
		Client:       replayClient,
		Nonce:        nonce,
		CapturedE2EE: capturedE2EE,
	})
	if err != nil {
		return nil, "", fmt.Errorf("replay verification: %w", err)
	}
	reportText = FormatReport(report)
	return report, reportText, nil
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

// FormatReport renders a VerificationReport as a human-readable string.
func FormatReport(r *attestation.VerificationReport) string {
	var b strings.Builder

	title := r.Title
	if title == "" {
		title = "Attestation Report"
	}
	header := fmt.Sprintf("%s: %s / %s", title, r.Provider, r.Model)
	separator := strings.Repeat("\u2550", len(header)) // U+2550 BOX DRAWINGS DOUBLE HORIZONTAL

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
		line := fmt.Sprintf("  %s %-26s %s", icon, f.Name, f.Detail)
		if f.Enforced {
			line += "  [ENFORCED]"
		} else {
			line += "  [ALLOWED]"
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Score: %d/%d passed, %d skipped, %d failed",
		r.Passed, r.Passed+r.Failed+r.Skipped, r.Skipped, r.Failed)
	if r.Failed > 0 {
		fmt.Fprintf(&b, " (%d enforced, %d allowed)", r.EnforcedFailed, r.AllowedFailed)
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
	default:
		return "?"
	}
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

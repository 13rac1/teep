// Command teep is the CLI entrypoint for the TEE proxy and attestation verifier.
//
// Usage:
//
//	teep serve      PROVIDER                Start the proxy server.
//	teep verify     PROVIDER --model M      Fetch and verify attestation, print report.
//	teep self-check                         Verify this binary's build provenance.
//	teep version                            Print version information.
//
// Configuration is loaded from $TEEP_CONFIG (TOML) and environment variables.
// See the config package for full documentation.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/proxy"
	"github.com/13rac1/teep/internal/reqid"
	"github.com/13rac1/teep/internal/tlsct"
)

func main() {
	if len(os.Args) < 2 {
		printOverview()
		os.Exit(1)
	}

	// Parse --log-level before the subcommand. It can appear anywhere in os.Args.
	level, err := parseLogLevel(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "teep: %v\n", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(reqid.NewHandler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))))

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "self-check":
		runSelfCheck(os.Args[2:])
	case "version":
		runVersion(os.Args[2:])
	case "-h", "--help", "help":
		runHelp(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "teep: unknown subcommand %q\n\n", os.Args[1])
		printOverview()
		os.Exit(1)
	}
}

// parseLogLevel extracts --log-level from args and returns the corresponding
// slog.Level. Defaults to slog.LevelInfo.
func parseLogLevel(args []string) (slog.Level, error) {
	for i, arg := range args {
		var val string
		if arg == "--log-level" && i+1 < len(args) {
			val = args[i+1]
		} else if after, ok := strings.CutPrefix(arg, "--log-level="); ok {
			val = after
		} else {
			continue
		}
		switch strings.ToLower(val) {
		case "debug":
			return slog.LevelDebug, nil
		case "info":
			return slog.LevelInfo, nil
		case "warn":
			return slog.LevelWarn, nil
		case "error":
			return slog.LevelError, nil
		default:
			return 0, fmt.Errorf("unknown log level %q (valid: debug, info, warn, error)", val)
		}
	}
	return slog.LevelInfo, nil
}

// runServe loads config, creates the proxy, and starts listening.
func runServe(args []string) {
	providerName, args := extractProvider(args)
	if providerName == "" {
		fmt.Fprintf(os.Stderr, "teep serve: provider is required\n\n")
		printServeHelp()
		os.Exit(1)
	}

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	offline := fs.Bool("offline", false, "skip external verification (Intel PCS, Proof of Cloud, Certificate Transparency)")
	force := registerForceFlag(fs)
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")
	fs.Usage = func() { printServeHelp() }
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}
	cfg.Offline = *offline

	if force != nil && *force {
		cfg.Force = true
		slog.Warn("--force enabled: requests will be forwarded even when enforced attestation factors fail")
	}

	if err := filterProviders(cfg, providerName); err != nil {
		slog.Error("provider filter failed", "err", err)
		os.Exit(1)
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		slog.Error("proxy init failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err = srv.ListenAndServe(ctx)
	stop()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
	slog.Info("server stopped")
}

// filterProviders narrows cfg.Providers to a single named provider.
func filterProviders(cfg *config.Config, providerName string) error {
	cp, ok := cfg.Providers[providerName]
	if !ok {
		return providerNotFoundError(providerName, cfg)
	}
	cfg.Providers = map[string]*config.Provider{providerName: cp}
	return nil
}

// providerEnvVars maps provider names to their API key environment variables.
var providerEnvVars = map[string]string{
	"venice":     "VENICE_API_KEY",
	"neardirect": "NEARAI_API_KEY",
	"nearcloud":  "NEARAI_API_KEY",
	"nanogpt":    "NANOGPT_API_KEY",
	"phalacloud": "PHALA_API_KEY",
	"chutes":     "CHUTES_API_KEY",
}

// providerNotFoundError returns a descriptive error when a provider is not configured.
func providerNotFoundError(name string, cfg *config.Config) error {
	envVar, known := providerEnvVars[name]
	if known && len(cfg.Providers) == 0 {
		return fmt.Errorf("provider %q not configured (set %s or add [providers.%s] to config)", name, envVar, name)
	}
	if known {
		return fmt.Errorf("provider %q not configured (set %s or add [providers.%s] to config; known: %s)", name, envVar, name, knownProviders(cfg))
	}
	return fmt.Errorf("provider %q not found (known: %s)", name, knownProviders(cfg))
}

// extractProvider returns the first arg as a provider name if it doesn't look
// like a flag, plus the remaining args for flag.Parse.
func extractProvider(args []string) (name string, rest []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}

// runVerify parses flags, fetches attestation from the named provider, builds
// the verification report, prints it to stdout, and exits with code 1 if any
// enforced factor failed (i.e. a factor not in the allow_fail list).
func runVerify(args []string) {
	providerName, args := extractProvider(args)

	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.Usage = func() { printVerifyHelp() }

	modelName := fs.String("model", "", "model name as known to the provider (required)")
	captureDir := fs.String("capture", "", "save all HTTP traffic to DIR for archival")
	reverifyDir := fs.String("reverify", "", "re-verify from a captured attestation directory")
	offline := fs.Bool("offline", false, "skip external verification (Intel PCS, Proof of Cloud, Certificate Transparency)")
	updateConfig := fs.Bool("update-config", false, "write observed measurements to the config file ($TEEP_CONFIG)")
	configOut := fs.String("config-out", "", "write updated config to this path instead of $TEEP_CONFIG")
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *reverifyDir != "" {
		runReverify(*reverifyDir)
		return
	}

	if providerName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: provider is required\n\n")
		printVerifyHelp()
		os.Exit(1)
	}
	if *modelName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: --model is required\n")
		fs.Usage()
		os.Exit(1)
	}

	report, err := runVerification(providerName, *modelName, *captureDir, *offline, nil, attestation.Nonce{}, nil)
	if err != nil {
		slog.Error("verification failed", "err", err)
		os.Exit(1)
	}
	fmt.Print(formatReport(report))

	blocked := report.Blocked()

	if *updateConfig || *configOut != "" {
		if blocked {
			fmt.Fprintf(os.Stderr, "teep verify: refusing --update-config: attestation blocked (measurements may be untrustworthy)\n")
			os.Exit(1)
		}
		outPath := *configOut
		if outPath == "" {
			outPath = os.Getenv("TEEP_CONFIG")
		}
		if outPath == "" {
			fmt.Fprintf(os.Stderr, "teep verify: --update-config requires $TEEP_CONFIG or --config-out\n")
			os.Exit(1)
		}
		observed := extractObserved(report)
		if err := config.UpdateConfig(outPath, providerName, &observed); err != nil {
			fmt.Fprintf(os.Stderr, "teep verify: update config: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Config updated: %s (provider %s)\n", outPath, providerName)
	}

	if blocked {
		os.Exit(1)
	}
}

// runReverify re-verifies attestation from a previously captured directory.
// All HTTP traffic is served from the saved responses via a replay transport.
func runReverify(captureDir string) {
	report, reverifyText, err := replayVerification(captureDir)
	if err != nil {
		slog.Error("replay verification failed", "err", err)
		os.Exit(1)
	}

	capturedText, loadErr := capture.LoadReport(captureDir)
	switch {
	case loadErr == nil:
		if err := compareReports(capturedText, reverifyText); err != nil {
			slog.Error("report comparison failed", "err", err)
			os.Exit(1)
		}
	case errors.Is(loadErr, os.ErrNotExist):
		slog.Warn("no captured report to compare (report.txt absent)")
	default:
		slog.Error("read captured report failed", "err", loadErr)
		os.Exit(1)
	}

	fmt.Print(reverifyText)
	if report.Blocked() {
		os.Exit(1)
	}
}

// replayVerification loads a capture directory, replays all HTTP traffic, and
// returns the verification report and formatted text.
func replayVerification(captureDir string) (report *attestation.VerificationReport, reportText string, err error) {
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

	replayClient := &http.Client{
		Transport: capture.NewReplayTransport(entries),
		Timeout:   config.AttestationTimeout,
	}

	capturedE2EE := e2eeResultFromOutcome(manifest.E2EE)
	report, err = runVerification(manifest.Provider, manifest.Model, "",
		false, replayClient, nonce, capturedE2EE)
	if err != nil {
		return nil, "", fmt.Errorf("replay verification: %w", err)
	}
	reportText = formatReport(report)
	return report, reportText, nil
}

// runVerification loads config, builds the appropriate attester, fetches
// attestation, runs TDX and NVIDIA verification, and returns the report.
//
// When captureDir is non-empty, all HTTP traffic is recorded and saved there.
// When overrideClient is non-nil, it replaces the default attestation client
// (used by --reverify to inject a replay transport). When overrideNonce is
// non-zero, it replaces the generated nonce. When capturedE2EE is non-nil,
// it replaces the live E2EE test (used by --reverify to inject the captured result).
func runVerification(providerName, modelName, captureDir string, offline bool,
	overrideClient *http.Client, overrideNonce attestation.Nonce, capturedE2EE *attestation.E2EETestResult,
) (*attestation.VerificationReport, error) {
	cfg, cp, err := loadConfig(providerName)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	cfg.Offline = offline
	attester, err := newAttester(providerName, cp, offline)
	if err != nil {
		return nil, fmt.Errorf("attester init: %w", err)
	}

	// Validate config before setting up deferred cleanup.
	var pocSigningKey ed25519.PublicKey
	if cfg.PoCSigningKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(cfg.PoCSigningKey)
		if err != nil {
			return nil, fmt.Errorf("poc_signing_key: invalid base64: %w", err)
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("poc_signing_key: wrong size: expected %d, got %d", ed25519.PublicKeySize, len(keyBytes))
		}
		pocSigningKey = ed25519.PublicKey(keyBytes)
		slog.Info("PoC JWT EdDSA signature verification enabled")
	}

	client := overrideClient
	if client == nil {
		client = config.NewAttestationClient(offline)
	}
	attestation.TDXCollateralGetter = attestation.NewCollateralGetter(client)
	defer func() { attestation.TDXCollateralGetter = nil }()

	// Wrap transport with recording when capturing.
	var recorder *capture.RecordingTransport
	if captureDir != "" {
		recorder = capture.WrapRecording(client.Transport)
		client.Transport = recorder
	}

	// Inject shared client into attester for capture/replay.
	type clientSetter interface{ SetClient(*http.Client) }
	if cs, ok := attester.(clientSetter); ok {
		cs.SetClient(client)
	}

	nonce := overrideNonce
	if nonce == (attestation.Nonce{}) {
		nonce = attestation.NewNonce()
	}

	slog.Debug("nonce generated", "provider", providerName, "model", modelName, "nonce", nonce.Hex()[:16]+"...")
	ctx := context.Background()

	raw, err := fetchAttestation(ctx, attester, providerName, modelName, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation: %w", err)
	}

	tdxResult := verifyTDX(ctx, raw, nonce, providerName, offline)
	nvidiaResult, nrasResult := verifyNVIDIA(ctx, raw, nonce, client, offline)
	pocResult := checkPoC(ctx, raw.IntelQuote, client, offline, pocSigningKey)

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
	gatewayTDX, gatewayCompose, gatewayPoCResult := verifyNearcloudGateway(ctx, raw, nonce, client, offline, pocSigningKey)
	var gatewayCD attestation.ComposeDigests
	if gatewayCompose != nil && gatewayCompose.Err == nil {
		gatewayCD = attestation.ExtractComposeDigests(raw.GatewayAppCompose)
	}

	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, gatewayCD)
	sigstoreResults, rekorResults := checkSigstore(ctx, allDigests, client, offline)

	var e2eeResult *attestation.E2EETestResult
	if capturedE2EE != nil {
		e2eeResult = capturedE2EE
	} else {
		e2eeResult = testE2EE(ctx, raw, providerName, cp, modelName, offline)
	}

	mDefaults, gwDefaults := defaults.MeasurementDefaults(providerName)
	mergedPolicy := config.MergedMeasurementPolicy(providerName, cfg, mDefaults)
	mergedGWPolicy := config.MergedGatewayMeasurementPolicy(providerName, cfg, gwDefaults)

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          providerName,
		Model:             modelName,
		Raw:               raw,
		Nonce:             nonce,
		AllowFail:         config.MergedAllowFail(providerName, cfg),
		Policy:            mergedPolicy,
		GatewayPolicy:     mergedGWPolicy,
		SupplyChainPolicy: supplyChainPolicy(providerName),
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
	if captureDir != "" {
		reportText := formatReport(report)
		subdir, saveErr := capture.Save(captureDir, &capture.Manifest{
			Provider:   providerName,
			Model:      modelName,
			NonceHex:   nonce.Hex(),
			CapturedAt: time.Now().UTC(),
			E2EE:       outcomeFromE2EEResult(e2eeResult),
		}, reportText, recorder.Entries)
		if saveErr != nil {
			return nil, fmt.Errorf("save capture: %w", saveErr)
		}
		slog.Info("capture saved", "dir", subdir, "responses", len(recorder.Entries))
		if err := verifyCapture(subdir, reportText); err != nil {
			return nil, fmt.Errorf("capture self-check: %w", err)
		}
	}

	return report, nil
}

// verifyCapture loads a just-saved capture and re-verifies it to confirm the
// capture round-trips cleanly.
func verifyCapture(captureDir, originalReport string) error {
	_, reverifyText, err := replayVerification(captureDir)
	if err != nil {
		return fmt.Errorf("verify capture: %w", err)
	}
	if err := compareReports(originalReport, reverifyText); err != nil {
		return err
	}
	slog.Info("capture verified", "dir", captureDir)
	return nil
}

// outcomeFromE2EEResult converts an attestation.E2EETestResult to a serializable E2EEOutcome.
// Returns nil if r is nil.
func outcomeFromE2EEResult(r *attestation.E2EETestResult) *capture.E2EEOutcome {
	if r == nil {
		return nil
	}
	o := &capture.E2EEOutcome{
		Attempted: r.Attempted,
		NoAPIKey:  r.NoAPIKey,
		APIKeyEnv: r.APIKeyEnv,
		Detail:    r.Detail,
	}
	if r.Err != nil {
		o.Failed = true
		o.ErrMsg = r.Err.Error()
	}
	return o
}

// e2eeResultFromOutcome converts a captured E2EEOutcome back to an attestation.E2EETestResult.
// Returns nil if o is nil.
func e2eeResultFromOutcome(o *capture.E2EEOutcome) *attestation.E2EETestResult {
	if o == nil {
		return nil
	}
	r := &attestation.E2EETestResult{
		Attempted: o.Attempted,
		NoAPIKey:  o.NoAPIKey,
		APIKeyEnv: o.APIKeyEnv,
		Detail:    o.Detail,
	}
	if o.Failed {
		// Err is reconstructed from the serialized message; type information is
		// lost across the capture boundary. Callers only check Err != nil.
		msg := o.ErrMsg
		if msg == "" {
			msg = "(error message lost across capture boundary)"
		}
		r.Err = errors.New(msg)
	}
	return r
}

// compareReports compares two formatted report strings exactly.
// On mismatch, prints a line-by-line diff to stderr and returns an error.
func compareReports(captured, reverify string) error {
	if captured == reverify {
		return nil
	}
	fmt.Fprintln(os.Stderr, "--- MISMATCH: reverify report differs from capture ---")
	printReportDiff(captured, reverify)
	return errors.New("reverify report differs from capture")
}

// printReportDiff prints a positional line-by-line diff. This is correct
// because both reports are produced by formatReport over the same factor
// list — lines cannot shift, only change in content.
func printReportDiff(a, b string) {
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

// extractObserved builds an ObservedMeasurements from the verification report
// metadata. Missing metadata keys result in empty strings (no policy change).
func extractObserved(report *attestation.VerificationReport) config.ObservedMeasurements {
	m := report.Metadata
	return config.ObservedMeasurements{
		MRSeam: m["mrseam"],
		MRTD:   m["mrtd"],
		RTMR0:  m["rtmr0"],
		RTMR1:  m["rtmr1"],
		RTMR2:  m["rtmr2"],
		// RTMR3 omitted: verified via event log replay, varies across instances.

		GatewayMRSeam: m["gateway_mrseam"],
		GatewayMRTD:   m["gateway_mrtd"],
		GatewayRTMR0:  m["gateway_rtmr0"],
		GatewayRTMR1:  m["gateway_rtmr1"],
		GatewayRTMR2:  m["gateway_rtmr2"],
		// Gateway RTMR3 omitted for the same reason as RTMR3.
	}
}

// loadConfig loads the TOML config and looks up the named provider.
func loadConfig(providerName string) (*config.Config, *config.Provider, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	cp, ok := cfg.Providers[providerName]
	if !ok {
		return nil, nil, providerNotFoundError(providerName, cfg)
	}
	return cfg, cp, nil
}

// fetchAttestation fetches raw attestation data from the provider with timing log.
func fetchAttestation(ctx context.Context, attester provider.Attester, providerName, modelName string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	slog.Debug("attestation fetch starting", "provider", providerName, "model", modelName)
	fetchStart := time.Now()
	raw, err := attester.FetchAttestation(ctx, modelName, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation from %s model %s: %w", providerName, modelName, err)
	}
	slog.Debug("attestation fetch complete", "provider", providerName, "elapsed", time.Since(fetchStart))
	return raw, nil
}

// verifyTDX runs TDX quote verification and report data binding.
// Returns nil if no intel_quote is present.
func verifyTDX(ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce, providerName string, offline bool) *attestation.TDXVerifyResult {
	if raw.IntelQuote == "" {
		return nil
	}
	slog.Debug("TDX verification starting", "quote_len", len(raw.IntelQuote))
	tdxStart := time.Now()
	tdxResult := attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, offline)
	if verifier := newReportDataVerifier(providerName); verifier != nil && tdxResult.ParseErr == nil {
		detail, err := verifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
		tdxResult.ReportDataBindingErr = err
		tdxResult.ReportDataBindingDetail = detail
	}
	slog.Debug("TDX verification complete", "elapsed", time.Since(tdxStart))
	return tdxResult
}

// verifyNVIDIA runs NVIDIA EAT and NRAS verification.
// Returns nil for either if not applicable.
func verifyNVIDIA(ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce, client *http.Client, offline bool) (eat, nras *attestation.NvidiaVerifyResult) {
	if raw.NvidiaPayload != "" {
		slog.DebugContext(ctx, "NVIDIA verification starting", "payload_len", len(raw.NvidiaPayload))
		nvidiaStart := time.Now()
		eat = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce)
		slog.DebugContext(ctx, "NVIDIA verification complete", "elapsed", time.Since(nvidiaStart))
	} else if len(raw.GPUEvidence) > 0 {
		serverNonce, err := attestation.ParseNonce(raw.Nonce)
		if err != nil {
			slog.Error("parse server nonce for GPU verification", "err", err)
			eat = &attestation.NvidiaVerifyResult{
				SignatureErr: fmt.Errorf("parse server nonce: %w", err),
			}
			return eat, nil
		}
		slog.DebugContext(ctx, "NVIDIA GPU direct verification starting", "gpus", len(raw.GPUEvidence))
		nvidiaStart := time.Now()
		eat = attestation.VerifyNVIDIAGPUDirect(ctx, raw.GPUEvidence, serverNonce)
		slog.DebugContext(ctx, "NVIDIA GPU direct verification complete", "elapsed", time.Since(nvidiaStart))
	}
	if !offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting")
		nrasStart := time.Now()
		nras = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete", "elapsed", time.Since(nrasStart))
	} else if !offline && len(raw.GPUEvidence) > 0 {
		eatJSON := attestation.GPUEvidenceToEAT(raw.GPUEvidence, raw.Nonce)
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting (synthesized EAT)")
		nrasStart := time.Now()
		nras = attestation.VerifyNVIDIANRAS(ctx, eatJSON, client)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete (synthesized EAT)", "elapsed", time.Since(nrasStart))
	}
	return eat, nras
}

// checkPoC runs a Proof of Cloud check for the given intel_quote.
// Returns nil if offline or quote is empty. When signingKey is non-nil,
// PoC JWT EdDSA signatures are verified.
func checkPoC(ctx context.Context, quote string, client *http.Client, offline bool, signingKey ed25519.PublicKey) *attestation.PoCResult {
	if offline || quote == "" {
		return nil
	}
	slog.Debug("Proof of Cloud check starting")
	pocStart := time.Now()
	var poc *attestation.PoCClient
	if signingKey != nil {
		poc = attestation.NewPoCClientWithSigningKey(attestation.PoCPeers, attestation.PoCQuorum, client, signingKey)
	} else {
		poc = attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, client)
	}
	result := poc.CheckQuote(ctx, quote)
	slog.Debug("Proof of Cloud check complete", "elapsed", time.Since(pocStart),
		"registered", result != nil && result.Registered)
	return result
}

// verifyNearcloudGateway verifies gateway TDX, compose binding, and PoC for
// providers that populate GatewayIntelQuote (nearcloud).
func verifyNearcloudGateway(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
	client *http.Client, offline bool, pocSigningKey ed25519.PublicKey,
) (tdx *attestation.TDXVerifyResult, compose *attestation.ComposeBindingResult, poc *attestation.PoCResult) {
	if raw.GatewayIntelQuote == "" {
		return nil, nil, nil
	}
	slog.Debug("gateway TDX verification starting", "quote_len", len(raw.GatewayIntelQuote))
	tdx = attestation.VerifyTDXQuote(ctx, raw.GatewayIntelQuote, nonce, offline)
	if tdx.ParseErr == nil {
		detail, rdErr := nearcloud.GatewayReportDataVerifier{}.VerifyReportData(
			tdx.ReportData, raw, nonce)
		tdx.ReportDataBindingErr = rdErr
		tdx.ReportDataBindingDetail = detail
	}
	if raw.GatewayAppCompose != "" && tdx.ParseErr == nil {
		compose = &attestation.ComposeBindingResult{Checked: true}
		compose.Err = attestation.VerifyComposeBinding(raw.GatewayAppCompose, tdx.MRConfigID)
	}
	poc = checkPoC(ctx, raw.GatewayIntelQuote, client, offline, pocSigningKey)
	slog.Debug("gateway TDX verification complete")
	return tdx, compose, poc
}

// checkSigstore checks sigstore digests and fetches Rekor provenance for matches.
func checkSigstore(ctx context.Context, digests []string, client *http.Client, offline bool) ([]attestation.SigstoreResult, []attestation.RekorProvenance) {
	if len(digests) == 0 || offline {
		return nil, nil
	}
	rc := attestation.NewRekorClient(client)
	sigstoreResults := rc.CheckSigstoreDigests(ctx, digests)
	for _, r := range sigstoreResults {
		switch {
		case r.OK:
			slog.Info("Sigstore check passed", "digest", "sha256:"+r.Digest[:min(16, len(r.Digest))]+"...", "status", r.Status)
		case r.Err != nil:
			slog.Warn("Sigstore check failed", "digest", "sha256:"+r.Digest[:min(16, len(r.Digest))]+"...", "err", r.Err)
		default:
			slog.Warn("Sigstore check failed", "digest", "sha256:"+r.Digest[:min(16, len(r.Digest))]+"...", "status", r.Status)
		}
	}
	var rekorResults []attestation.RekorProvenance
	for _, sr := range sigstoreResults {
		if !sr.OK {
			continue
		}
		slog.Info("fetching Rekor provenance", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...")
		prov := rc.FetchRekorProvenance(ctx, sr.Digest)
		switch {
		case prov.Err != nil:
			slog.Warn("Rekor provenance fetch failed", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...", "err", prov.Err)
		case prov.HasCert:
			slog.Info("Rekor provenance found",
				"digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...",
				"issuer", prov.OIDCIssuer,
				"repo", prov.SourceRepo,
				"commit", prov.SourceCommit[:min(7, len(prov.SourceCommit))],
				"runner", prov.RunnerEnv,
			)
		default:
			slog.Info("Rekor entry has raw public key (no Fulcio provenance)", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...")
		}
		rekorResults = append(rekorResults, prov)
	}
	return sigstoreResults, rekorResults
}

// newAttester returns the appropriate Attester for the named provider.
func newAttester(name string, cp *config.Provider, offline bool) (provider.Attester, error) {
	switch name {
	case "venice":
		return venice.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "neardirect":
		return neardirect.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "nearcloud":
		return nearcloud.NewAttester(cp.APIKey, offline), nil
	case "nanogpt":
		return nanogpt.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "phalacloud":
		return phalacloud.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "chutes":
		return chutes.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, neardirect, nearcloud, nanogpt, phalacloud, chutes)", name)
	}
}

func newReportDataVerifier(name string) provider.ReportDataVerifier {
	switch name {
	case "venice":
		return venice.ReportDataVerifier{}
	case "neardirect", "nearcloud":
		return neardirect.ReportDataVerifier{}
	case "nanogpt":
		// NanoGPT uses the same dstack REPORTDATA binding as Venice.
		return venice.ReportDataVerifier{}
	case "phalacloud":
		return multi.Verifier{
			Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
				attestation.FormatDstack: venice.ReportDataVerifier{},
			},
		}
	case "chutes":
		return chutes.ReportDataVerifier{}
	default:
		return nil
	}
}

func supplyChainPolicy(name string) *attestation.SupplyChainPolicy {
	switch name {
	case "venice":
		return venice.SupplyChainPolicy()
	case "neardirect":
		return neardirect.SupplyChainPolicy()
	case "nearcloud":
		return nearcloud.SupplyChainPolicy()
	case "nanogpt":
		return nanogpt.SupplyChainPolicy()
	case "phalacloud":
		return nil // no supply chain policy yet
	case "chutes":
		return nil // cosign+IMA model, no docker-compose
	default:
		return nil
	}
}

// e2eeEnabledByDefault reports whether the named provider has E2EE enabled
// by default in config.go's applyAPIKeyEnv.
func e2eeEnabledByDefault(name string) bool {
	switch name {
	case "venice", "nearcloud", "chutes":
		return true
	default:
		return false
	}
}

// chatPathForProvider returns the upstream chat completions path for the named provider.
func chatPathForProvider(name string) string {
	switch name {
	case "venice":
		return "/api/v1/chat/completions"
	case "nearcloud", "neardirect", "nanogpt":
		return "/v1/chat/completions"
	case "chutes":
		return "/v1/chat/completions"
	default:
		return ""
	}
}

// testE2EE runs a live E2EE test inference if the provider is E2EE-capable.
// Returns nil if the provider doesn't support E2EE, signalling callers
// to skip. Returns a result with NoAPIKey=true if the API key is missing, or
// with Err set on any failure.
func testE2EE(ctx context.Context, raw *attestation.RawAttestation, providerName string, cp *config.Provider, model string, offline bool) *attestation.E2EETestResult {
	if !e2eeEnabledByDefault(providerName) {
		return nil
	}
	if raw.SigningKey == "" {
		return nil // e2ee_capable will fail; no point testing
	}
	if offline {
		return &attestation.E2EETestResult{Detail: "offline mode; E2EE test skipped"}
	}
	envVar := providerEnvVars[providerName]
	if cp.APIKey == "" {
		return &attestation.E2EETestResult{NoAPIKey: true, APIKeyEnv: envVar}
	}

	switch providerName {
	case "venice":
		return testE2EEVenice(ctx, raw, cp, model)
	case "nearcloud":
		return testE2EENearCloud(ctx, raw, cp, model)
	case "chutes":
		return testE2EEChutes(ctx, raw, cp, model)
	default:
		return nil
	}
}

// testE2EEVenice tests Venice E2EE (secp256k1 ECDH + AES-256-GCM).
func testE2EEVenice(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("create session: %w", err)}
	}
	defer session.Zero()

	if err := session.SetModelKey(raw.SigningKey); err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("set model key: %w", err)}
	}

	ct, err := e2ee.EncryptVenice([]byte("Say hello"), session.ModelPubKey())
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("encrypt: %w", err)}
	}

	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": ct}},
		"stream":   true,
	})
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("marshal body: %w", err)}
	}

	chatURL := cp.BaseURL + chatPathForProvider("venice")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(body))
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Venice-Tee-Client-Pub-Key", session.ClientPubKeyHex())
	req.Header.Set("X-Venice-Tee-Model-Pub-Key", raw.SigningKey)
	req.Header.Set("X-Venice-Tee-Signing-Algo", "ecdsa")
	req.Header.Set("Authorization", "Bearer "+cp.APIKey)
	req.Header.Set("Connection", "close")

	return doE2EEStreamTest(req, session, "venice")
}

// testE2EENearCloud tests NearCloud E2EE (Ed25519/XChaCha20-Poly1305) via
// direct HTTPS request with E2EE headers.
func testE2EENearCloud(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Say hello"}},
		"stream":   true,
	})
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("marshal body: %w", err)}
	}

	encBody, session, err := e2ee.EncryptChatMessagesNearCloud(body, raw.SigningKey)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("encrypt v2: %w", err)}
	}
	defer session.Zero()

	baseURL := cp.BaseURL
	if baseURL == "" {
		baseURL = "https://cloud-api.near.ai"
	}
	chatURL := baseURL + chatPathForProvider("nearcloud")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatURL, bytes.NewReader(encBody))
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signing-Algo", "ed25519")
	req.Header.Set("X-Client-Pub-Key", session.ClientEd25519PubHex())
	req.Header.Set("X-Encryption-Version", "2")
	req.Header.Set("Authorization", "Bearer "+cp.APIKey)
	req.Header.Set("Connection", "close")

	return doE2EEStreamTest(req, session, "nearcloud")
}

// testE2EEChutes tests Chutes E2EE (ML-KEM-768 + ChaCha20-Poly1305) via
// direct HTTPS request to the /e2e/invoke endpoint.
func testE2EEChutes(ctx context.Context, raw *attestation.RawAttestation, cp *config.Provider, model string) *attestation.E2EETestResult {
	if raw.InstanceID == "" {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("chutes E2EE: instance_id absent from attestation")}
	}
	if raw.E2ENonce == "" {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("chutes E2EE: e2e_nonce absent from attestation")}
	}

	// Use the resolved chute UUID for the X-Chute-Id header.
	// FetchAttestation resolves model names to UUIDs and stores the
	// result in raw.ChuteID.
	chuteID := raw.ChuteID
	if chuteID == "" {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("chutes E2EE: chute_id absent from attestation")}
	}

	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "Say hello"}},
		"stream":   true,
	})
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("marshal body: %w", err)}
	}

	encPayload, session, err := e2ee.EncryptChatRequestChutes(body, raw.SigningKey)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("encrypt: %w", err)}
	}
	defer session.Zero()

	baseURL := cp.BaseURL
	if baseURL == "" {
		baseURL = "https://api.chutes.ai"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/e2e/invoke", bytes.NewReader(encPayload))
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+cp.APIKey)
	req.Header.Set("X-Chute-Id", chuteID)
	req.Header.Set("X-Instance-Id", raw.InstanceID)
	req.Header["X-E2E-Nonce"] = []string{raw.E2ENonce}
	req.Header["X-E2E-Stream"] = []string{"true"}
	req.Header["X-E2E-Path"] = []string{chatPathForProvider("chutes")}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Connection", "close")

	return doE2EEChutesStreamTest(req, session)
}

// doE2EEChutesStreamTest sends an encrypted Chutes E2EE request and validates
// the SSE response, which uses Chutes-specific envelope events (e2e_init,
// e2e, e2e_error, usage) instead of the per-field encryption used by other
// providers.
func doE2EEChutesStreamTest(req *http.Request, session *e2ee.ChutesSession) *attestation.E2EETestResult {
	client := tlsct.NewHTTPClient(60 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("HTTP request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &attestation.E2EETestResult{
			Attempted: true,
			Err:       fmt.Errorf("HTTP %d: %s", resp.StatusCode, body),
		}
	}

	// Collect non-standard response headers for leak reporting.
	var headerNotes []string
	for name := range resp.Header {
		switch strings.ToLower(name) {
		case "content-type", "cache-control", "date", "server",
			"transfer-encoding", "connection", "keep-alive",
			"x-request-id", "x-trace-id",
			"access-control-allow-origin", "access-control-allow-headers",
			"access-control-allow-methods", "access-control-max-age",
			"access-control-expose-headers",
			"vary", "strict-transport-security", "x-content-type-options":
			// Standard/infra headers — skip.
		default:
			headerNotes = append(headerNotes, fmt.Sprintf("%s: %s", name, strings.Join(resp.Header[name], ", ")))
		}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	var streamKey []byte
	decryptedChunks := 0
	usageEvents := 0

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}

		var event struct {
			E2EInit  *string `json:"e2e_init,omitempty"`
			E2E      *string `json:"e2e,omitempty"`
			E2EError *string `json:"e2e_error,omitempty"`
			Usage    any     `json:"usage,omitempty"`
		}
		if err := jsonstrict.UnmarshalWarn([]byte(data), &event, "chutes SSE event"); err != nil {
			return &attestation.E2EETestResult{
				Attempted: true,
				Err:       fmt.Errorf("parse SSE event: %w (prefix=%q)", err, safePrefix(data, 64)),
			}
		}

		switch {
		case event.E2EInit != nil:
			streamKey, err = session.DecryptStreamInitChutes(*event.E2EInit)
			if err != nil {
				return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("derive stream key: %w", err)}
			}
		case event.E2E != nil:
			if streamKey == nil {
				return &attestation.E2EETestResult{Attempted: true, Err: errors.New("e2e event before e2e_init")}
			}
			encrypted, err := base64.StdEncoding.DecodeString(*event.E2E)
			if err != nil {
				return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("decode e2e chunk: %w", err)}
			}
			plaintext, err := e2ee.DecryptStreamChunkChutes(encrypted, streamKey)
			if err != nil {
				return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("decrypt e2e chunk %d: %w", decryptedChunks+1, err)}
			}
			// The Chutes server encrypts full SSE lines including
			// "data: " prefix and trailing newlines. Strip these
			// before validating the JSON payload.
			chunk := bytes.TrimSpace(plaintext)
			chunk = bytes.TrimPrefix(chunk, []byte("data: "))
			// Empty chunks (inter-event newlines) and the [DONE]
			// sentinel are valid decrypted content, not JSON.
			if len(chunk) == 0 || string(chunk) == "[DONE]" {
				decryptedChunks++
				continue
			}
			if !json.Valid(chunk) {
				return &attestation.E2EETestResult{
					Attempted: true,
					Err:       fmt.Errorf("decrypted chunk %d is not valid JSON (prefix=%q)", decryptedChunks+1, safePrefix(string(plaintext), 64)),
				}
			}
			decryptedChunks++
		case event.E2EError != nil:
			return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("server e2e_error: %s", *event.E2EError)}
		case event.Usage != nil:
			usageEvents++
		}
	}
	if err := scanner.Err(); err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("read SSE stream: %w", err)}
	}

	if streamKey == nil {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("no e2e_init event received")}
	}
	if decryptedChunks == 0 {
		return &attestation.E2EETestResult{Attempted: true, Err: errors.New("no encrypted chunks received")}
	}

	detail := fmt.Sprintf("E2EE chutes ML-KEM-768: %d encrypted chunks decrypted", decryptedChunks)
	if usageEvents > 0 {
		detail += fmt.Sprintf("; %d cleartext usage events (expected)", usageEvents)
	}
	if len(headerNotes) > 0 {
		sort.Strings(headerNotes)
		detail += "; non-standard response headers: " + strings.Join(headerNotes, "; ")
	}
	return &attestation.E2EETestResult{Attempted: true, Detail: detail}
}

// doE2EEStreamTest sends an E2EE chat completions request and validates
// that the SSE response contains properly encrypted content fields.
func doE2EEStreamTest(req *http.Request, session e2ee.Decryptor, version string) *attestation.E2EETestResult {
	client := tlsct.NewHTTPClient(60 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("HTTP request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &attestation.E2EETestResult{
			Attempted: true,
			Err:       fmt.Errorf("HTTP %d: %s", resp.StatusCode, body),
		}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)
	encryptedCount := 0
	chunkCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		chunkCount++

		var chunk struct {
			ID                string `json:"id"`
			Object            string `json:"object"`
			Created           int64  `json:"created"`
			Model             string `json:"model"`
			SystemFingerprint string `json:"system_fingerprint"`
			Choices           []struct {
				Index        int `json:"index"`
				Delta        any `json:"delta"`
				FinishReason any `json:"finish_reason"`
			} `json:"choices"`
			Usage any `json:"usage"`
		}
		if err := jsonstrict.UnmarshalWarn([]byte(data), &chunk, "e2ee SSE chunk"); err != nil {
			return &attestation.E2EETestResult{
				Attempted: true,
				Err:       fmt.Errorf("parse SSE chunk %d: %w", chunkCount, err),
			}
		}
		if len(chunk.Choices) == 0 {
			continue
		}

		delta := chunk.Choices[0].Delta
		if delta == nil {
			continue
		}
		fields, ok := delta.(map[string]any)
		if !ok {
			return &attestation.E2EETestResult{
				Attempted: true,
				Err:       fmt.Errorf("delta in chunk %d is %T, expected map", chunkCount, delta),
			}
		}

		for key, val := range fields {
			s, ok := val.(string)
			if !ok || s == "" {
				continue
			}
			if e2ee.NonEncryptedFields[key] {
				continue
			}
			// This field should be encrypted.
			if !session.IsEncryptedChunk(s) {
				return &attestation.E2EETestResult{
					Attempted: true,
					Err:       fmt.Errorf("field %q not encrypted (len=%d, prefix=%q)", key, len(s), safePrefix(s, 16)),
				}
			}
			if _, err := session.Decrypt(s); err != nil {
				return &attestation.E2EETestResult{
					Attempted: true,
					Err:       fmt.Errorf("decrypt field %q: %w", key, err),
				}
			}
			encryptedCount++
		}
	}
	if err := scanner.Err(); err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("read SSE stream: %w", err)}
	}

	if encryptedCount == 0 {
		return &attestation.E2EETestResult{
			Attempted: true,
			Err:       fmt.Errorf("no encrypted content fields received in %d chunks", chunkCount),
		}
	}

	return &attestation.E2EETestResult{
		Attempted: true,
		Detail:    fmt.Sprintf("E2EE %s: %d encrypted fields decrypted across %d chunks", version, encryptedCount, chunkCount),
	}
}

// safePrefix returns the first n characters of s, or s if shorter.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// knownProviders returns the comma-separated list of provider names from cfg
// in deterministic (sorted) order.
func knownProviders(cfg *config.Config) string {
	names := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// formatReport renders a VerificationReport as a human-readable string,
// matching the output format documented in the plan.
func formatReport(r *attestation.VerificationReport) string {
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

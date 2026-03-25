// Command teep is the CLI entrypoint for the TEE proxy and attestation verifier.
//
// Usage:
//
//	teep serve   PROVIDER                Start the proxy server.
//	teep verify  PROVIDER --model M      Fetch and verify attestation, print report.
//
// Configuration is loaded from $TEEP_CONFIG (TOML) and environment variables.
// See the config package for full documentation.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/proxy"
)

func main() {
	if len(os.Args) < 2 {
		printOverview()
		os.Exit(1)
	}

	// Parse --log-level before the subcommand. It can appear anywhere in os.Args.
	level := parseLogLevel(os.Args[1:])
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
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
func parseLogLevel(args []string) slog.Level {
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
			return slog.LevelDebug
		case "info":
			return slog.LevelInfo
		case "warn":
			return slog.LevelWarn
		case "error":
			return slog.LevelError
		default:
			fmt.Fprintf(os.Stderr, "teep: unknown log level %q (valid: debug, info, warn, error)\n", val)
			os.Exit(1)
		}
	}
	return slog.LevelInfo
}

// runServe loads config, creates the proxy, and starts listening.
func runServe(args []string) {
	providerName, args := extractProvider(args)
	if providerName == "" {
		fmt.Fprintf(os.Stderr, "teep serve: provider is required\n\n")
		printServeHelp()
		os.Exit(1)
	}

	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	offline := fs.Bool("offline", false, "skip external verification (Intel PCS, Proof of Cloud, Certificate Transparency)")
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")
	fs.Usage = func() { printServeHelp() }
	fs.Parse(args) //nolint:errcheck // fs.Parse calls os.Exit on error per flag.ExitOnError

	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}
	cfg.Offline = *offline

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
}

// providerNotFoundError returns a descriptive error when a provider is not configured.
func providerNotFoundError(name string, cfg *config.Config) error {
	if envVar, ok := providerEnvVars[name]; ok && len(cfg.Providers) == 0 {
		return fmt.Errorf("provider '%s' not configured (set %s or add [providers.%s] to config)", name, envVar, name)
	}
	if envVar, ok := providerEnvVars[name]; ok {
		return fmt.Errorf("provider '%s' not configured (set %s or add [providers.%s] to config; known: %s)", name, envVar, name, knownProviders(cfg))
	}
	return fmt.Errorf("provider '%s' not found (known: %s)", name, knownProviders(cfg))
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
// the 20-factor report, prints it to stdout, and exits with code 1 if any
// enforced factor failed.
func runVerify(args []string) {
	providerName, args := extractProvider(args)
	if providerName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: provider is required\n\n")
		printVerifyHelp()
		os.Exit(1)
	}

	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() { printVerifyHelp() }

	modelName := fs.String("model", "", "model name as known to the provider (required)")
	saveDir := fs.String("save-dir", "", "directory to save raw attestation data (EAT, TDX quote)")
	offline := fs.Bool("offline", false, "skip external verification (Intel PCS, Proof of Cloud, Certificate Transparency)")
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")

	fs.Parse(args) //nolint:errcheck // fs.Parse calls os.Exit on error per flag.ExitOnError

	if *modelName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: --model is required\n")
		fs.Usage()
		os.Exit(1)
	}

	report := runVerification(providerName, *modelName, *saveDir, *offline)
	fmt.Print(formatReport(report))

	if report.Blocked() {
		os.Exit(1)
	}
}

// runVerification loads config, builds the appropriate attester, fetches
// attestation, runs TDX and NVIDIA verification, and returns the report.
// If saveDir is non-empty, raw attestation data is saved to files there.
func runVerification(providerName, modelName, saveDir string, offline bool) *attestation.VerificationReport {
	cfg, cp := loadConfig(providerName)
	attester := newAttester(providerName, cp, offline)
	client := config.NewAttestationClient(offline)

	nonce := attestation.NewNonce()
	slog.Debug("nonce generated", "provider", providerName, "model", modelName, "nonce", nonce.Hex()[:16]+"...")
	ctx := context.Background()

	raw := fetchAttestation(ctx, attester, providerName, modelName, nonce)
	if saveDir != "" {
		saveAttestationData(saveDir, providerName, raw)
	}

	tdxResult := verifyTDX(ctx, raw, nonce, providerName, offline)
	nvidiaResult, nrasResult := verifyNVIDIA(ctx, raw, nonce, client, offline)
	pocResult := checkPoC(ctx, raw.IntelQuote, client, offline)

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
	gatewayTDX, gatewayCompose, gatewayPoCResult := verifyNearcloudGateway(ctx, raw, nonce, client, offline)
	var gatewayCD attestation.ComposeDigests
	if gatewayCompose != nil && gatewayCompose.Err == nil {
		gatewayCD = attestation.ExtractComposeDigests(raw.GatewayAppCompose)
	}

	allDigests, digestToRepo := attestation.MergeComposeDigests(modelCD, gatewayCD)
	sigstoreResults, rekorResults := checkSigstore(ctx, allDigests, client, offline)

	return attestation.BuildReport(&attestation.ReportInput{
		Provider:          providerName,
		Model:             modelName,
		Raw:               raw,
		Nonce:             nonce,
		Enforced:          cfg.Enforced,
		Policy:            cfg.MeasurementPolicy,
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
	})
}

// loadConfig loads the TOML config and looks up the named provider.
func loadConfig(providerName string) (*config.Config, *config.Provider) {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}
	cp, ok := cfg.Providers[providerName]
	if !ok {
		slog.Error(providerNotFoundError(providerName, cfg).Error())
		os.Exit(1)
	}
	return cfg, cp
}

// fetchAttestation fetches raw attestation data from the provider with timing log.
func fetchAttestation(ctx context.Context, attester provider.Attester, providerName, modelName string, nonce attestation.Nonce) *attestation.RawAttestation {
	slog.Debug("attestation fetch starting", "provider", providerName, "model", modelName)
	fetchStart := time.Now()
	raw, err := attester.FetchAttestation(ctx, modelName, nonce)
	if err != nil {
		slog.Error("fetch attestation failed", "provider", providerName, "model", modelName, "err", err)
		os.Exit(1)
	}
	slog.Debug("attestation fetch complete", "provider", providerName, "elapsed", time.Since(fetchStart))
	return raw
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
		slog.Debug("NVIDIA verification starting", "payload_len", len(raw.NvidiaPayload))
		nvidiaStart := time.Now()
		eat = attestation.VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		slog.Debug("NVIDIA verification complete", "elapsed", time.Since(nvidiaStart))
	}
	if !offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.Debug("NVIDIA NRAS verification starting")
		nrasStart := time.Now()
		nras = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client)
		slog.Debug("NVIDIA NRAS verification complete", "elapsed", time.Since(nrasStart))
	}
	return eat, nras
}

// checkPoC runs a Proof of Cloud check for the given intel_quote.
// Returns nil if offline or quote is empty.
func checkPoC(ctx context.Context, quote string, client *http.Client, offline bool) *attestation.PoCResult {
	if offline || quote == "" {
		return nil
	}
	slog.Debug("Proof of Cloud check starting")
	pocStart := time.Now()
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, client)
	result := poc.CheckQuote(ctx, quote)
	slog.Debug("Proof of Cloud check complete", "elapsed", time.Since(pocStart),
		"registered", result != nil && result.Registered)
	return result
}

// verifyNearcloudGateway verifies gateway TDX, compose binding, and PoC for
// providers that populate GatewayIntelQuote (nearcloud).
func verifyNearcloudGateway(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
	client *http.Client, offline bool,
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
	poc = checkPoC(ctx, raw.GatewayIntelQuote, client, offline)
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
func newAttester(name string, cp *config.Provider, offline ...bool) provider.Attester {
	off := false
	if len(offline) > 0 {
		off = offline[0]
	}
	switch name {
	case "venice":
		return venice.NewAttester(cp.BaseURL, cp.APIKey, off)
	case "neardirect":
		return neardirect.NewAttester(cp.BaseURL, cp.APIKey, off)
	case "nearcloud":
		return nearcloud.NewAttester(cp.APIKey, off)
	default:
		slog.Error("unknown provider", "provider", name, "supported", "venice, neardirect, nearcloud")
		os.Exit(1)
		return nil // unreachable
	}
}

func newReportDataVerifier(name string) provider.ReportDataVerifier {
	switch name {
	case "venice":
		return venice.ReportDataVerifier{}
	case "neardirect", "nearcloud":
		return neardirect.ReportDataVerifier{}
	default:
		return nil
	}
}

// knownProviders returns the comma-separated list of provider names from cfg.
func knownProviders(cfg *config.Config) string {
	names := make([]string, 0, len(cfg.Providers))
	for name := range cfg.Providers {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// formatReport renders a VerificationReport as a human-readable string,
// matching the output format documented in the plan.
func formatReport(r *attestation.VerificationReport) string {
	var b strings.Builder

	header := fmt.Sprintf("Attestation Report: %s / %s", r.Provider, r.Model)
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
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Score: %d/%d passed, %d skipped, %d failed\n",
		r.Passed, r.Passed+r.Failed+r.Skipped, r.Skipped, r.Failed)
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
		if (entry.key == "compose_hash" || entry.key == "os_image" || entry.key == "device" || entry.key == "ppid") && len(val) > 16 {
			val = val[:16] + "..."
		}
		fmt.Fprintf(b, "  %-14s %s\n", entry.label+":", val)
	}
}

// saveAttestationData writes the raw provider response and extracted fields to dir.
// Filenames include a timestamp so multiple runs do not overwrite each other.
func saveAttestationData(dir, provName string, raw *attestation.RawAttestation) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Error("create save dir failed", "dir", dir, "err", err)
		return
	}

	ts := time.Now().UTC().Format("20060102T150405Z")

	// Save the unmodified HTTP response body from the provider.
	if len(raw.RawBody) > 0 {
		saveFile(filepath.Join(dir, fmt.Sprintf("%s_attestation_%s.json", provName, ts)), raw.RawBody)
	}

	if raw.NvidiaPayload != "" {
		saveFile(filepath.Join(dir, fmt.Sprintf("%s_nvidia_payload_%s.json", provName, ts)), []byte(raw.NvidiaPayload))
	}

	if raw.IntelQuote != "" {
		saveFile(filepath.Join(dir, fmt.Sprintf("%s_intel_quote_%s.hex", provName, ts)), []byte(raw.IntelQuote))
	}
}

// saveFile writes data to path with 0600 permissions, logging the result.
func saveFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		slog.Error("save failed", "path", path, "err", err)
		return
	}
	slog.Debug("saved", "path", path, "bytes", len(data))
}

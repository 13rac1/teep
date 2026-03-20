// Command teep is the CLI entrypoint for the TEE proxy and attestation verifier.
//
// Usage:
//
//	teep serve                              Start the proxy server.
//	teep verify --provider NAME --model M  Fetch and verify attestation, print report.
//
// Configuration is loaded from $TEEP_CONFIG (TOML) and environment variables.
// See the config package for full documentation.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearai"
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
		} else if strings.HasPrefix(arg, "--log-level=") {
			val = strings.TrimPrefix(arg, "--log-level=")
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
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	offline := fs.Bool("offline", false, "skip external verification (Intel PCS, Proof of Cloud)")
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")
	fs.Usage = func() { printServeHelp() }
	fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}
	cfg.Offline = *offline

	srv, err := proxy.New(cfg)
	if err != nil {
		slog.Error("proxy init failed", "err", err)
		os.Exit(1)
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}

// runVerify parses flags, fetches attestation from the named provider, builds
// the 20-factor report, prints it to stdout, and exits with code 1 if any
// enforced factor failed.
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() { printVerifyHelp() }

	providerName := fs.String("provider", "", "provider name (required, e.g. venice, nearai)")
	modelName := fs.String("model", "", "model name as known to the provider (required)")
	saveDir := fs.String("save-dir", "", "directory to save raw attestation data (EAT, TDX quote)")
	offline := fs.Bool("offline", false, "skip external verification (Proof of Cloud registry)")
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")

	fs.Parse(args)

	if *providerName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: --provider is required\n")
		fs.Usage()
		os.Exit(1)
	}
	if *modelName == "" {
		fmt.Fprintf(os.Stderr, "teep verify: --model is required\n")
		fs.Usage()
		os.Exit(1)
	}

	report := runVerification(*providerName, *modelName, *saveDir, *offline)
	fmt.Print(formatReport(report))

	if report.Blocked() {
		os.Exit(1)
	}
}

// runVerification loads config, builds the appropriate attester, fetches
// attestation, runs TDX and NVIDIA verification, and returns the report.
// If saveDir is non-empty, raw attestation data is saved to files there.
func runVerification(providerName, modelName, saveDir string, offline bool) *attestation.VerificationReport {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}

	cp, ok := cfg.Providers[providerName]
	if !ok {
		slog.Error("provider not found", "provider", providerName, "known", knownProviders(cfg))
		os.Exit(1)
	}

	attester := newAttester(providerName, cp)
	client := config.NewAttestationClient()

	nonce := attestation.NewNonce()
	slog.Debug("nonce generated", "provider", providerName, "model", modelName, "nonce", nonce.Hex()[:16]+"...")
	ctx := context.Background()

	slog.Debug("attestation fetch starting", "provider", providerName, "model", modelName)
	fetchStart := time.Now()
	raw, err := attester.FetchAttestation(ctx, modelName, nonce)
	if err != nil {
		slog.Error("fetch attestation failed", "provider", providerName, "model", modelName, "err", err)
		os.Exit(1)
	}
	slog.Debug("attestation fetch complete", "provider", providerName, "elapsed", time.Since(fetchStart))

	if saveDir != "" {
		saveAttestationData(saveDir, providerName, raw)
	}

	var tdxResult *attestation.TDXVerifyResult
	if raw.IntelQuote != "" {
		slog.Debug("TDX verification starting", "quote_len", len(raw.IntelQuote))
		tdxStart := time.Now()
		tdxResult = attestation.VerifyTDXQuote(ctx, raw.IntelQuote, raw.SigningKey, nonce, offline)
		slog.Debug("TDX verification complete", "elapsed", time.Since(tdxStart))
	}

	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		slog.Debug("NVIDIA verification starting", "payload_len", len(raw.NvidiaPayload))
		nvidiaStart := time.Now()
		nvidiaResult = attestation.VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		slog.Debug("NVIDIA verification complete", "elapsed", time.Since(nvidiaStart))
	}

	var nrasResult *attestation.NvidiaVerifyResult
	if !offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.Debug("NVIDIA NRAS verification starting")
		nrasStart := time.Now()
		nrasResult = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client)
		slog.Debug("NVIDIA NRAS verification complete", "elapsed", time.Since(nrasStart))
	}

	var pocResult *attestation.PoCResult
	if !offline && raw.IntelQuote != "" {
		slog.Debug("Proof of Cloud check starting")
		pocStart := time.Now()
		poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, client)
		pocResult = poc.CheckQuote(ctx, raw.IntelQuote)
		slog.Debug("Proof of Cloud check complete", "elapsed", time.Since(pocStart),
			"registered", pocResult != nil && pocResult.Registered)
	}

	return attestation.BuildReport(providerName, modelName, raw, nonce, cfg.Enforced, tdxResult, nvidiaResult, nrasResult, pocResult)
}

// newAttester returns the appropriate Attester for the named provider.
func newAttester(name string, cp *config.Provider) provider.Attester {
	switch name {
	case "venice":
		return venice.NewAttester(cp.BaseURL, cp.APIKey)
	case "nearai":
		return nearai.NewAttester(cp.BaseURL, cp.APIKey)
	default:
		slog.Error("unknown provider", "provider", name, "supported", "venice, nearai")
		os.Exit(1)
		return nil // unreachable
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

// tierBoundaries defines the exclusive upper index (0-based) for each tier.
// Factors 0-6 = Tier 1, 7-14 = Tier 2, 15-19 = Tier 3.
var tierBoundaries = [3]struct {
	name string
	end  int
}{
	{"Tier 1: Core Attestation", 7},
	{"Tier 2: Binding & Crypto", 16},
	{"Tier 3: Supply Chain & Channel Integrity", 21},
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

	start := 0
	for _, tb := range tierBoundaries {
		end := tb.end
		if end > len(r.Factors) {
			end = len(r.Factors)
		}
		if start >= len(r.Factors) {
			break
		}

		b.WriteString(tb.name)
		b.WriteString("\n")

		for _, f := range r.Factors[start:end] {
			icon := statusIcon(f.Status)
			line := fmt.Sprintf("  %s %-26s %s", icon, f.Name, f.Detail)
			if f.Enforced {
				line += "  [ENFORCED]"
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")

		start = end
	}

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
func saveAttestationData(dir, provider string, raw *attestation.RawAttestation) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Error("create save dir failed", "dir", dir, "err", err)
		return
	}

	ts := time.Now().UTC().Format("20060102T150405Z")

	// Save the unmodified HTTP response body from the provider.
	if len(raw.RawBody) > 0 {
		saveFile(filepath.Join(dir, fmt.Sprintf("%s_attestation_%s.json", provider, ts)), raw.RawBody)
	}

	if raw.NvidiaPayload != "" {
		saveFile(filepath.Join(dir, fmt.Sprintf("%s_nvidia_payload_%s.json", provider, ts)), []byte(raw.NvidiaPayload))
	}

	if raw.IntelQuote != "" {
		saveFile(filepath.Join(dir, fmt.Sprintf("%s_intel_quote_%s.hex", provider, ts)), []byte(raw.IntelQuote))
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

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
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/nearai"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/proxy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
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
		usage()
	default:
		fmt.Fprintf(os.Stderr, "teep: unknown subcommand %q\n\n", os.Args[1])
		usage()
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

// usage prints a brief help message to stderr.
func usage() {
	fmt.Fprintf(os.Stderr, `teep — TEE proxy and attestation verifier

Usage:
  teep serve [--log-level LEVEL]                              Start the HTTP proxy server.
  teep verify --provider NAME --model M [--log-level LEVEL]  Fetch and print attestation report.

Flags:
  --log-level LEVEL  Set log verbosity: debug, info, warn, error (default: info).

Environment variables:
  TEEP_CONFIG       Path to TOML config file.
  TEEP_LISTEN_ADDR  Override listen address (default 127.0.0.1:8080).
  VENICE_API_KEY    Venice AI API key.
  NEARAI_API_KEY    NEAR AI API key.
`)
}

// runServe loads config, creates the proxy, and starts listening.
func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.String("log-level", "info", "log verbosity: debug, info, warn, error")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: teep serve\n\nStart the proxy HTTP server.\n")
	}
	fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "err", err)
		os.Exit(1)
	}

	srv := proxy.New(cfg)
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
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: teep verify --provider NAME --model MODEL\n\nFetch and print an attestation verification report.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	providerName := fs.String("provider", "", "provider name (required, e.g. venice, nearai)")
	modelName := fs.String("model", "", "model name as known to the provider (required)")
	saveDir := fs.String("save-dir", "", "directory to save raw attestation data (EAT, TDX quote)")
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

	report := runVerification(*providerName, *modelName, *saveDir)
	fmt.Print(formatReport(report))

	if report.Blocked() {
		os.Exit(1)
	}
}

// runVerification loads config, builds the appropriate attester, fetches
// attestation, runs TDX and NVIDIA verification, and returns the report.
// If saveDir is non-empty, raw attestation data is saved to files there.
func runVerification(providerName, modelName, saveDir string) *attestation.VerificationReport {
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
	ctx := context.Background()

	raw, err := attester.FetchAttestation(ctx, modelName, nonce)
	if err != nil {
		slog.Error("fetch attestation failed", "provider", providerName, "model", modelName, "err", err)
		os.Exit(1)
	}

	if saveDir != "" {
		saveAttestationData(saveDir, providerName, raw)
	}

	var tdxResult *attestation.TDXVerifyResult
	if raw.IntelQuote != "" {
		tdxResult = attestation.VerifyTDXQuote(raw.IntelQuote, raw.SigningKey, nonce)
	}

	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce, client)
	}

	return attestation.BuildReport(providerName, modelName, raw, nonce, cfg.Enforced, tdxResult, nvidiaResult)
}

// attesterInterface is a local alias so we can call FetchAttestation without
// importing the provider package (which would be a circular path for nearai/venice).
type attesterInterface interface {
	FetchAttestation(ctx context.Context, model string, nonce attestation.Nonce) (*attestation.RawAttestation, error)
}

// newAttester returns the appropriate Attester for the named provider.
func newAttester(name string, cp *config.Provider) attesterInterface {
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

// tier groups the 20 factors into human-readable sections.
type tier struct {
	name    string
	factors []attestation.FactorResult
}

// tierBoundaries defines the exclusive upper index (0-based) for each tier.
// Factors 0-6 = Tier 1, 7-14 = Tier 2, 15-19 = Tier 3.
var tierBoundaries = [3]struct {
	name string
	end  int
}{
	{"Tier 1: Core Attestation", 7},
	{"Tier 2: Binding & Crypto", 15},
	{"Tier 3: Supply Chain & Channel Integrity", 20},
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
			line := fmt.Sprintf("  %s %-30s %s", icon, f.Name, f.Detail)
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

// saveAttestationData writes raw attestation fields to files in dir.
func saveAttestationData(dir, provider string, raw *attestation.RawAttestation) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Error("create save dir failed", "dir", dir, "err", err)
		return
	}

	if raw.NvidiaPayload != "" {
		path := filepath.Join(dir, provider+"_nvidia_payload.json")
		// Pretty-print if it's JSON; write raw otherwise.
		data := []byte(raw.NvidiaPayload)
		var obj any
		if json.Unmarshal(data, &obj) == nil {
			if pretty, err := json.MarshalIndent(obj, "", "  "); err == nil {
				data = pretty
			}
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			slog.Error("save NVIDIA payload failed", "path", path, "err", err)
		} else {
			slog.Info("saved NVIDIA payload", "path", path, "bytes", len(data))
		}
	}

	if raw.IntelQuote != "" {
		path := filepath.Join(dir, provider+"_intel_quote.b64")
		if err := os.WriteFile(path, []byte(raw.IntelQuote), 0o600); err != nil {
			slog.Error("save Intel quote failed", "path", path, "err", err)
		} else {
			slog.Info("saved Intel TDX quote", "path", path)
		}
	}
}

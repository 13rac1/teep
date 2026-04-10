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
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/proxy"
	"github.com/13rac1/teep/internal/reqid"
	"github.com/13rac1/teep/internal/verify"
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

// providerNotFoundError returns a descriptive error when a provider is not configured.
func providerNotFoundError(name string, cfg *config.Config) error {
	envVar, known := verify.ProviderEnvVars[name]
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
	if report != nil {
		fmt.Print(verify.FormatReport(report))
	}
	if err != nil {
		slog.Error("verification failed", "err", err)
		os.Exit(1)
	}

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
		if err := verify.CompareReports(capturedText, reverifyText); err != nil {
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
func replayVerification(captureDir string) (*attestation.VerificationReport, string, error) {
	return verify.Replay(context.Background(), captureDir, loadConfig)
}

// runVerification loads config, builds the appropriate attester, fetches
// attestation, runs TDX and NVIDIA verification, and returns the report.
func runVerification(providerName, modelName, captureDir string, offline bool,
	overrideClient *http.Client, overrideNonce attestation.Nonce, capturedE2EE *attestation.E2EETestResult,
) (*attestation.VerificationReport, error) {
	cfg, cp, err := loadConfig(providerName)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return verify.Run(context.Background(), &verify.Options{
		Config:       cfg,
		Provider:     cp,
		ProviderName: providerName,
		ModelName:    modelName,
		CaptureDir:   captureDir,
		Offline:      offline,
		Client:       overrideClient,
		Nonce:        overrideNonce,
		CapturedE2EE: capturedE2EE,
	})
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

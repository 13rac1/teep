// Command teep is the CLI entrypoint for the TEE proxy and attestation verifier.
//
// Usage:
//
//	teep serve      [flags] PROVIDER             Start the proxy server.
//	teep verify     --model M [flags] PROVIDER   Fetch and verify attestation, print report.
//	teep self-check                              Verify this binary's build provenance.
//	teep version                                 Print version information.
//
// Configuration is loaded from $TEEP_CONFIG (TOML) and environment variables.
// See the config package for full documentation.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v4"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/proxy"
	"github.com/13rac1/teep/internal/reqid"
	"github.com/13rac1/teep/internal/verify"
)

// errSilentExit indicates the command has already printed its output and wants
// a non-zero exit without additional error logging.
var errSilentExit = errors.New("silent exit")

func main() {
	// Root flags — inherited by all subcommands via SetParent.
	rootFlags := ff.NewFlagSet("teep")
	logLevel := rootFlags.StringEnumLong("log-level",
		"log verbosity: debug, info, warn, error",
		"info", "debug", "warn", "error")

	// Serve flags.
	serveFlags := ff.NewFlagSet("serve").SetParent(rootFlags)
	serveOffline := serveFlags.BoolLong("offline",
		"skip external verification (Intel PCS, Proof of Cloud, Certificate Transparency)")
	serveForce := registerForceFlag(serveFlags)

	// Verify flags.
	verifyFlags := ff.NewFlagSet("verify").SetParent(rootFlags)
	model := verifyFlags.StringLong("model", "",
		"model name as known to the provider (required)")
	captureDir := verifyFlags.StringLong("capture", "",
		"save all HTTP traffic to DIR for archival")
	reverifyDir := verifyFlags.StringLong("reverify", "",
		"re-verify from a captured attestation directory")
	verifyOffline := verifyFlags.BoolLong("offline",
		"skip external verification (Intel PCS, Proof of Cloud, Certificate Transparency)")
	updateConfig := verifyFlags.BoolLong("update-config",
		"write observed measurements to the config file ($TEEP_CONFIG)")
	configOut := verifyFlags.StringLong("config-out", "",
		"write updated config to this path instead of $TEEP_CONFIG")

	root := &ff.Command{
		Name:  "teep",
		Usage: "teep [--log-level LEVEL] <subcommand> ...",
		Flags: rootFlags,
		Exec: func(_ context.Context, args []string) error {
			if len(args) > 0 {
				fmt.Fprintf(os.Stderr, "teep: unknown subcommand %q\n\n", args[0])
			}
			printOverview()
			return errSilentExit
		},
		Subcommands: []*ff.Command{
			{
				Name:      "serve",
				Usage:     "teep serve [--offline] [--force] PROVIDER",
				ShortHelp: "Start the proxy server",
				Flags:     serveFlags,
				Exec: func(ctx context.Context, args []string) error {
					if len(args) == 0 {
						fmt.Fprintf(os.Stderr, "teep serve: provider is required\n\n")
						printServeHelp()
						return errSilentExit
					}
					if err := rejectTrailingFlags("serve", args); err != nil {
						return err
					}
					return runServe(ctx, args[0], *serveOffline, forceValue(serveForce))
				},
			},
			{
				Name:      "verify",
				Usage:     "teep verify (--model M [flags] PROVIDER | --reverify DIR [flags])",
				ShortHelp: "Fetch and verify attestation, print report",
				Flags:     verifyFlags,
				Exec: func(ctx context.Context, args []string) error {
					if err := verifyArgsConflict(*reverifyDir, args); err != nil {
						return err
					}
					if *reverifyDir != "" {
						return runReverify(ctx, *reverifyDir)
					}
					if len(args) == 0 {
						fmt.Fprintf(os.Stderr, "teep verify: provider is required\n\n")
						printVerifyHelp()
						return errSilentExit
					}
					if err := rejectTrailingFlags("verify", args); err != nil {
						return err
					}
					if *model == "" {
						fmt.Fprintf(os.Stderr, "teep verify: --model is required\n\n")
						printVerifyHelp()
						return errSilentExit
					}
					return runVerify(ctx, args[0], *model, *captureDir,
						*verifyOffline, *updateConfig, *configOut)
				},
			},
			{
				Name:      "self-check",
				Usage:     "teep self-check",
				ShortHelp: "Verify this binary's build provenance",
				Exec: func(_ context.Context, args []string) error {
					if len(args) != 0 {
						fmt.Fprintf(os.Stderr, "teep self-check: unexpected arguments: %v\n", args)
						return errSilentExit
					}
					return runSelfCheck()
				},
			},
			{
				Name:      "version",
				Usage:     "teep version",
				ShortHelp: "Print version information",
				Exec: func(_ context.Context, args []string) error {
					if len(args) != 0 {
						fmt.Fprintf(os.Stderr, "teep version: unexpected arguments: %v\n", args)
						return errSilentExit
					}
					return runVersion()
				},
			},
			{
				Name:      "help",
				Usage:     "teep help [TOPIC]",
				ShortHelp: "Show help for a command or topic",
				Exec: func(_ context.Context, args []string) error {
					runHelp(args)
					return nil
				},
			},
		},
	}

	// Parse arguments — handles flag parsing and subcommand selection.
	if err := root.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, ff.ErrHelp) {
			if sel := root.GetSelected(); sel != nil && sel.Name != "teep" {
				runHelp([]string{sel.Name})
			} else {
				runHelp(nil)
			}
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Set slog level between parse and execute — *logLevel is populated after Parse.
	slog.SetDefault(slog.New(reqid.NewHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: parseSlogLevel(*logLevel),
		}))))

	// Execute the selected subcommand.
	ctx := context.Background()
	if err := root.Run(ctx); err != nil {
		if !errors.Is(err, errSilentExit) {
			slog.Error(err.Error())
		}
		os.Exit(1)
	}
}

// parseSlogLevel converts a string log level to slog.Level, defaulting to Info.
func parseSlogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// verifyArgsConflict returns an error if reverifyDir and positional provider
// args are both present (they are mutually exclusive).
func verifyArgsConflict(reverifyDir string, args []string) error {
	if reverifyDir != "" && len(args) > 0 {
		return errors.New("PROVIDER and --reverify are mutually exclusive")
	}
	return nil
}

// rejectTrailingFlags checks for flag-like arguments after the first positional
// arg and returns a helpful error. ff stops parsing at the first non-flag
// argument (POSIX convention), so flags placed after the provider are not
// parsed. This catches the common mistake of writing "serve venice --offline"
// instead of "serve --offline venice".
func rejectTrailingFlags(cmd string, args []string) error {
	var trailingFlags, extraPositionals []string
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			trailingFlags = append(trailingFlags, a)
		} else {
			extraPositionals = append(extraPositionals, a)
		}
	}
	// Only suggest a reordering when the sole problem is trailing flags —
	// if there are also extra positionals the reordering would be wrong.
	if len(trailingFlags) > 0 && len(extraPositionals) == 0 {
		return fmt.Errorf("%s: flags must precede the provider argument (try: teep %s %s %s)",
			cmd, cmd, strings.Join(trailingFlags, " "), args[0])
	}
	if len(args) > 1 {
		return fmt.Errorf("%s: expected one provider argument, got %d", cmd, len(args))
	}
	return nil
}

// runServe loads config, creates the proxy, and starts listening.
func runServe(ctx context.Context, provider string, offline, force bool) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.Offline = offline

	if force {
		cfg.Force = true
		slog.Warn("--force enabled: requests will be forwarded even when enforced attestation factors fail")
	}

	if err := filterProviders(cfg, provider); err != nil {
		return err
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		return fmt.Errorf("proxy init: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	err = srv.ListenAndServe(ctx)
	stop()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: %w", err)
	}
	slog.Info("server stopped")
	return nil
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

// runVerify fetches attestation from the named provider, builds the
// verification report, prints it to stdout, and returns an error if any
// enforced factor failed.
func runVerify(ctx context.Context, provider, model, captureDir string, offline, updateConfig bool, configOut string) error {
	if model == "" {
		return errors.New("--model is required")
	}
	if captureDir != "" && offline {
		return errors.New("--capture and --offline are mutually exclusive")
	}

	report, err := runVerification(ctx, &verify.Options{
		ProviderName: provider,
		ModelName:    model,
		CaptureDir:   captureDir,
		Offline:      offline,
	})
	if report != nil {
		fmt.Print(verify.FormatReport(report))
	}
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	blocked := report.Blocked()

	if updateConfig || configOut != "" {
		if blocked {
			return errors.New("refusing --update-config: attestation blocked (measurements may be untrustworthy)")
		}
		outPath := configOut
		if outPath == "" {
			outPath = os.Getenv("TEEP_CONFIG")
		}
		if outPath == "" {
			return errors.New("--update-config requires $TEEP_CONFIG or --config-out")
		}
		observed := extractObserved(report)
		if err := config.UpdateConfig(outPath, provider, &observed); err != nil {
			return fmt.Errorf("update config: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Config updated: %s (provider %s)\n", outPath, provider)
	}

	if blocked {
		return errSilentExit
	}
	return nil
}

// runReverify re-verifies attestation from a previously captured directory.
// All HTTP traffic is served from the saved responses via a replay transport.
func runReverify(ctx context.Context, captureDir string) error {
	report, reverifyText, err := verify.Replay(ctx, captureDir, loadConfig)
	if err != nil {
		return fmt.Errorf("replay verification failed: %w", err)
	}

	capturedText, loadErr := capture.LoadReport(captureDir)
	switch {
	case loadErr == nil:
		if err := verify.CompareReports(capturedText, reverifyText); err != nil {
			return fmt.Errorf("report comparison failed: %w", err)
		}
	case errors.Is(loadErr, os.ErrNotExist):
		slog.Warn("no captured report to compare (report.txt absent)")
	default:
		return fmt.Errorf("read captured report: %w", loadErr)
	}

	fmt.Print(reverifyText)
	if report.Blocked() {
		return errSilentExit
	}
	return nil
}

// runVerification loads config then delegates to verify.Run.
// Callers set override fields (Client, Nonce, CapturedE2EE) directly on opts
// when needed for testing or replay; leave them zero for normal operation.
func runVerification(ctx context.Context, opts *verify.Options) (*attestation.VerificationReport, error) {
	cfg, cp, err := loadConfig(opts.ProviderName)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	opts.Config = cfg
	opts.Provider = cp
	return verify.Run(ctx, opts)
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

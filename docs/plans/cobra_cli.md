# Plan: Migrate CLI to Cobra

## 1. Goal

Replace the homegrown `flag.FlagSet` CLI in `cmd/teep/` with
[`github.com/spf13/cobra`](https://github.com/spf13/cobra) in a single PR.
The current implementation has accumulated several hand-rolled workarounds that
Cobra handles natively. All `internal/` packages are unchanged.

---

## 2. Current Pain Points

| Problem | Current workaround | Cobra solution |
|---------|-------------------|----------------|
| `--log-level` must be available to all subcommands | `parseLogLevel()` pre-scans `os.Args` before dispatch (lines 87–111) | `rootCmd.PersistentFlags()` |
| Provider is a positional arg before flags | `extractProvider()` peels it off before `flag.Parse` (lines 197–204) | `cobra.ExactArgs(1)` + `cmd.Args[0]` |
| Unknown subcommand produces a hand-written error | `default:` case in `switch os.Args[1]` (lines 67–82) | Cobra's built-in unknown-command error |
| `--reverify` and positional provider are mutually exclusive but not enforced | Not validated | `cobra.RangeArgs(0, 1)` + check in `RunE` |
| Build-tag `--force` requires `registerForceFlag()` indirection | `force_debug.go` / `force_release.go` passing `*flag.FlagSet` | `init()` in `force_debug.go` calls `serveCmd.Flags().Bool(...)` directly |
| Every `run*` function duplicates `flag.FlagSet` setup + `fs.Parse` | Boilerplate in each subcommand (e.g. lines 122–129, 212–225) | Flags declared once; `RunE` receives pre-parsed `*cobra.Command` |

Total hand-rolled plumbing eliminated: ~150 lines.

---

## 3. What Stays the Same

- **`internal/` packages** — zero changes.
- **`help.go` domain content** — `factorRegistry`, `tierRegistry`, all
  `print*Help()` functions. These are domain documentation, not CLI framework.
- **`selfcheck.go`** — unchanged.
- **teeplint** — `checkCLIMain` parses `cmd/teep/main.go` and asserts
  `providerEnvVars`, `newAttester`, `newReportDataVerifier`, and
  `supplyChainPolicy` cover every provider. These stay in `main.go` as helpers
  for `RunE`, so teeplint needs no changes.

---

## 4. Target Command Structure

```
teep [--log-level LEVEL]
  serve   PROVIDER [--offline] [--force]
  verify  [PROVIDER] --model M [--capture DIR] [--reverify DIR] [--offline]
                     [--update-config] [--config-out FILE]
  self-check
  version
  help    [TOPIC]
```

`--log-level` is a persistent flag on the root command inherited by all
subcommands. `PROVIDER` is required on `serve` and on `verify` in live mode.
When `--reverify DIR` is passed, `PROVIDER` is optional — the captured
manifest's provider is used instead (`cobra.RangeArgs(0, 1)` + `RunE` check).

---

## 5. What the PR Does

**Add `go get github.com/spf13/cobra`.**

**Create `cmd/teep/cmd.go`** with the root command and all subcommands wired
to the existing `run*` internals:

```go
var rootCmd = &cobra.Command{
    Use:   "teep",
    Short: "TEE proxy and attestation verifier",
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        // set slog level from --log-level flag
    },
}

func init() {
    rootCmd.PersistentFlags().String("log-level", "info",
        "log verbosity: debug, info, warn, error")
    rootCmd.AddCommand(serveCmd, verifyCmd, selfCheckCmd, versionCmd, helpCmd)
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

**Subcommand flags** declared in `init()` on each command — no more per-function
`flag.NewFlagSet`. `RunE` functions call the existing business logic directly.

**`force_debug.go`** — replace `registerForceFlag(fs *flag.FlagSet)` with:

```go
//go:build debug

func init() {
    serveCmd.Flags().Bool("force", false, "forward requests even when enforced attestation factors fail (WARNING: reduces security)")
}
```

**`force_release.go`** — delete (the no-op `registerForceFlag` is no longer needed).

**`help` command** — custom `RunE` that delegates to existing `runHelp(args)`:

```go
var helpCmd = &cobra.Command{
    Use:                "help [TOPIC]",
    DisableFlagParsing: true,
    RunE: func(cmd *cobra.Command, args []string) error {
        runHelp(args)
        return nil
    },
}
```

**Delete from `main.go`:**
- `parseLogLevel()` — replaced by persistent flag + `PersistentPreRunE`
- `extractProvider()` — replaced by `cobra.ExactArgs(1)` / `cobra.RangeArgs(0,1)`
- `registerForceFlag()` calls
- The `switch os.Args[1]` dispatch block and manual no-args check

**Keep:**
- `filterProviders()`, `providerNotFoundError()`, `loadConfig()` — still needed in `RunE`
- All of `help.go`, `selfcheck.go`

**Update `cmd/teep/main_test.go`:** tests that call `runVerify(args)` directly
become `rootCmd.SetArgs(args); rootCmd.Execute()` — the subprocess crasher test
for `os.Exit` becomes a simple in-process call since `RunE` returns an error
instead of calling `os.Exit`.

---

## 6. Files Changed

| File | Action |
|------|--------|
| `cmd/teep/cmd.go` | Create — root, serve, verify, self-check, version, help commands |
| `cmd/teep/main.go` | Shrink to just `main()` + helpers still needed by `RunE` |
| `cmd/teep/force_debug.go` | Replace `registerForceFlag(*flag.FlagSet)` with `init()` on `serveCmd` |
| `cmd/teep/force_release.go` | Delete |
| `cmd/teep/main_test.go` | Replace `runVerify(args)` calls with `rootCmd.SetArgs` + `Execute()` |
| `go.mod` / `go.sum` | Add `github.com/spf13/cobra` |
| `internal/*` | No changes |
| `cmd/teeplint/*` | No changes |

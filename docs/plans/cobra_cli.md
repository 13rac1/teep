# Plan: Migrate CLI to Cobra — REJECTED

**Status:** Rejected in favor of `github.com/peterbourgon/ff/v4`.

**Rejection reasons:**

1. **Requires package-level mutable state.** Cobra's `var rootCmd` + `init()`
   pattern violates AGENTS.md's "no mutable package-level variables" rule.
   While `rootCmd` is only used from `main()`, it sets a precedent that
   conflicts with the project's concurrency safety conventions.

2. **Auto-registered help command conflicts.** Cobra auto-registers a `help`
   subcommand during `Execute()`. Teep's custom help system (factor lookup,
   tier docs, measurement guides) requires `SetHelpCommand()` to override
   it — a workaround for framework behavior, not a feature.

3. **Prints usage on error by default.** Cobra dumps full usage text to stderr
   on every `RunE` error unless `SilenceUsage: true` is set. This is a
   regression from current behavior where errors print only the error message.

4. **Test concurrency problems.** The natural Cobra test pattern
   (`rootCmd.SetArgs` + `Execute`) mutates package-level state and prevents
   `t.Parallel()`. Avoiding this requires testing business logic functions
   directly, making the Cobra wiring effectively untestable without subprocess
   forking.

5. **Heavier dependency tree.** Cobra pulls in `pflag` and optionally `viper`.
   For security software that verifies supply chains, each dependency is a
   supply chain risk.

6. **ff/v4 is a better fit.** Pure stdlib dependencies, no global state,
   `FlagSet.SetParent` for inherited flags, `Exec` returns errors without
   ever calling `os.Exit`, no auto-registered help to conflict with. The
   entire command tree is built locally in `main()`.

---

## Original Plan (for reference)

## 1. Goal

Replace the homegrown `flag.FlagSet` CLI in `cmd/teep/` with
[`github.com/spf13/cobra`](https://github.com/spf13/cobra) in a single PR.
The current implementation has accumulated several hand-rolled workarounds that
Cobra handles natively. All `internal/` packages are unchanged.

---

## 2. Current Pain Points

| Problem | Current workaround | Cobra solution |
|---------|-------------------|----------------|
| `--log-level` must be available to all subcommands | `parseLogLevel()` pre-scans `os.Args` before dispatch (lines 69–93) | `rootCmd.PersistentFlags()` |
| Provider is a positional arg before flags | `extractProvider()` peels it off before `flag.Parse` (lines 171–176) | `cobra.ExactArgs(1)` + `args[0]` |
| Unknown subcommand produces a hand-written error | `default:` case in `switch os.Args[1]` (lines 60–64) | Cobra's built-in unknown-command error |
| `--reverify` and positional provider supplied together are silently ignored | Current code ignores PROVIDER when `--reverify` is set (violates AGENTS.md: "never silently drop") | `cobra.RangeArgs(0, 1)` + `RunE` rejects `len(args) > 0 && reverifyDir != ""` with an explicit error |
| Build-tag `--force` requires `registerForceFlag()` indirection | `force_debug.go` / `force_release.go` passing `*flag.FlagSet` | `init()` + `getForce(*cobra.Command) bool` helper in both files |
| Every `run*` function duplicates `flag.FlagSet` setup + `fs.Parse` | Boilerplate in each subcommand (e.g. lines 104–111, 184–197) | Flags declared once; `RunE` receives pre-parsed `*cobra.Command` |

Total hand-rolled plumbing eliminated: ~80 lines.

---

## 3. What Stays the Same

- **`internal/` packages** — zero changes.
- **`help.go` domain content** — `factorRegistry`, `tierRegistry`, all
  `print*Help()` functions. These are domain documentation, not CLI framework.
- **`selfcheck.go`** — business logic unchanged in the first commit (thin `RunE`
  wrappers in `cmd.go` call `runSelfCheck`/`runVersion`). In the second commit,
  their 3 `os.Exit` calls convert to error returns and signatures change to
  return `error`.
- **teeplint** — `checkCLIMain` parses `internal/verify/factory.go` (not
  `cmd/teep/main.go`) and asserts `ProviderEnvVars`, `newAttester`,
  `newReportDataVerifier`, and `supplyChainPolicy` cover every provider.
  These are in `internal/verify/` and are unaffected. However,
  `checkNoJSONUnmarshalCLI` targets `cmd/teep/main.go` by filename — after the
  migration adds `cmd/teep/cmd.go`, that check needs its filename filter widened
  to cover both files.

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
Supplying both `PROVIDER` and `--reverify` is rejected with an explicit error
(behavior change: current code silently ignores the provider in that case).

---

## 5. What the PR Does

**Add `go get github.com/spf13/cobra`.**

**Shrink `cmd/teep/main.go`** to just `main()` + helpers still needed by `RunE`:

```go
func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

**Create `cmd/teep/cmd.go`** with the root command and all subcommands wired
to the existing `run*` internals:

```go
var rootCmd = &cobra.Command{
    Use:          "teep",
    Short:        "TEE proxy and attestation verifier",
    SilenceUsage: true, // don't dump usage on RunE errors
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        // set slog level from --log-level flag
    },
}

func init() {
    rootCmd.PersistentFlags().String("log-level", "info",
        "log verbosity: debug, info, warn, error")
    rootCmd.AddCommand(serveCmd, verifyCmd, selfCheckCmd, versionCmd)
}
```

**Subcommand flags** declared in `init()` on each command — no more per-function
`flag.NewFlagSet`. `RunE` wrappers pre-extract all flag values and pass them to
`run*` functions as individual parameters. The `run*` functions do not take
`*cobra.Command` — this keeps business logic decoupled from Cobra.

New signatures after both commits:

```go
func runServe(provider string, offline, force bool) error
func runVerify(provider, model, captureDir, reverifyDir string, offline, updateConfig bool, configOut string) error
func runReverify(captureDir string) error
func runSelfCheck() error
func runVersion() error
```

**`force_debug.go`** — replace `registerForceFlag(fs *flag.FlagSet)` with:

```go
//go:build debug

func init() {
    serveCmd.Flags().Bool("force", false, "forward requests even when enforced attestation factors fail (WARNING: reduces security)")
}

func getForce(cmd *cobra.Command) bool {
    // Flag is registered in this file's init(); GetBool cannot fail here.
    v, _ := cmd.Flags().GetBool("force")
    return v
}
```

**`force_release.go`** — replace `registerForceFlag` with:

```go
//go:build !debug

func getForce(_ *cobra.Command) bool { return false }
```

Both files are kept. In release builds, the `--force` flag is never registered
so Cobra rejects it as unknown. `getForce` returns `false` unconditionally.
In debug builds, `init()` registers the flag and `getForce` reads it.

**`help` command** — use `rootCmd.SetHelpCommand()` to replace Cobra's built-in
`help` subcommand (Cobra auto-registers its own during `Execute()`; adding a
second via `AddCommand` conflicts):

```go
func init() {
    rootCmd.SetHelpCommand(&cobra.Command{
        Use:   "help [TOPIC]",
        Short: "Show help for a command or topic",
        Args:  cobra.ArbitraryArgs,
        RunE: func(cmd *cobra.Command, args []string) error {
            runHelp(args)
            return nil
        },
    })
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

**Convert `os.Exit` to error returns (separate commit).** There are 25
`os.Exit` calls across `main.go` (runServe: 5, runVerify: 8, runReverify: 3,
plus dispatch) and `selfcheck.go` (runSelfCheck: 2, runVersion: 1). Convert
all to `return fmt.Errorf(...)` so `RunE` wrappers can propagate errors
properly. `main()` handles the exit:

```go
func main() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

This is a separate commit within the same PR — first commit wires Cobra with
the existing `os.Exit` behavior, second commit converts to error returns.

**Test approach:** keep testing `run*` business logic functions directly — do NOT
use `rootCmd.SetArgs(args); rootCmd.Execute()`, which mutates package-level state
and prevents `t.Parallel()`. Cobra wiring (arg counts, unknown flags) is tested
by a small number of subprocess-based integration tests.

The subprocess crasher test (`TestRunVerify_CaptureOfflineMutuallyExclusive`)
becomes a simple in-process call since `runVerify` now returns an error instead
of calling `os.Exit`.

**Update `cmd/teep/main_test.go`:** delete `TestExtractProvider` and
`TestParseLogLevel` (functions removed). Convert the subprocess crasher test to
an in-process error check. Add `TestVerifyReverifyRejectsProvider` for the new
explicit-error behavior.

---

## 6. Files Changed

| File | Action |
|------|--------|
| `cmd/teep/cmd.go` | Create — root, serve, verify, self-check, version, help commands |
| `cmd/teep/main.go` | Shrink to just `main()` + helpers still needed by `RunE` |
| `cmd/teep/force_debug.go` | Replace `registerForceFlag(*flag.FlagSet)` with `init()` + `getForce(*cobra.Command)` |
| `cmd/teep/force_release.go` | Replace `registerForceFlag` with `getForce(*cobra.Command) bool { return false }` |
| `cmd/teep/selfcheck.go` | Convert 3 `os.Exit` calls to error returns; signatures return `error` (commit 2) |
| `cmd/teep/main_test.go` | Delete `TestExtractProvider`, `TestParseLogLevel`; add reverify+provider rejection test |
| `go.mod` / `go.sum` | Add `github.com/spf13/cobra` |
| `cmd/teeplint/main.go` | Widen `checkNoJSONUnmarshalCLI` filename filter to cover `cmd/teep/cmd.go` |
| `internal/*` | No changes |

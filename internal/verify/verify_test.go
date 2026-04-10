package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// --------------------------------------------------------------------------
// FormatReport tests
// --------------------------------------------------------------------------

// buildVerifyTestReport constructs a VerificationReport with test factors.
func buildVerifyTestReport(provider, model string) *attestation.VerificationReport {
	factors := []attestation.FactorResult{
		// Tier 1
		{Name: "nonce_match", Status: attestation.Pass, Detail: "Nonce matches (64 hex chars)", Enforced: true, Tier: attestation.TierCore},
		{Name: "tdx_quote_present", Status: attestation.Pass, Detail: "TDX quote present (1247 base64 chars)", Tier: attestation.TierCore},
		{Name: "tdx_quote_structure", Status: attestation.Pass, Detail: "Valid QuoteV4 structure", Tier: attestation.TierCore},
		{Name: "tdx_cert_chain", Status: attestation.Pass, Detail: "cert chain valid (Intel root CA)", Tier: attestation.TierCore},
		{Name: "tdx_quote_signature", Status: attestation.Pass, Detail: "Quote signature verified", Tier: attestation.TierCore},
		{Name: "tdx_debug_disabled", Status: attestation.Pass, Detail: "Debug bit is 0", Enforced: true, Tier: attestation.TierCore},
		{Name: "signing_key_present", Status: attestation.Pass, Detail: "enclave pubkey present (04a3b2...)", Enforced: true, Tier: attestation.TierCore},
		// Tier 2
		{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "REPORTDATA binds signing key + nonce", Enforced: true, Tier: attestation.TierBinding},
		{Name: "intel_pcs_collateral", Status: attestation.Skip, Detail: "Quote age not determinable", Tier: attestation.TierBinding},
		{Name: "tdx_tcb_current", Status: attestation.Pass, Detail: "TCB is UpToDate per Intel PCS", Tier: attestation.TierBinding},
		{Name: "nvidia_payload_present", Status: attestation.Pass, Detail: "NVIDIA payload present (512 chars)", Tier: attestation.TierBinding},
		{Name: "nvidia_signature", Status: attestation.Pass, Detail: "JWT signature valid (RS256)", Tier: attestation.TierBinding},
		{Name: "nvidia_claims", Status: attestation.Pass, Detail: "Claims valid", Tier: attestation.TierBinding},
		{Name: "nvidia_nonce_client_bound", Status: attestation.Skip, Detail: "nonce not found in NVIDIA payload", Tier: attestation.TierBinding},
		{Name: "nvidia_nras_verified", Status: attestation.Skip, Detail: "offline mode; NRAS skipped", Tier: attestation.TierBinding},
		{Name: "e2ee_capable", Status: attestation.Pass, Detail: "E2EE key exchange possible", Tier: attestation.TierBinding},
		// Tier 3
		{Name: "tls_key_binding", Status: attestation.Fail, Detail: "no TLS key in attestation", Tier: attestation.TierSupplyChain},
		{Name: "cpu_gpu_chain", Status: attestation.Fail, Detail: "CPU-GPU attestation not bound", Tier: attestation.TierSupplyChain},
		{Name: "measured_model_weights", Status: attestation.Fail, Detail: "no model weight hashes", Tier: attestation.TierSupplyChain},
		{Name: "build_transparency_log", Status: attestation.Fail, Detail: "no build transparency log", Tier: attestation.TierSupplyChain},
		{Name: "cpu_id_registry", Status: attestation.Fail, Detail: "no CPU ID registry check", Tier: attestation.TierSupplyChain},
	}

	passed, failed, skipped := 0, 0, 0
	enforcedFailed, allowedFailed := 0, 0
	for _, f := range factors {
		switch f.Status {
		case attestation.Pass:
			passed++
		case attestation.Fail:
			failed++
			if f.Enforced {
				enforcedFailed++
			} else {
				allowedFailed++
			}
		case attestation.Skip:
			skipped++
		}
	}

	return &attestation.VerificationReport{
		Provider:       provider,
		Model:          model,
		Timestamp:      time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC),
		Factors:        factors,
		Passed:         passed,
		Failed:         failed,
		Skipped:        skipped,
		EnforcedFailed: enforcedFailed,
		AllowedFailed:  allowedFailed,
	}
}

func TestFormatReport_Header(t *testing.T) {
	r := buildVerifyTestReport("venice", "e2ee-qwen3")
	out := FormatReport(r)

	if !strings.Contains(out, "Attestation Report: venice / e2ee-qwen3") {
		t.Errorf("header not found; output:\n%s", out)
	}
}

func TestFormatReport_Separator(t *testing.T) {
	r := buildVerifyTestReport("venice", "e2ee-qwen3")
	out := FormatReport(r)

	if !strings.Contains(out, "\u2550\u2550\u2550") {
		t.Errorf("separator line not found; output:\n%s", out)
	}
}

func TestFormatReport_TierLabels(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)

	for _, label := range []string{
		"Tier 1: Core Attestation",
		"Tier 2: Binding & Crypto",
		"Tier 3: Supply Chain & Channel Integrity",
	} {
		if !strings.Contains(out, label) {
			t.Errorf("tier label %q not found; output:\n%s", label, out)
		}
	}
}

func TestFormatReport_StatusIcons(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)

	if !strings.Contains(out, "\u2713") { // ✓ pass
		t.Error("pass icon ✓ not found in output")
	}
	if !strings.Contains(out, "\u2717") { // ✗ fail
		t.Error("fail icon ✗ not found in output")
	}
	if !strings.Contains(out, "?") { // ? skip
		t.Error("skip icon ? not found in output")
	}
}

func TestFormatReport_EnforcedTag(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)

	if !strings.Contains(out, "[ENFORCED]") {
		t.Errorf("[ENFORCED] tag not found; output:\n%s", out)
	}
	if !strings.Contains(out, "[ALLOWED]") {
		t.Errorf("[ALLOWED] tag not found; output:\n%s", out)
	}
}

func TestFormatReport_ScoreLine(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)

	if !strings.Contains(out, "Score:") {
		t.Errorf("Score line not found; output:\n%s", out)
	}
	if !strings.Contains(out, "13/21 passed") {
		t.Errorf("expected '13/21 passed' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "3 skipped") {
		t.Errorf("expected '3 skipped' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "5 failed") {
		t.Errorf("expected '5 failed' in score line; output:\n%s", out)
	}
	if !strings.Contains(out, "0 enforced, 5 allowed") {
		t.Errorf("expected '0 enforced, 5 allowed' in score line; output:\n%s", out)
	}
}

func TestFormatReport_FactorNamesPresent(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)

	for _, name := range []string{
		"nonce_match",
		"tdx_quote_present",
		"tdx_reportdata_binding",
		"tls_key_binding",
		"cpu_id_registry",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("factor name %q not found in output:\n%s", name, out)
		}
	}
}

func TestFormatReport_EmptyReport(t *testing.T) {
	r := &attestation.VerificationReport{
		Provider:  "test",
		Model:     "test-model",
		Timestamp: time.Now(),
	}
	out := FormatReport(r)

	if !strings.Contains(out, "Attestation Report: test / test-model") {
		t.Errorf("header missing from empty report output:\n%s", out)
	}
	if !strings.Contains(out, "Score: 0/0") {
		t.Errorf("score line for empty report should read '0/0'; output:\n%s", out)
	}
	if strings.Contains(out, "enforced") {
		t.Errorf("score line should omit breakdown when no failures; output:\n%s", out)
	}
}

func TestFormatReport_ScoreLineWithEnforcedFailures(t *testing.T) {
	r := &attestation.VerificationReport{
		Provider:  "test",
		Model:     "m",
		Timestamp: time.Now(),
		Factors: []attestation.FactorResult{
			{Name: "a", Status: attestation.Pass, Tier: attestation.TierCore},
			{Name: "b", Status: attestation.Fail, Enforced: true, Tier: attestation.TierCore},
			{Name: "c", Status: attestation.Fail, Enforced: false, Tier: attestation.TierSupplyChain},
		},
		Passed: 1, Failed: 2, EnforcedFailed: 1, AllowedFailed: 1,
	}
	out := FormatReport(r)
	if !strings.Contains(out, "1 enforced, 1 allowed") {
		t.Errorf("expected '1 enforced, 1 allowed'; output:\n%s", out)
	}
}

func TestFormatReport_FooterHint(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)
	if !strings.Contains(out, "teep help") {
		t.Errorf("footer hint not found; output:\n%s", out)
	}
}

func TestFormatReport_SeparatorLength(t *testing.T) {
	r := buildVerifyTestReport("venice", "some-model")
	out := FormatReport(r)

	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		t.Fatalf("output too short to have a separator line: %q", out)
	}

	header := lines[0]
	separator := lines[1]

	headerRunes := []rune(header)
	sepRunes := []rune(separator)

	if len(headerRunes) != len(sepRunes) {
		t.Errorf("separator rune length %d != header rune length %d",
			len(sepRunes), len(headerRunes))
	}
}

func TestFormatReport_MetadataBlock(t *testing.T) {
	r := buildVerifyTestReport("venice", "e2ee-qwen3")
	r.Metadata = map[string]string{
		"hardware":     "intel-tdx",
		"upstream":     "Qwen/Qwen3.5-122B-A10B",
		"app":          "dstack-nvidia-0.5.5",
		"compose_hash": "242a6272abcdef0123456789",
		"nonce_source": "client",
		"candidates":   "1/6 evaluated",
		"event_log":    "30 entries",
	}
	out := FormatReport(r)

	for _, want := range []string{
		"Hardware:",
		"intel-tdx",
		"Upstream:",
		"Qwen/Qwen3.5-122B-A10B",
		"App:",
		"dstack-nvidia-0.5.5",
		"Compose hash:",
		"242a6272abcdef01...",
		"Nonce source:",
		"client",
		"Candidates:",
		"1/6 evaluated",
		"Event log:",
		"30 entries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata %q not found in output:\n%s", want, out)
		}
	}

	metaIdx := strings.Index(out, "Hardware:")
	tier1Idx := strings.Index(out, "Tier 1:")
	if metaIdx < 0 || tier1Idx < 0 || metaIdx > tier1Idx {
		t.Errorf("metadata should appear before Tier 1; meta=%d, tier1=%d", metaIdx, tier1Idx)
	}
}

func TestFormatReport_NoMetadataBlock(t *testing.T) {
	r := buildVerifyTestReport("neardirect", "some-model")
	out := FormatReport(r)

	if strings.Contains(out, "Hardware:") {
		t.Errorf("metadata block should not appear for empty metadata; output:\n%s", out)
	}
}

func TestStatusIcon(t *testing.T) {
	tests := []struct {
		status attestation.Status
		want   string
	}{
		{attestation.Pass, "\u2713"},
		{attestation.Fail, "\u2717"},
		{attestation.Skip, "?"},
		{attestation.Status(99), "?"},
	}
	for _, tc := range tests {
		got := statusIcon(tc.status)
		if got != tc.want {
			t.Errorf("statusIcon(%v): got %q, want %q", tc.status, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------------
// CompareReports / PrintReportDiff
// --------------------------------------------------------------------------

// captureStderr redirects os.Stderr for the duration of fn and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old; r.Close() })
	fn()
	w.Close()
	os.Stderr = old
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestCompareReports_Match(t *testing.T) {
	report := "line1\nline2\nline3"
	if err := CompareReports(report, report); err != nil {
		t.Errorf("CompareReports with identical strings should return nil, got %v", err)
	}
}

func TestCompareReports_Mismatch(t *testing.T) {
	a := "line1\nline2"
	b := "line1\nchanged"
	err := CompareReports(a, b)
	if err == nil {
		t.Fatal("CompareReports should return error on mismatch")
	}
	if !strings.Contains(err.Error(), "differs") {
		t.Errorf("error = %q, should mention 'differs'", err)
	}
}

func TestPrintReportDiff_IdenticalProducesNoOutput(t *testing.T) {
	out := captureStderr(t, func() { PrintReportDiff("same\nlines", "same\nlines") })
	if out != "" {
		t.Errorf("identical strings should produce no diff output, got %q", out)
	}
}

func TestPrintReportDiff_ShowsChangedLines(t *testing.T) {
	out := captureStderr(t, func() { PrintReportDiff("aaa\nbbb\nccc", "aaa\nBBB\nccc") })
	if !strings.Contains(out, "- bbb") {
		t.Errorf("diff should show removed line '- bbb', got %q", out)
	}
	if !strings.Contains(out, "+ BBB") {
		t.Errorf("diff should show added line '+ BBB', got %q", out)
	}
}

func TestPrintReportDiff_DifferentLengths(t *testing.T) {
	out := captureStderr(t, func() { PrintReportDiff("a\nb", "a\nb\nc") })
	if !strings.Contains(out, "+ c") {
		t.Errorf("diff should show added line '+ c', got %q", out)
	}
}

func TestRun_EmptyRaw_NoTDX(t *testing.T) {
	// Verify nil-guard paths: empty attestation returns a report (not an error).
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice": {Name: "venice", BaseURL: "http://test", APIKey: ""},
		},
	}
	cp := cfg.Providers["venice"]

	// Use a mock attester that returns minimal raw attestation.
	ts := newMinimalAttestServer(t)
	defer ts.Close()

	replayClient := &http.Client{Transport: ts.Transport}
	origGetter := attestation.TDXCollateralGetter
	attestation.TDXCollateralGetter = nil
	t.Cleanup(func() { attestation.TDXCollateralGetter = origGetter })

	report, err := Run(context.Background(), &Options{
		Config:       cfg,
		Provider:     cp,
		ProviderName: "venice",
		ModelName:    "test-model",
		Offline:      true,
		Client:       replayClient,
		Nonce:        attestation.NewNonce(),
		CapturedE2EE: &attestation.E2EETestResult{Detail: "skipped in test"},
	})
	if err != nil {
		t.Fatalf("Run with empty raw: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	t.Logf("factors: %d", len(report.Factors))
}

func TestRun_EmptyRaw_WithCapture(t *testing.T) {
	// Exercises the capture-save and verifyCapture (self-check) code paths.
	cfg := &config.Config{
		Providers: map[string]*config.Provider{
			"venice": {Name: "venice", BaseURL: "http://test", APIKey: ""},
		},
	}
	cp := cfg.Providers["venice"]

	ts := newMinimalAttestServer(t)
	defer ts.Close()

	replayClient := &http.Client{Transport: ts.Transport}
	origGetter := attestation.TDXCollateralGetter
	attestation.TDXCollateralGetter = nil
	t.Cleanup(func() { attestation.TDXCollateralGetter = origGetter })

	captureDir := t.TempDir()
	report, err := Run(context.Background(), &Options{
		Config:       cfg,
		Provider:     cp,
		ProviderName: "venice",
		ModelName:    "test-model",
		Offline:      false,
		Client:       replayClient,
		Nonce:        attestation.NewNonce(),
		CapturedE2EE: &attestation.E2EETestResult{Detail: "skipped in test"},
		CaptureDir:   captureDir,
	})
	if err != nil {
		t.Fatalf("Run with capture: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	t.Logf("factors: %d, captureDir: %s", len(report.Factors), captureDir)
}

// minimalAttestTransport serves a minimal Venice attestation JSON response.
type minimalAttestTransport struct{}

func (minimalAttestTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	body := `{"model":"test-model","intel_quote":"","signing_key":""}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

// newMinimalAttestServer creates a test HTTP server that returns minimal attestation JSON.
type minimalAttestServerResult struct {
	Transport http.RoundTripper
}

func newMinimalAttestServer(t *testing.T) *minimalAttestServerResult {
	t.Helper()
	return &minimalAttestServerResult{Transport: minimalAttestTransport{}}
}

func (s *minimalAttestServerResult) Close() {}

// --------------------------------------------------------------------------
// Replay error paths
// --------------------------------------------------------------------------

func TestReplay_BadDir(t *testing.T) {
	ctx := context.Background()
	_, _, err := Replay(ctx, "/no/such/directory/for/testing", func(_ string) (*config.Config, *config.Provider, error) {
		return nil, nil, nil
	})
	if err == nil {
		t.Fatal("expected error for non-existent capture dir")
	}
	if !strings.Contains(err.Error(), "load capture") {
		t.Errorf("error = %q, should mention 'load capture'", err)
	}
}

func TestReplay_InvalidNonce(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"provider":"test","model":"m","nonce_hex":"not-valid-hex","captured_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	ctx := context.Background()
	_, _, err := Replay(ctx, dir, func(_ string) (*config.Config, *config.Provider, error) {
		return nil, nil, nil
	})
	if err == nil {
		t.Fatal("expected error for invalid nonce in manifest")
	}
	if !strings.Contains(err.Error(), "invalid nonce") {
		t.Errorf("error = %q, should mention 'invalid nonce'", err)
	}
}

func TestReplay_CfgLoaderError(t *testing.T) {
	dir := t.TempDir()
	nonce := attestation.NewNonce()
	manifest := fmt.Sprintf(`{"provider":"test","model":"m","nonce_hex":%q,"captured_at":"2026-01-01T00:00:00Z"}`, nonce.Hex())
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	ctx := context.Background()
	_, _, err := Replay(ctx, dir, func(_ string) (*config.Config, *config.Provider, error) {
		return nil, nil, errors.New("config load error")
	})
	if err == nil {
		t.Fatal("expected error from cfgLoader")
	}
	if !strings.Contains(err.Error(), "load config for replay") {
		t.Errorf("error = %q, should mention 'load config for replay'", err)
	}
}

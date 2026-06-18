package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// skipTinfoilIntegration skips the test if TINFOIL_API_KEY is unset or if
// running under go test -short.
func skipTinfoilIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("TINFOIL_API_KEY") == "" {
		t.Skip("TINFOIL_API_KEY not set")
	}
}

// tinfoilIntegrationModel returns the model name to use, defaulting to a
// known-good TEE model if TINFOIL_E2EE_MODEL is unset.
func tinfoilIntegrationModel() string {
	if m := os.Getenv("TINFOIL_E2EE_MODEL"); m != "" {
		if strings.HasPrefix(m, "tinfoil_v3_cloud:") {
			return m
		}
		return "tinfoil_v3_cloud:" + m
	}
	return "tinfoil_v3_cloud:llama3-3-70b"
}

// integrationTinfoilPlaintextConfig returns a config pointing at the live
// Tinfoil API with E2EE disabled and Offline true.
func integrationTinfoilPlaintextConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"tinfoil_v3_cloud": {
				Name:    "tinfoil_v3_cloud",
				BaseURL: "https://inference.tinfoil.sh",
				APIKey:  os.Getenv("TINFOIL_API_KEY"),
				E2EE:    false,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
}

func TestIntegration_Tinfoil(t *testing.T) {
	skipTinfoilIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationTinfoilPlaintextConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, tinfoilIntegrationModel(), false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})

	t.Run("Streaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, integrationTinfoilPlaintextConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, tinfoilIntegrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	// E2EE subtests are skipped: Tinfoil's router uses SEV-SNP, but
	// BuildReport only has TDX evaluators. tee_reportdata_binding Fails
	// for SEV-SNP, which blocks the proxy's E2EE path. SEV-SNP evaluator
	// support will enable these tests.
	t.Run("E2EEStreaming", func(t *testing.T) {
		t.Skip("SEV-SNP: tee_reportdata_binding requires TDX evaluators; SEV-SNP support pending")
	})

	t.Run("E2EENonStream", func(t *testing.T) {
		t.Skip("SEV-SNP: tee_reportdata_binding requires TDX evaluators; SEV-SNP support pending")
	})

	t.Run("AttestationReport", func(t *testing.T) {
		// Plaintext (E2EE off) + online mode so the report includes full
		// verification without being blocked by SEV-SNP binding.
		cfg := integrationTinfoilPlaintextConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := tinfoilIntegrationModel()
		_, upstreamModel, _ := strings.Cut(model, ":")

		// First chat request triggers attestation and populates the report cache.
		chatResp := postChatIntegration(t, proxySrv.URL, model, true)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=tinfoil_v3_cloud&model=%s", proxySrv.URL, upstreamModel)
		reportResp, err := integrationClient.Get(reportURL)
		if err != nil {
			t.Fatalf("GET report: %v", err)
		}
		defer reportResp.Body.Close()

		if reportResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(reportResp.Body)
			t.Fatalf("status = %d, want 200; body=%s", reportResp.StatusCode, body)
		}

		var report attestation.VerificationReport
		if err := json.NewDecoder(reportResp.Body).Decode(&report); err != nil {
			t.Fatalf("decode report: %v", err)
		}

		// Live test against actual SEV-SNP hardware. The report evaluators
		// are TDX-only, so many factors will fail. Assert only TEE-agnostic
		// factors. e2ee_usable cannot be asserted because E2EE is disabled
		// (SEV-SNP binding blocks the proxy E2EE path).
		mustPass := []string{
			"nonce_match",
			"signing_key_present",
			"e2ee_capable",
			"tls_key_binding",
		}
		for _, name := range mustPass {
			f, ok := findFactor(report.Factors, name)
			if !ok {
				t.Errorf("factor %q not found in report", name)
				continue
			}
			if f.Status != attestation.Pass {
				t.Errorf("factor %q: status = %v, want Pass; detail: %s", name, f.Status, f.Detail)
			}
		}

		// Log every non-Pass factor for diagnostics.
		for _, f := range report.Factors {
			if f.Status == attestation.Pass {
				continue
			}
			t.Logf("  %s %s: %s", f.Status, f.Name, f.Detail)
		}

		t.Logf("score: %d/%d passed, %d skipped, %d failed",
			report.Passed, report.Passed+report.Failed+report.Skipped, report.Skipped, report.Failed)
	})
}

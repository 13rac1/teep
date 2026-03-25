package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// skipNanogptIntegration skips the test if NANOGPT_API_KEY is unset or if
// running under go test -short.
func skipNanogptIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if os.Getenv("NANOGPT_API_KEY") == "" {
		t.Skip("NANOGPT_API_KEY not set")
	}
}

// nanogptIntegrationModel returns the NanoGPT model to use, defaulting to a
// known-good TEE model if NANOGPT_MODEL is unset.
func nanogptIntegrationModel() string {
	if m := os.Getenv("NANOGPT_MODEL"); m != "" {
		return m
	}
	return "TEE/llama-3.3-70b-instruct"
}

// nanogptIntegrationConfig returns a config pointing at the live NanoGPT API
// with E2EE disabled and Offline true (skips Intel PCS, NRAS, PoC network
// calls).
func nanogptIntegrationConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Offline:    true,
		Providers: map[string]*config.Provider{
			"nanogpt": {
				Name:    "nanogpt",
				BaseURL: "https://nano-gpt.com/api",
				APIKey:  os.Getenv("NANOGPT_API_KEY"),
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}
}

func TestIntegration_NanoGPT(t *testing.T) {
	skipNanogptIntegration(t)

	t.Run("NonStream", func(t *testing.T) {
		proxySrv := newProxyServer(t, nanogptIntegrationConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, nanogptIntegrationModel(), false)
		defer resp.Body.Close()
		assertNonStreamResponse(t, resp)
	})

	t.Run("Streaming", func(t *testing.T) {
		proxySrv := newProxyServer(t, nanogptIntegrationConfig(t))
		defer proxySrv.Close()
		resp := postChatIntegration(t, proxySrv.URL, nanogptIntegrationModel(), true)
		defer resp.Body.Close()
		assertStreamResponse(t, resp)
	})

	t.Run("AttestationReport", func(t *testing.T) {
		cfg := nanogptIntegrationConfig(t)
		cfg.Offline = false
		proxySrv := newProxyServer(t, cfg)
		defer proxySrv.Close()

		model := nanogptIntegrationModel()

		// First chat request triggers attestation and populates the report cache.
		chatResp := postChatIntegration(t, proxySrv.URL, model, true)
		io.Copy(io.Discard, chatResp.Body)
		chatResp.Body.Close()

		reportURL := fmt.Sprintf("%s/v1/tee/report?provider=nanogpt&model=%s", proxySrv.URL, model)
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
		assertReportFactors(t, &report)
	})
}

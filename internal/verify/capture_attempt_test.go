package verify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

func TestVerificationCaptureKeepsFinalEvidence(t *testing.T) {
	t.Parallel()
	// A repeated collateral URL has no nonce to distinguish its responses.
	// Replay must retain discovery but must not select the first evidence.
	for range 4 {
		t.Run("independent run", func(t *testing.T) {
			t.Parallel()
			var attempt atomic.Value
			attempt.Store("old evidence")
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := attempt.Load().(string)
				if r.URL.Path == "/discovery" {
					body = "original route"
				}
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			client := upstream.Client()
			state := &verificationCapture{discovery: capture.WrapRecording(client.Transport)}
			client.Transport = state.discovery
			get := func(client *http.Client, path string) string {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+path, http.NoBody)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				return string(body)
			}
			get(client, "/discovery")
			state.beginEvidence(client)
			get(client, "/evidence")
			// The preceding request has completed before the next attempt starts.
			attempt.Store("final evidence")
			state.beginEvidence(client)
			get(client, "/evidence")
			entries := state.entries()
			if len(entries) != 2 {
				t.Fatalf("retained %d responses, want discovery and final evidence", len(entries))
			}
			replay := &http.Client{Transport: capture.NewReplayTransport(entries)}
			if get(replay, "/discovery") != "original route" || get(replay, "/evidence") != "final evidence" {
				t.Fatal("replay mixed evidence attempts or lost the immutable route")
			}
		})
	}
}

func TestVerificationCaptureFinalOutcomeReplay(t *testing.T) {
	// Use real signed evidence and normal factor enforcement for the saved
	// attempt. Poison a prior attempt so retaining it makes self-check fail.
	manifest, entries, err := capture.Load("../integration/testdata/tinfoil_v3_cloud_glm-5-2_20260817_003424")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := attestation.ParseNonce(manifest.NonceHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"success", "response failure", "request failure"} {
		t.Run(outcome, func(t *testing.T) {
			cp := &config.Provider{Name: manifest.Provider, BaseURL: "https://inference.tinfoil.sh", APIKey: "test"}
			cfg := &config.Config{Providers: map[string]*config.Provider{manifest.Provider: cp}}
			state := &verificationCapture{discovery: capture.WrapRecording(capture.NewReplayTransport(entries))}
			client := &http.Client{Transport: state.discovery}
			state.beginEvidence(client)
			stale := entries[0]
			stale.Body = []byte("invalid prior attestation")
			state.evidence.Entries = []capture.RecordedEntry{stale}
			opts := &Options{Config: cfg, Provider: cp, ProviderName: manifest.Provider, ModelName: manifest.Model,
				Client: client, Nonce: nonce, CapturedE2EE: e2eeResultFromOutcome(manifest.E2EE),
				VerificationTime: verificationTimeForCapture(&manifest), CaptureDir: t.TempDir(), capture: state}
			route := provider.ResolvedRoute{}
			result, err := runEvidence(context.Background(), opts, &route)
			if err != nil {
				t.Fatal(err)
			}
			if result.report.Blocked() {
				t.Fatal("fixture failed normal enforcement")
			}
			if outcome == "request failure" {
				result.e2ee = nil
			}
			if outcome != "success" {
				completeTLSInference(&result, errors.New("key rejection retry exhausted"))
			}
			if err := saveCapture(t.Context(), opts, state.entries(), nonce, result.e2ee, result.report, nil); err != nil {
				t.Fatalf("final evidence and inference outcome did not round-trip: %v", err)
			}
		})
	}
}

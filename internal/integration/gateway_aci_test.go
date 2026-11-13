package integration

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/verify"
)

// gatewayACIFixtures are the live captures of the private-ai-gateway's ACI/1
// gateway variant, one for each provider that forwards it, with the base URL
// of the capture and the provider's response parser. The base URL is stated
// because NanoGPT's carries a path, which the first request URL does not
// show apart from the attestation path. Phala Cloud verifies the canonical
// report of /v1/aci/attestation instead; its replay test uses its own
// capture.
var gatewayACIFixtures = []struct {
	prefix  string
	baseURL string
	parse   func(context.Context, []byte) (*attestation.RawAttestation, error)
}{
	{"nanogpt_aci", "https://nano-gpt.com/api", nanogpt.ParseAttestationResponse},
}

// gatewayACIBaseURL returns the stated base URL of a fixture after it checks
// that the captured attestation request starts with it.
func gatewayACIBaseURL(t *testing.T, env *fixtureEnv, baseURL string) string {
	t.Helper()
	if !strings.HasPrefix(env.entries[0].URL, baseURL+"/v1/") {
		t.Fatalf("fixture attestation URL %q is not under base URL %q", env.entries[0].URL, baseURL)
	}
	return baseURL
}

// TestVerifyRun_GatewayACI_Fixtures replays the NanoGPT capture of the ACI/1
// gateway variant through verify.Run with the production policy. The gateway
// evidence, its REPORTDATA binding of the client nonce, the key custody chain
// to the shared gateway pins and the GPU evidence nonce must pass; the nonce
// factors (no echoed nonce) and the factors that describe the inference host
// and the unnamed backend are allowed failures.
func TestVerifyRun_GatewayACI_Fixtures(t *testing.T) {
	for _, fx := range gatewayACIFixtures {
		t.Run(fx.prefix, func(t *testing.T) {
			env := loadFixture(t, fx.prefix)
			cfg, cp := buildVerifyRunConfig(env.manifest.Provider, gatewayACIBaseURL(t, &env, fx.baseURL))
			report, err := verify.Run(context.Background(), &verify.Options{
				Config:           cfg,
				Provider:         cp,
				ProviderName:     env.manifest.Provider,
				ModelName:        env.manifest.Model,
				Client:           env.client,
				Nonce:            env.nonce,
				CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
				VerificationTime: fixtureVerificationTime(&env),
			})
			if err != nil {
				t.Fatalf("verify.Run: %v", err)
			}
			logReportScore(t, report)
			assertNoEnforcedFailures(t, report)
			assertMustPass(t, report, []string{
				"signing_key_present",
				"aci_key_custody",
				"nvidia_signature",
				"nvidia_nonce_client_bound",
				"gateway_tee_quote_present",
				"gateway_tee_quote_structure",
				"gateway_tee_cert_chain",
				"gateway_tee_quote_signature",
				"gateway_tee_debug_disabled",
				"gateway_tee_measurement",
				"gateway_tee_reportdata_binding",
				"gateway_compose_binding",
				"gateway_event_log_integrity",
			})
			for _, name := range []string{"tee_quote_present", "tee_reportdata_binding", "aci_backend_named", "nonce_match", "gateway_nonce_match"} {
				f := findFactor(t, report, name)
				if f.Status != attestation.Fail || f.Enforced {
					t.Errorf("%s: status=%s enforced=%v, want an allowed Fail", name, f.Status, f.Enforced)
				}
			}
			if f := findFactor(t, report, "nonce_match"); !strings.Contains(f.Detail, "no echoed nonce") {
				t.Errorf("nonce_match detail = %q, want the no-echo failure", f.Detail)
			}
			// The compatibility route binds the signing key, not the keyset digest:
			// the report carries no digest, so responses are not checked against one.
			if report.ACIKeysetDigest != "" {
				t.Errorf("compatibility-route report carries keyset digest %q", report.ACIKeysetDigest)
			}
		})
	}
}

// A gateway identity outside the pins fails the key custody chain: the
// accepted KMS root and app id decide which gateway teep accepts.
func TestGatewayACI_PinsDecideCustody(t *testing.T) {
	for _, fx := range gatewayACIFixtures {
		t.Run(fx.prefix, func(t *testing.T) {
			env := loadFixture(t, fx.prefix)
			raw, err := fx.parse(context.Background(), env.entries[0].Body)
			if err != nil {
				t.Fatalf("parse fixture attestation: %v", err)
			}
			at := fixtureVerificationTime(&env)
			if r := aci.VerifyKeyset(raw, at, aci.GatewayPins()); r == nil || !r.CustodyChainValid {
				t.Fatalf("custody with the gateway pins: %+v", r)
			}
			pins := aci.GatewayPins()
			for _, tc := range []struct {
				name string
				pins aci.Pins
			}{
				{"other KMS root", aci.Pins{KMSRoots: []string{"03" + strings.Repeat("11", 32)}, GatewayAppIDs: pins.GatewayAppIDs}},
				{"other app id", aci.Pins{KMSRoots: pins.KMSRoots, GatewayAppIDs: []string{strings.Repeat("22", 20)}}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := aci.VerifyKeyset(raw, at, tc.pins)
					if r == nil || r.CustodyChainValid {
						t.Fatalf("custody with %s passed: %+v", tc.name, r)
					}
				})
			}
		})
	}
}

// Concurrent verification of the Venice and NanoGPT ACI/1
// fixtures keeps each provider's policy: all reach the same gateway with the
// shared pins, and each binds its E2EE key through the gateway REPORTDATA
// factor.
func TestVerifyRun_ConcurrentACIProviders(t *testing.T) {
	venice := loadFixture(t, "venice_aci")
	envs := make([]fixtureEnv, 0, 1+len(gatewayACIFixtures))
	envs = append(envs, venice)
	baseURLs := make([]string, 0, 1+len(gatewayACIFixtures))
	baseURLs = append(baseURLs, extractBaseURL(t, venice.entries))
	for _, fx := range gatewayACIFixtures {
		env := loadFixture(t, fx.prefix)
		envs = append(envs, env)
		baseURLs = append(baseURLs, gatewayACIBaseURL(t, &env, fx.baseURL))
	}
	type result struct {
		provider string
		report   *attestation.VerificationReport
		err      error
	}
	results := make(chan result, 2*len(envs))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		for i, env := range envs {
			cfg, cp := buildVerifyRunConfig(env.manifest.Provider, baseURLs[i])
			wg.Go(func() {
				<-start
				report, err := verify.Run(context.Background(), &verify.Options{
					Config:           cfg,
					Provider:         cp,
					ProviderName:     env.manifest.Provider,
					ModelName:        env.manifest.Model,
					Client:           &http.Client{Transport: capture.NewReplayTransport(env.entries)},
					Nonce:            env.nonce,
					CapturedE2EE:     fixtureE2EEResult(env.manifest.E2EE),
					VerificationTime: fixtureVerificationTime(&env),
				})
				results <- result{env.manifest.Provider, report, err}
			})
		}
	}
	close(start)
	wg.Wait()
	close(results)
	seen := map[string]int{}
	for got := range results {
		seen[got.provider]++
		if got.err != nil {
			t.Errorf("verify %s: %v", got.provider, got.err)
			continue
		}
		assertNoEnforcedFailures(t, got.report)
		if got.report.Provider != got.provider {
			t.Errorf("report provider = %q, want %q", got.report.Provider, got.provider)
		}
		if f := findFactor(t, got.report, "aci_key_custody"); f.Status != attestation.Pass {
			t.Errorf("%s: aci_key_custody = %v %q", got.provider, f.Status, f.Detail)
		}
		// Each provider encrypts to the gateway key that the gateway quote
		// binds.
		if got.report.E2EEBindingFactor != attestation.FactorGWReportData {
			t.Errorf("%s: E2EEBindingFactor = %q", got.provider, got.report.E2EEBindingFactor)
		}
		if got.report.BackendFormat != attestation.FormatACI1 {
			t.Errorf("%s: BackendFormat = %q", got.provider, got.report.BackendFormat)
		}
	}
	for _, p := range []string{"venice", "nanogpt"} {
		if seen[p] != 2 {
			t.Errorf("%s: %d reports, want 2", p, seen[p])
		}
	}
}

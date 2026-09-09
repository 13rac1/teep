package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
)

func TestNearReplayConfigurationIndependentOfProbe(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cp := &config.Provider{BaseURL: "https://API.NEAR.AI:443", E2EE: enabled}
		recorded, err := nearCaptureConfig("nearcloud", cp)
		if err != nil {
			t.Fatal(err)
		}
		for _, probe := range []string{"skipped", "success", "failure"} {
			manifest := &capture.Manifest{Provider: "nearcloud", NearConfig: recorded}
			if probe != "skipped" {
				if enabled {
					manifest.E2EE = &capture.E2EEOutcome{Attempted: true, Failed: probe == "failure"}
				} else {
					manifest.TLSInference = &capture.TLSInferenceOutcome{Attempted: true, Failed: probe == "failure"}
				}
			}
			if _, err := validateNearReplay(manifest, cp, nil); err != nil {
				t.Fatal(err)
			}
			changed := *cp
			changed.E2EE = !enabled
			if _, err := validateNearReplay(manifest, &changed, nil); err == nil {
				t.Fatal("accepted changed inference mode")
			}
			changed = *cp
			changed.BaseURL = "https://completions.near.ai"
			if _, err := validateNearReplay(manifest, &changed, nil); err != nil {
				t.Fatal("unused NearCloud base_url changed replay:", err)
			}
			manifest.NearConfig = nil
			if _, err := validateNearReplay(manifest, cp, nil); err == nil {
				t.Fatal("inferred missing configuration from probe")
			}
		}
	}
}

func TestNearRecordedSelectionValidation(t *testing.T) {
	index := uint64(1)
	cp := &config.Provider{BaseURL: "https://completions.near.ai", E2EE: true}
	cfg, err := nearCaptureConfig("neardirect", cp)
	if err != nil {
		t.Fatal(err)
	}
	makeManifest := func() *capture.Manifest {
		return &capture.Manifest{Provider: "neardirect", Model: "model", NearConfig: cfg, NearRoute: &capture.NearRoute{Canonical: "model.completions.near.ai", Index: &index, Authority: "model-i1.completions.near.ai", Mode: "discovered"}}
	}
	entries := []capture.RecordedEntry{
		{Method: "GET", URL: "https://completions.near.ai/endpoints", Status: 200, Body: []byte(`{"endpoints":[{"domain":"model.completions.near.ai","models":["model"]}]}`)},
		{Method: "GET", URL: "https://completions.near.ai/backends/count?domain=model.completions.near.ai", Status: 200, Body: []byte(`{"domain":"model.completions.near.ai","requested_domain":"model.completions.near.ai","healthy":2,"total":2}`)},
		// This is routing validation only. The production verifier must authenticate peer evidence afterwards.
		{Method: "GET", URL: "https://model-i1.completions.near.ai/v1/attestation/report", Status: 200, TLSVersion: "TLS 1.3", PeerSPKIDER: []byte("not trusted by this validation")},
	}
	if _, err := validateNearReplay(makeManifest(), cp, entries); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*capture.Manifest){
		func(m *capture.Manifest) { m.NearRoute.Mode = "explicit" },
		func(m *capture.Manifest) { m.NearRoute.Index = nil },
		func(m *capture.Manifest) { value := uint64(2); m.NearRoute.Index = &value },
		func(m *capture.Manifest) { m.NearRoute.Authority = "other-i1.completions.near.ai" },
		func(m *capture.Manifest) { m.NearRoute.Canonical = "other.completions.near.ai" },
	} {
		manifest := makeManifest()
		change(manifest)
		if _, err := validateNearReplay(manifest, cp, entries); err == nil {
			t.Fatal("accepted tampered route")
		}
	}
	for i := range entries {
		incomplete := append([]capture.RecordedEntry{}, entries[:i]...)
		incomplete = append(incomplete, entries[i+1:]...)
		if _, err := validateNearReplay(makeManifest(), cp, incomplete); err == nil {
			t.Fatalf("accepted missing entry %d", i)
		}
	}
}

func TestNearTLSOnlySignedCaptureReplay(t *testing.T) {
	for _, fixture := range []string{"neardirect_z-ai_glm-5.3-flash_20260909_202322", "nearcloud_z-ai_glm-5.3-flash_20260909_204035"} {
		t.Run(fixture, func(t *testing.T) {
			dir := "../integration/testdata/near_tls_only/" + fixture
			manifest, _, err := capture.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			cp := &config.Provider{Name: manifest.Provider, BaseURL: manifest.NearConfig.Origin, E2EE: false}
			allowFail := config.ProviderDefaultAllowFail()[manifest.Provider]
			allowFail = append(allowFail, "e2ee_usable")
			cfg := &config.Config{Providers: map[string]*config.Provider{manifest.Provider: cp}, ProviderAllowFail: map[string][]string{manifest.Provider: allowFail}}
			loader := func(string) (*config.Config, *config.Provider, error) { return cfg, cp, nil }
			report, text, err := Replay(t.Context(), dir, loader)
			if err != nil {
				t.Fatal(err)
			}
			if report.Blocked() {
				t.Fatal("signed TLS-only capture failed production policy")
			}
			original, err := capture.LoadReport(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := CompareReports(original, text); err != nil {
				t.Fatal(err)
			}
			for _, factor := range report.Factors {
				if factor.Name == "e2ee_usable" && factor.Status == attestation.Pass {
					t.Fatal("TLS-only replay claimed E2EE success")
				}
			}
			cp.E2EE = true
			if _, _, err := Replay(t.Context(), dir, loader); err == nil {
				t.Fatal("replay accepted a changed E2EE mode")
			}
		})
	}
}

func TestNearCloudTLSOnlyReplayRejectsSubstitutedBoundKey(t *testing.T) {
	dir := "../integration/testdata/near_tls_only/nearcloud_z-ai_glm-5.3-flash_20260909_204035"
	manifest, entries, err := capture.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	replacement := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	field := regexp.MustCompile(`("signing_public_key"\s*:\s*")[^"]*(")`)
	changed := false
	for i := range entries {
		if strings.Contains(entries[i].URL, "cloud-api.near.ai/v1/attestation/report?") {
			entries[i].Body = field.ReplaceAll(entries[i].Body, []byte(`${1}`+replacement+`${2}`))
			changed = true
		}
	}
	if !changed {
		t.Fatal("capture has no gateway evidence")
	}
	altered, err := capture.Save(t.TempDir(), &manifest, "", entries)
	if err != nil {
		t.Fatal(err)
	}
	cp := &config.Provider{Name: "nearcloud", BaseURL: manifest.NearConfig.Origin, E2EE: false}
	policy := config.ProviderDefaultAllowFail()["nearcloud"]
	policy = append(policy, attestation.FactorE2EEUsable, attestation.FactorTEEReportData)
	cfg := &config.Config{Providers: map[string]*config.Provider{"nearcloud": cp}, ProviderAllowFail: map[string][]string{"nearcloud": policy}}
	report, _, err := Replay(t.Context(), altered, func(string) (*config.Config, *config.Provider, error) { return cfg, cp, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !report.Blocked() {
		t.Fatal("recorded TLS-only success authorized a substituted key under a binding allowance")
	}
}

package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testDigest is a fake sha256 digest used in Rekor tests.
const testDigest = "a3c6e2abcd1234567890abcdef1234567890abcdef1234567890abcdef123456"

// realFulcioCertPEM is a real Fulcio certificate from NEAR AI's compose-manager
// image, extracted during the Rekor API investigation.
const realFulcioCertPEM = `-----BEGIN CERTIFICATE-----
MIIGzTCCBlOgAwIBAgIUXUK/kI/LaMPNyVOVG7bocKjK3pUwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjYwMzA0MTQxMzAwWhcNMjYwMzA0MTQyMzAwWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEl0SsWh495ss1zewQ3+Qw8GYb2i5XRl/G4cyH
F8jrRYfW/M9rJ9ns3qrB0NT1kflzuDiolhovYiZtu02azvY6SqOCBXIwggVuMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUzIN2
dTRlgbM4S4eFPEWwsKUZz1wwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wZQYDVR0RAQH/BFswWYZXaHR0cHM6Ly9naXRodWIuY29tL25lYXJhaS9jb21w
b3NlLW1hbmFnZXIvLmdpdGh1Yi93b3JrZmxvd3MvYnVpbGQueW1sQHJlZnMvaGVh
ZHMvbWFzdGVyMDkGCisGAQQBg78wAQEEK2h0dHBzOi8vdG9rZW4uYWN0aW9ucy5n
aXRodWJ1c2VyY29udGVudC5jb20wEgYKKwYBBAGDvzABAgQEcHVzaDA2BgorBgEE
AYO/MAEDBCg0MDZiZGRkOTVhN2ZhNzM4NTgzNzdmMDc4ZDg4MjcyZDdlODg3OGFi
MBwGCisGAQQBg78wAQQEDkJ1aWxkICYgRGVwbG95MCQGCisGAQQBg78wAQUEFm5l
YXJhaS9jb21wb3NlLW1hbmFnZXIwHwYKKwYBBAGDvzABBgQRcmVmcy9oZWFkcy9t
YXN0ZXIwOwYKKwYBBAGDvzABCAQtDCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0
aHVidXNlcmNvbnRlbnQuY29tMGcGCisGAQQBg78wAQkEWQxXaHR0cHM6Ly9naXRo
dWIuY29tL25lYXJhaS9jb21wb3NlLW1hbmFnZXIvLmdpdGh1Yi93b3JrZmxvd3Mv
YnVpbGQueW1sQHJlZnMvaGVhZHMvbWFzdGVyMDgGCisGAQQBg78wAQoEKgwoNDA2
YmRkZDk1YTdmYTczODU4Mzc3ZjA3OGQ4ODI3MmQ3ZTg4NzhhYjAdBgorBgEEAYO/
MAELBA8MDWdpdGh1Yi1ob3N0ZWQwOQYKKwYBBAGDvzABDAQrDClodHRwczovL2dp
dGh1Yi5jb20vbmVhcmFpL2NvbXBvc2UtbWFuYWdlcjA4BgorBgEEAYO/MAENBCoM
KDQwNmJkZGQ5NWE3ZmE3Mzg1ODM3N2YwNzhkODgyNzJkN2U4ODc4YWIwIQYKKwYB
BAGDvzABDgQTDBFyZWZzL2hlYWRzL21hc3RlcjAaBgorBgEEAYO/MAEPBAwMCjEx
NDk2Nzk0OTQwKQYKKwYBBAGDvzABEAQbDBlodHRwczovL2dpdGh1Yi5jb20vbmVh
cmFpMBgGCisGAQQBg78wAREECgwIMjkxMzQyMjEwZwYKKwYBBAGDvzABEgRZDFdo
dHRwczovL2dpdGh1Yi5jb20vbmVhcmFpL2NvbXBvc2UtbWFuYWdlci8uZ2l0aHVi
L3dvcmtmbG93cy9idWlsZC55bWxAcmVmcy9oZWFkcy9tYXN0ZXIwOAYKKwYBBAGD
vzABEwQqDCg0MDZiZGRkOTVhN2ZhNzM4NTgzNzdmMDc4ZDg4MjcyZDdlODg3OGFi
MBQGCisGAQQBg78wARQEBgwEcHVzaDBdBgorBgEEAYO/MAEVBE8MTWh0dHBzOi8v
Z2l0aHViLmNvbS9uZWFyYWkvY29tcG9zZS1tYW5hZ2VyL2FjdGlvbnMvcnVucy8y
MjY3MzA0MDkwMy9hdHRlbXB0cy8xMBYGCisGAQQBg78wARYECAwGcHVibGljMIGL
BgorBgEEAdZ5AgQCBH0EewB5AHcA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4py
gC8p7o4AAAGcuTHlwwAABAMASDBGAiEApPvm1AAFjE/MFuMuouWETwuWQI/ZZthG
fD++U5UAOfsCIQCy4AvGwhwmuIKNEb7ppq8yjFeIxpxODJKdXmM9uPvL1zAKBggq
hkjOPQQDAwNoADBlAjBF9ObfJ6TH8yr1I8jvJhxrIzCLuQqVL0Tunv+bYSS1432b
pgHF0tsPxKcmDOwNk8MCMQDzAXbST0SxYViSGBE8KLk23Vp594hSCfUtOVT1FO1J
ul+EQoIbq0DbN0tUecyWY4g=
-----END CERTIFICATE-----`

// realPublicKeyPEM is a raw public key from a third-party image (e.g. datadog/agent).
const realPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgLMCN19xdaSnmBi/BYD26q6AoWjK
Fdml3gKLajAqc2o72mewgyjHsYHsm3P7gP5jZMP33fzug1xX7obF21k/JQ==
-----END PUBLIC KEY-----`

// buildMockDSSEBody builds a base64-encoded Rekor entry body (DSSE) with the
// given verifier PEM.
func buildMockDSSEBody(verifierPEM string) string {
	verifierB64 := base64.StdEncoding.EncodeToString([]byte(verifierPEM))
	dsse := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "dsse",
		"spec": map[string]any{
			"signatures": []map[string]any{
				{"verifier": verifierB64},
			},
		},
	}
	raw, _ := json.Marshal(dsse)
	return base64.StdEncoding.EncodeToString(raw)
}

// buildMockEntryResponse builds the JSON response for POST /api/v1/log/entries/retrieve.
func buildMockEntryResponse(uuid, dsseBodyB64 string) []byte {
	entry := []map[string]any{
		{uuid: map[string]any{"body": dsseBodyB64}},
	}
	raw, _ := json.Marshal(entry)
	return raw
}

func TestFetchRekorProvenance_FulcioCert(t *testing.T) {
	testUUID := "24296fb24b8ad77a1234567890abcdef"
	dsseBody := buildMockDSSEBody(realFulcioCertPEM)
	entryResp := buildMockEntryResponse(testUUID, dsseBody)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryResp)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())

	prov := rc.FetchRekorProvenance(context.Background(), testDigest)

	t.Logf("Provenance result:")
	t.Logf("  Digest:         %s", prov.Digest)
	t.Logf("  HasCert:        %v", prov.HasCert)
	t.Logf("  KeyFingerprint: %s", prov.KeyFingerprint)
	t.Logf("  SubjectURI:     %s", prov.SubjectURI)
	t.Logf("  OIDCIssuer:     %s", prov.OIDCIssuer)
	t.Logf("  Trigger:        %s", prov.Trigger)
	t.Logf("  SourceCommit:   %s", prov.SourceCommit)
	t.Logf("  SourceRepo:     %s", prov.SourceRepo)
	t.Logf("  SourceRef:      %s", prov.SourceRef)
	t.Logf("  RunnerEnv:      %s", prov.RunnerEnv)
	t.Logf("  SourceRepoURL:  %s", prov.SourceRepoURL)
	t.Logf("  RunURL:         %s", prov.RunURL)
	t.Logf("  Err:            %v", prov.Err)

	if prov.Err != nil {
		t.Fatalf("unexpected error: %v", prov.Err)
	}
	if !prov.HasCert {
		t.Fatal("expected HasCert=true for Fulcio cert")
	}
	if prov.OIDCIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("OIDCIssuer: got %q, want %q", prov.OIDCIssuer, "https://token.actions.githubusercontent.com")
	}
	if prov.Trigger != "push" {
		t.Errorf("Trigger: got %q, want %q", prov.Trigger, "push")
	}
	if prov.SourceCommit != "406bddd95a7fa73858377f078d88272d7e8878ab" {
		t.Errorf("SourceCommit: got %q", prov.SourceCommit)
	}
	if prov.SourceRepo != "nearai/compose-manager" {
		t.Errorf("SourceRepo: got %q, want %q", prov.SourceRepo, "nearai/compose-manager")
	}
	if prov.SourceRef != "refs/heads/master" {
		t.Errorf("SourceRef: got %q, want %q", prov.SourceRef, "refs/heads/master")
	}
	if prov.RunnerEnv != "github-hosted" {
		t.Errorf("RunnerEnv: got %q, want %q", prov.RunnerEnv, "github-hosted")
	}
	if prov.SourceRepoURL != "https://github.com/nearai/compose-manager" {
		t.Errorf("SourceRepoURL: got %q", prov.SourceRepoURL)
	}
	if !strings.Contains(prov.RunURL, "github.com/nearai/compose-manager/actions/runs/") {
		t.Errorf("RunURL: got %q, expected GitHub Actions run URL", prov.RunURL)
	}
}

func TestFetchRekorProvenance_RawPublicKey(t *testing.T) {
	testUUID := "24296fb24b8ad77a0987654321fedcba"
	dsseBody := buildMockDSSEBody(realPublicKeyPEM)
	entryResp := buildMockEntryResponse(testUUID, dsseBody)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryResp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())

	prov := rc.FetchRekorProvenance(context.Background(), testDigest)

	t.Logf("Provenance result: HasCert=%v KeyFingerprint=%s Err=%v", prov.HasCert, prov.KeyFingerprint, prov.Err)

	if prov.Err != nil {
		t.Fatalf("unexpected error: %v", prov.Err)
	}
	if prov.HasCert {
		t.Error("expected HasCert=false for raw public key")
	}
	if prov.OIDCIssuer != "" {
		t.Errorf("OIDCIssuer should be empty, got %q", prov.OIDCIssuer)
	}
}

func TestFetchRekorProvenance_NoEntries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "[]")
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())

	prov := rc.FetchRekorProvenance(context.Background(), testDigest)

	t.Logf("Provenance result: HasCert=%v Err=%v", prov.HasCert, prov.Err)

	if prov.Err == nil {
		t.Fatal("expected error for no entries")
	}
	if !strings.Contains(prov.Err.Error(), "no Rekor entries") {
		t.Errorf("error should mention no entries: %v", prov.Err)
	}
}

func TestParseFulcioProvenance(t *testing.T) {
	prov, err := parseFulcioProvenance([]byte(realFulcioCertPEM))
	if err != nil {
		t.Fatalf("parseFulcioProvenance: %v", err)
	}

	t.Logf("Parsed provenance:")
	t.Logf("  HasCert:       %v", prov.HasCert)
	t.Logf("  OIDCIssuer:    %s", prov.OIDCIssuer)
	t.Logf("  Trigger:       %s", prov.Trigger)
	t.Logf("  SourceCommit:  %s", prov.SourceCommit)
	t.Logf("  SourceRepo:    %s", prov.SourceRepo)
	t.Logf("  SourceRef:     %s", prov.SourceRef)
	t.Logf("  RunnerEnv:     %s", prov.RunnerEnv)
	t.Logf("  SourceRepoURL: %s", prov.SourceRepoURL)
	t.Logf("  RunURL:        %s", prov.RunURL)

	if !prov.HasCert {
		t.Fatal("expected HasCert=true")
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"OIDCIssuer", prov.OIDCIssuer, "https://token.actions.githubusercontent.com"},
		{"Trigger", prov.Trigger, "push"},
		{"SourceCommit", prov.SourceCommit, "406bddd95a7fa73858377f078d88272d7e8878ab"},
		{"SourceRepo", prov.SourceRepo, "nearai/compose-manager"},
		{"SourceRef", prov.SourceRef, "refs/heads/master"},
		{"RunnerEnv", prov.RunnerEnv, "github-hosted"},
		{"SourceRepoURL", prov.SourceRepoURL, "https://github.com/nearai/compose-manager"},
		{"RunURL", prov.RunURL, "https://github.com/nearai/compose-manager/actions/runs/22673040903/attempts/1"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestFetchRekorProvenance_IndexHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s → 500", r.Method, r.URL.Path)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())

	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	if prov.Err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	t.Logf("Error: %v", prov.Err)
	if !strings.Contains(prov.Err.Error(), "search Rekor") {
		t.Errorf("error should mention search: %v", prov.Err)
	}
}

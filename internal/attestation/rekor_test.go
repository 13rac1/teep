package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/transparency-dev/merkle/rfc6962"
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

// signSET signs a rekorEntry with the given key, producing a valid SET.
func signSET(t *testing.T, entry *rekorEntry, key *ecdsa.PrivateKey) string {
	t.Helper()
	type setBundle struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	}
	b := setBundle{
		Body:           entry.Body,
		IntegratedTime: entry.IntegratedTime,
		LogIndex:       entry.LogIndex,
		LogID:          entry.LogID,
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal SET bundle: %v", err)
	}
	canon, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	h := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestVerifySET_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	entry := &rekorEntry{
		Body:           base64.StdEncoding.EncodeToString([]byte("test entry body")),
		IntegratedTime: 1700000000,
		LogIndex:       12345,
		LogID:          "c0d23d6ad406973f9559f3ba2d1ca5f0e0c7f5e8b0c5a2e6d3b1e4f7a8b9c0d1",
		Verification: &rekorVerification{
			SignedEntryTimestamp: "", // filled below
		},
	}
	entry.Verification.SignedEntryTimestamp = signSET(t, entry, key)

	if err := verifySET(entry, &key.PublicKey); err != nil {
		t.Fatalf("verifySET should pass: %v", err)
	}
}

func TestVerifySET_Tampered(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	entry := &rekorEntry{
		Body:           base64.StdEncoding.EncodeToString([]byte("test entry body")),
		IntegratedTime: 1700000000,
		LogIndex:       12345,
		LogID:          "c0d23d6ad406973f9559f3ba2d1ca5f0e0c7f5e8b0c5a2e6d3b1e4f7a8b9c0d1",
		Verification: &rekorVerification{
			SignedEntryTimestamp: "", // filled below
		},
	}
	entry.Verification.SignedEntryTimestamp = signSET(t, entry, key)

	// Tamper with the body after signing.
	entry.Body = base64.StdEncoding.EncodeToString([]byte("TAMPERED body"))

	if err := verifySET(entry, &key.PublicKey); err == nil {
		t.Fatal("verifySET should fail for tampered entry")
	} else {
		t.Logf("Expected error: %v", err)
	}
}

func TestVerifySET_NoVerification(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	entry := &rekorEntry{Body: "dGVzdA=="}
	if err := verifySET(entry, &key.PublicKey); err == nil {
		t.Fatal("verifySET should fail when Verification is nil")
	}
}

func TestVerifyInclusionProof_Valid(t *testing.T) {
	// Build a tiny Merkle tree with 4 leaves and prove leaf 2.
	leaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
	}

	hasher := rfc6962.DefaultHasher
	h := make([][]byte, len(leaves))
	for i, l := range leaves {
		h[i] = hasher.HashLeaf(l)
	}

	// Level 1: pairs
	n01 := hasher.HashChildren(h[0], h[1])
	n23 := hasher.HashChildren(h[2], h[3])
	// Level 2: root
	root := hasher.HashChildren(n01, n23)

	// Inclusion proof for leaf index 2 (tree size 4):
	// sibling = h[3], then n01
	proofHashes := []string{
		hex.EncodeToString(h[3]),
		hex.EncodeToString(n01),
	}

	entry := &rekorEntry{
		Body: base64.StdEncoding.EncodeToString(leaves[2]),
		Verification: &rekorVerification{
			InclusionProof: &rekorInclusionProof{
				LogIndex: 2,
				TreeSize: 4,
				Hashes:   proofHashes,
				RootHash: hex.EncodeToString(root),
			},
		},
	}

	if err := verifyInclusionProof(entry); err != nil {
		t.Fatalf("verifyInclusionProof should pass: %v", err)
	}
}

func TestVerifyInclusionProof_Tampered(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf-0"),
		[]byte("leaf-1"),
		[]byte("leaf-2"),
		[]byte("leaf-3"),
	}

	hasher := rfc6962.DefaultHasher
	h := make([][]byte, len(leaves))
	for i, l := range leaves {
		h[i] = hasher.HashLeaf(l)
	}

	n01 := hasher.HashChildren(h[0], h[1])
	n23 := hasher.HashChildren(h[2], h[3])
	root := hasher.HashChildren(n01, n23)

	proofHashes := []string{
		hex.EncodeToString(h[3]),
		hex.EncodeToString(n01),
	}

	entry := &rekorEntry{
		// Tamper: use leaf-0 body instead of leaf-2.
		Body: base64.StdEncoding.EncodeToString(leaves[0]),
		Verification: &rekorVerification{
			InclusionProof: &rekorInclusionProof{
				LogIndex: 2,
				TreeSize: 4,
				Hashes:   proofHashes,
				RootHash: hex.EncodeToString(root),
			},
		},
	}

	if err := verifyInclusionProof(entry); err == nil {
		t.Fatal("verifyInclusionProof should fail for tampered entry")
	} else {
		t.Logf("Expected error: %v", err)
	}
}

func TestVerifyInclusionProof_NoProof(t *testing.T) {
	entry := &rekorEntry{Body: "dGVzdA=="}
	if err := verifyInclusionProof(entry); err == nil {
		t.Fatal("verifyInclusionProof should fail when no inclusion proof")
	}
}

func TestVerifyInclusionProof_NegativeLogIndex(t *testing.T) {
	entry := &rekorEntry{
		Body: "dGVzdA==",
		Verification: &rekorVerification{
			InclusionProof: &rekorInclusionProof{
				LogIndex: -1,
				TreeSize: 10,
				RootHash: "abcd",
			},
		},
	}
	err := verifyInclusionProof(entry)
	if err == nil {
		t.Fatal("expected error for negative LogIndex")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("error should mention negative: %v", err)
	}
}

func TestVerifyInclusionProof_ZeroTreeSize(t *testing.T) {
	entry := &rekorEntry{
		Body: "dGVzdA==",
		Verification: &rekorVerification{
			InclusionProof: &rekorInclusionProof{
				LogIndex: 0,
				TreeSize: 0,
				RootHash: "abcd",
			},
		},
	}
	err := verifyInclusionProof(entry)
	if err == nil {
		t.Fatal("expected error for zero TreeSize")
	}
	if !strings.Contains(err.Error(), "non-positive") {
		t.Errorf("error should mention non-positive: %v", err)
	}
}

func TestVerifyInclusionProof_LogIndexGETreeSize(t *testing.T) {
	entry := &rekorEntry{
		Body: "dGVzdA==",
		Verification: &rekorVerification{
			InclusionProof: &rekorInclusionProof{
				LogIndex: 10,
				TreeSize: 10,
				RootHash: "abcd",
			},
		},
	}
	err := verifyInclusionProof(entry)
	if err == nil {
		t.Fatal("expected error when LogIndex >= TreeSize")
	}
	if !strings.Contains(err.Error(), ">=") {
		t.Errorf("error should mention >= comparison: %v", err)
	}
}

func TestVerifyInclusionProof_TooManyHashes(t *testing.T) {
	hashes := make([]string, 65)
	for i := range hashes {
		hashes[i] = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	}
	entry := &rekorEntry{
		Body: "dGVzdA==",
		Verification: &rekorVerification{
			InclusionProof: &rekorInclusionProof{
				LogIndex: 0,
				TreeSize: 1,
				Hashes:   hashes,
				RootHash: "abcd",
			},
		},
	}
	err := verifyInclusionProof(entry)
	if err == nil {
		t.Fatal("expected error for too many hashes")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error should mention exceeds maximum: %v", err)
	}
}

func TestParseRekorPublicKey(t *testing.T) {
	rc := NewRekorClient(http.DefaultClient)
	key, err := rc.parseRekorPublicKey()
	if err != nil {
		t.Fatalf("parseRekorPublicKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %v", key.Curve.Params().Name)
	}
}

// TestVerifyRekorEntry_InclusionIndependentOfSET verifies that a Rekor public
// key parse failure only prevents SET verification, not inclusion proof
// verification. The two checks must be independent.
func TestVerifyRekorEntry_InclusionIndependentOfSET(t *testing.T) {
	// Build a valid single-leaf Merkle tree.
	leafData := []byte("leaf-data")
	hasher := rfc6962.DefaultHasher
	leafHash := hasher.HashLeaf(leafData)
	rootHash := hex.EncodeToString(leafHash) // single-leaf: root == leaf hash

	entry := &rekorEntry{
		Body:           base64.StdEncoding.EncodeToString(leafData),
		IntegratedTime: 1700000000,
		LogIndex:       0,
		LogID:          "test-log-id",
		Verification: &rekorVerification{
			SignedEntryTimestamp: base64.StdEncoding.EncodeToString([]byte("invalid-sig")),
			InclusionProof: &rekorInclusionProof{
				LogIndex: 0,
				TreeSize: 1,
				Hashes:   []string{},
				RootHash: rootHash,
			},
		},
	}

	// Use a client with an invalid key to force SET failure.
	rc := NewRekorClientWithKey(defaultRekorBase, "not-a-pem-key", http.DefaultClient)

	prov := &RekorProvenance{}
	rc.verifyRekorEntry(entry, prov)

	// SET should fail due to bad key.
	if prov.SETErr == nil {
		t.Error("expected SETErr when Rekor key is invalid")
	}
	if prov.SETVerified {
		t.Error("expected SETVerified=false when Rekor key is invalid")
	}

	// Inclusion proof should still pass — it doesn't need the Rekor key.
	if prov.InclusionErr != nil {
		t.Errorf("expected InclusionErr=nil, got %v", prov.InclusionErr)
	}
	if !prov.InclusionVerified {
		t.Error("expected InclusionVerified=true even when SET fails")
	}
}

// buildMockEntryResponseWithVerification builds a mock Rekor entry response
// that includes verification fields (SET and inclusion proof).
func buildMockEntryResponseWithVerification(uuid, dsseBodyB64 string) []byte {
	entry := []map[string]any{
		{uuid: map[string]any{
			"body":           dsseBodyB64,
			"integratedTime": 1700000000,
			"logID":          "c0d23d6ad406973f9559f3ba2d1ca5f0e0c7f5e8b0c5a2e6d3b1e4f7a8b9c0d1",
			"logIndex":       42,
			"verification": map[string]any{
				"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("not-a-real-sig")),
				"inclusionProof": map[string]any{
					"checkpoint": "rekor.sigstore.dev - 1234\n42\nROOTHASH\n",
					"hashes":     []string{"abcd1234"},
					"logIndex":   42,
					"rootHash":   "abcd1234",
					"treeSize":   100,
				},
			},
		}},
	}
	raw, _ := json.Marshal(entry)
	return raw
}

func TestFetchRekorProvenance_SETAndInclusionErrors(t *testing.T) {
	// Use an entry with invalid SET/inclusion data — verification should fail
	// gracefully (non-fatal) and populate the error fields.
	testUUID := "24296fb24b8ad77a1234567890abcdef"
	dsseBody := buildMockDSSEBody(realFulcioCertPEM)
	entryResp := buildMockEntryResponseWithVerification(testUUID, dsseBody)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	if prov.Err != nil {
		t.Fatalf("unexpected fatal error: %v", prov.Err)
	}
	// Fulcio cert parsing should still work.
	if !prov.HasCert {
		t.Error("expected HasCert=true")
	}
	// SET should fail — the signature is fake.
	if prov.SETVerified {
		t.Error("expected SETVerified=false for fake signature")
	}
	if prov.SETErr == nil {
		t.Error("expected SETErr to be set for fake signature")
	} else {
		t.Logf("SETErr: %v", prov.SETErr)
	}
	// Inclusion proof should fail — the hashes are fake.
	if prov.InclusionVerified {
		t.Error("expected InclusionVerified=false for fake proof")
	}
	if prov.InclusionErr == nil {
		t.Error("expected InclusionErr to be set for fake proof")
	} else {
		t.Logf("InclusionErr: %v", prov.InclusionErr)
	}
	// IntegratedTime should be populated.
	if prov.IntegratedTime != 1700000000 {
		t.Errorf("IntegratedTime: got %d, want 1700000000", prov.IntegratedTime)
	}
}

// --------------------------------------------------------------------------
// buildPAE
// --------------------------------------------------------------------------

func TestBuildPAE_Format(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	payload := []byte("hello")
	pae := buildPAE(payloadType, payload)
	got := string(pae)
	// DSSEv1 SP len(payloadType) SP payloadType SP len(payload) SP payload
	want := "DSSEv1 28 application/vnd.in-toto+json 5 hello"
	if got != want {
		t.Errorf("buildPAE:\ngot  %q\nwant %q", got, want)
	}
}

// --------------------------------------------------------------------------
// verifyDSSESignature error paths
// --------------------------------------------------------------------------

func TestVerifyDSSESignature_InvalidJSON(t *testing.T) {
	err := verifyDSSESignature([]byte("not json"), nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	t.Logf("expected error: %v", err)
}

func TestVerifyDSSESignature_WrongKind(t *testing.T) {
	body := `{"kind":"hashedrekord","spec":{"content":{"envelope":{"signatures":[]}}}}`
	err := verifyDSSESignature([]byte(body), nil)
	if err == nil {
		t.Fatal("expected error for wrong kind")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("error should mention 'not supported': %v", err)
	}
}

func TestVerifyDSSESignature_NoSignatures(t *testing.T) {
	body := `{"kind":"dsse","spec":{"content":{"envelope":{"signatures":[]}}}}`
	err := verifyDSSESignature([]byte(body), nil)
	if err == nil {
		t.Fatal("expected error for no signatures")
	}
	if !strings.Contains(err.Error(), "no signatures") {
		t.Errorf("error should mention 'no signatures': %v", err)
	}
}

func TestVerifyDSSESignature_BadSigBase64(t *testing.T) {
	body := `{"kind":"dsse","spec":{"content":{"envelope":{"payload":"aGVsbG8=","payloadType":"text/plain","signatures":[{"sig":"not-base64!!!"}]}}}}`
	err := verifyDSSESignature([]byte(body), nil)
	if err == nil {
		t.Fatal("expected error for invalid sig base64")
	}
	t.Logf("expected error: %v", err)
}

func TestVerifyDSSESignature_BadPayloadBase64(t *testing.T) {
	body := `{"kind":"dsse","spec":{"content":{"envelope":{"payload":"not-base64!!!","payloadType":"text/plain","signatures":[{"sig":"aGVsbG8="}]}}}}`
	err := verifyDSSESignature([]byte(body), nil)
	if err == nil {
		t.Fatal("expected error for invalid payload base64")
	}
	t.Logf("expected error: %v", err)
}

func TestVerifyDSSESignature_NoPEMBlock(t *testing.T) {
	body := `{"kind":"dsse","spec":{"content":{"envelope":{"payload":"aGVsbG8=","payloadType":"text/plain","signatures":[{"sig":"aGVsbG8="}]}}}}`
	err := verifyDSSESignature([]byte(body), []byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error for no PEM block")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error should mention 'no PEM block': %v", err)
	}
}

func TestVerifyDSSESignature_InvalidCertInPEM(t *testing.T) {
	// PEM block present but contains garbage — x509 parse will fail.
	certPEM := "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n"
	body := `{"kind":"dsse","spec":{"content":{"envelope":{"payload":"aGVsbG8=","payloadType":"text/plain","signatures":[{"sig":"aGVsbG8="}]}}}}`
	err := verifyDSSESignature([]byte(body), []byte(certPEM))
	if err == nil {
		t.Fatal("expected error for invalid certificate")
	}
	t.Logf("expected error: %v", err)
}

func TestVerifyDSSESignature_WrongSignature(t *testing.T) {
	// Generate a real self-signed ECDSA cert and provide a wrong signature.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certDER, err := selfSignedCert(key)
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	certPEM := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		base64.StdEncoding.EncodeToString(certDER))
	// Use a valid base64 signature that is wrong (all zeros).
	wrongSig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	body := fmt.Sprintf(`{"kind":"dsse","spec":{"content":{"envelope":{"payload":"aGVsbG8=","payloadType":"text/plain","signatures":[{"sig":%q}]}}}}`,
		wrongSig)
	err = verifyDSSESignature([]byte(body), []byte(certPEM))
	if err == nil {
		t.Fatal("expected ECDSA verification failure")
	}
	t.Logf("expected error: %v", err)
}

// selfSignedCert creates a minimal self-signed DER-encoded certificate for testing.
func selfSignedCert(key *ecdsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// --------------------------------------------------------------------------
// extractVerifierPEM error paths
// --------------------------------------------------------------------------

func TestExtractVerifierPEM_InvalidJSON(t *testing.T) {
	_, err := extractVerifierPEM([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	t.Logf("expected error: %v", err)
}

func TestExtractVerifierPEM_NoSignatures(t *testing.T) {
	_, err := extractVerifierPEM([]byte(`{"spec":{"signatures":[]}}`))
	if err == nil {
		t.Fatal("expected error for no signatures")
	}
	if !strings.Contains(err.Error(), "no signatures") {
		t.Errorf("error should mention 'no signatures': %v", err)
	}
}

func TestExtractVerifierPEM_EmptyVerifier(t *testing.T) {
	body := `{"spec":{"signatures":[{"verifier":""}]}}`
	_, err := extractVerifierPEM([]byte(body))
	if err == nil {
		t.Fatal("expected error for empty verifier")
	}
	if !strings.Contains(err.Error(), "empty verifier") {
		t.Errorf("error should mention 'empty verifier': %v", err)
	}
}

// --------------------------------------------------------------------------
// FetchRekorProvenance: entry fetch error path
// --------------------------------------------------------------------------

func TestFetchRekorProvenance_EntryFetchError(t *testing.T) {
	// UUID lookup returns a UUID, but the entry fetch returns HTTP 500.
	testUUID := "24296fb24b8ad77afailentry123456"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			http.Error(w, "server error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	if prov.Err == nil {
		t.Fatal("expected error when entry fetch fails")
	}
	t.Logf("expected error: %v", prov.Err)
}

// TestFetchRekorProvenance_UnexpectedPEMType tests the unexpected PEM type branch.
func TestFetchRekorProvenance_UnexpectedPEMType(t *testing.T) {
	// Build an entry body with a PEM block of type "PRIVATE KEY" — neither
	// "PUBLIC KEY" nor "CERTIFICATE", so the unexpected type branch fires.
	unexpectedPEM := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7
-----END PRIVATE KEY-----`
	dsseBody := buildMockDSSEBody(unexpectedPEM)
	entryResp := buildMockEntryResponse("test-unexpected-pem-uuid", dsseBody)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{"test-unexpected-pem-uuid"})
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
	t.Logf("FetchRekorProvenance with unexpected PEM type: Err=%v", prov.Err)
	// The function should return some error (no usable entry found).
	if prov.Err == nil {
		t.Error("expected non-nil error for unexpected PEM type")
	}
}

// ---------------------------------------------------------------------------
// decodeExtensionValue
// ---------------------------------------------------------------------------

func TestDecodeExtensionValue_RawUTF8Fallback(t *testing.T) {
	// Pass raw UTF-8 bytes (not ASN.1-encoded). The fallback branch is taken.
	raw := []byte("hello world")
	got := decodeExtensionValue(raw)
	if got != "hello world" {
		t.Errorf("decodeExtensionValue UTF-8 fallback = %q, want \"hello world\"", got)
	}
}

func TestDecodeExtensionValue_InvalidUTF8(t *testing.T) {
	// Invalid UTF-8 and not ASN.1 → returns empty string.
	raw := []byte{0xff, 0xfe, 0x00}
	got := decodeExtensionValue(raw)
	if got != "" {
		t.Errorf("decodeExtensionValue invalid UTF-8 = %q, want \"\"", got)
	}
}

// --------------------------------------------------------------------------
// FetchRekorProvenance: additional error paths in the entry loop
// --------------------------------------------------------------------------

// TestFetchRekorProvenance_BadBodyBase64 covers the base64-decode-body error
// path (lines 173-176 in rekor.go). The entry is returned but its Body is
// not valid base64, so the loop continues and no usable entry is found.
func TestFetchRekorProvenance_BadBodyBase64(t *testing.T) {
	testUUID := "bad-body-uuid"
	// Build an entry response where the body is not valid base64.
	entry := []map[string]any{
		{testUUID: map[string]any{"body": "not!valid!base64!!!"}},
	}
	entryRaw, _ := json.Marshal(entry)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock: %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	t.Logf("bad body base64: Err=%v", prov.Err)
	if prov.Err == nil {
		t.Error("expected non-nil error for bad body base64")
	}
}

// TestFetchRekorProvenance_ExtractVerifierPEMError covers the extractVerifierPEM
// error path (lines 179-182). The body is valid base64, but its JSON has no
// signatures, causing extractVerifierPEM to return an error.
func TestFetchRekorProvenance_ExtractVerifierPEMError(t *testing.T) {
	testUUID := "no-sig-uuid"
	// Body is valid base64 of JSON with no signatures field.
	innerJSON := `{"spec":{"signatures":[]}}`
	bodyB64 := base64.StdEncoding.EncodeToString([]byte(innerJSON))
	entry := []map[string]any{
		{testUUID: map[string]any{"body": bodyB64}},
	}
	entryRaw, _ := json.Marshal(entry)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	t.Logf("extract verifier error: Err=%v", prov.Err)
	if prov.Err == nil {
		t.Error("expected non-nil error for empty signatures")
	}
}

// TestFetchRekorProvenance_NilPEMBlock covers the nil-PEM-block path
// (lines 185-188). verifierPEM decodes successfully but pem.Decode returns nil.
func TestFetchRekorProvenance_NilPEMBlock(t *testing.T) {
	testUUID := "nil-pem-uuid"
	// Build a DSSE body where the verifier is valid base64 but decodes to
	// bytes that are not a PEM block (plain text).
	notAPEM := "this is not a PEM block"
	verifierB64 := base64.StdEncoding.EncodeToString([]byte(notAPEM))
	dsse := map[string]any{
		"spec": map[string]any{
			"signatures": []map[string]any{
				{"verifier": verifierB64},
			},
		},
	}
	dsseJSON, _ := json.Marshal(dsse)
	bodyB64 := base64.StdEncoding.EncodeToString(dsseJSON)
	entry := []map[string]any{
		{testUUID: map[string]any{"body": bodyB64}},
	}
	entryRaw, _ := json.Marshal(entry)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	t.Logf("nil PEM block: Err=%v", prov.Err)
	if prov.Err == nil {
		t.Error("expected non-nil error when PEM block is nil")
	}
}

// TestFetchRekorProvenance_ParseFulcioProvenanceError covers the
// parseFulcioProvenance error path (lines 212-215). The verifierPEM is a
// CERTIFICATE block but contains invalid DER bytes.
func TestFetchRekorProvenance_ParseFulcioProvenanceError(t *testing.T) {
	testUUID := "invalid-cert-uuid"
	// Build a PEM block with type CERTIFICATE but invalid DER content.
	invalidCertPEM := "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n"
	verifierB64 := base64.StdEncoding.EncodeToString([]byte(invalidCertPEM))
	dsse := map[string]any{
		"spec": map[string]any{
			"signatures": []map[string]any{
				{"verifier": verifierB64},
			},
		},
	}
	dsseJSON, _ := json.Marshal(dsse)
	bodyB64 := base64.StdEncoding.EncodeToString(dsseJSON)
	entry := []map[string]any{
		{testUUID: map[string]any{"body": bodyB64}},
	}
	entryRaw, _ := json.Marshal(entry)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	t.Logf("invalid cert DER: Err=%v", prov.Err)
	if prov.Err == nil {
		t.Error("expected non-nil error for invalid certificate DER")
	}
}

// TestFetchRekorProvenance_NonFulcioCert covers the OIDCIssuer=="" path
// (lines 224-235). A valid CERTIFICATE is present but it has no Fulcio OIDC
// extensions, so it's treated as a raw-key fallback. With no other entries,
// the fallback is returned (no fatal error).
func TestFetchRekorProvenance_NonFulcioCert(t *testing.T) {
	testUUID := "non-fulcio-cert-uuid"
	// Use selfSignedCert (defined in the test file) to build a valid cert
	// with no Fulcio extensions.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certDER, err := selfSignedCert(key)
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	certPEM := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
		base64.StdEncoding.EncodeToString(certDER))

	verifierB64 := base64.StdEncoding.EncodeToString([]byte(certPEM))
	dsse := map[string]any{
		"spec": map[string]any{
			"signatures": []map[string]any{
				{"verifier": verifierB64},
			},
		},
	}
	dsseJSON, _ := json.Marshal(dsse)
	bodyB64 := base64.StdEncoding.EncodeToString(dsseJSON)
	entry := []map[string]any{
		{testUUID: map[string]any{"body": bodyB64}},
	}
	entryRaw, _ := json.Marshal(entry)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			w.Header().Set("Content-Type", "application/json")
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Header().Set("Content-Type", "application/json")
			w.Write(entryRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	prov := rc.FetchRekorProvenance(context.Background(), testDigest)
	t.Logf("non-Fulcio cert: HasCert=%v HasNonFulcioCert=%v OIDCIssuer=%q Err=%v",
		prov.HasCert, prov.HasNonFulcioCert, prov.OIDCIssuer, prov.Err)
	// No error — the fallback is returned.
	if prov.Err != nil {
		t.Errorf("unexpected fatal error: %v", prov.Err)
	}
	// HasNonFulcioCert should be true since it's a cert but not Fulcio.
	if !prov.HasNonFulcioCert {
		t.Error("expected HasNonFulcioCert=true for self-signed cert without Fulcio extensions")
	}
	if prov.HasCert {
		t.Error("expected HasCert=false for non-Fulcio cert returned as fallback")
	}
}

// TestExtractVerifierPEM_DirectPEM covers the direct-PEM fallback path
// (lines 418-420). When the verifier is a raw PEM string (not base64-encoded),
// base64 decode fails but pem.Decode succeeds, so the PEM is returned as-is.
func TestExtractVerifierPEM_DirectPEM(t *testing.T) {
	// Pass a PEM directly as the verifier value (not base64-encoded).
	// base64.StdEncoding.DecodeString("-----BEGIN PUBLIC KEY...") will fail
	// because PEM has non-base64 chars like '-', so the fallback is taken.
	dsse := fmt.Sprintf(`{"spec":{"signatures":[{"verifier":%q}]}}`, realPublicKeyPEM)
	result, err := extractVerifierPEM([]byte(dsse))
	t.Logf("extractVerifierPEM(direct PEM): len=%d err=%v", len(result), err)
	if err != nil {
		t.Fatalf("extractVerifierPEM: unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty PEM result")
	}
	if !strings.Contains(string(result), "PUBLIC KEY") {
		t.Errorf("result should contain PUBLIC KEY, got: %q", string(result))
	}
}

func TestFetchRekorProvenances_PreservesOrderAndErrors(t *testing.T) {
	const (
		digestSlow  = "1111111111111111111111111111111111111111111111111111111111111111"
		digestError = "2222222222222222222222222222222222222222222222222222222222222222"
		digestRaw   = "3333333333333333333333333333333333333333333333333333333333333333"
		uuidSlow    = "uuid-slow"
		uuidRaw     = "uuid-raw"
	)

	slowEntry := buildMockEntryResponse(uuidSlow, buildMockDSSEBody(realFulcioCertPEM))
	rawEntry := buildMockEntryResponse(uuidRaw, buildMockDSSEBody(realPublicKeyPEM))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode index payload: %v", err)
			}
			hash := payload["hash"]
			w.Header().Set("Content-Type", "application/json")
			switch hash {
			case "sha256:" + digestSlow:
				time.Sleep(40 * time.Millisecond)
				_ = json.NewEncoder(w).Encode([]string{uuidSlow})
			case "sha256:" + digestError:
				fmt.Fprint(w, "[]")
			case "sha256:" + digestRaw:
				time.Sleep(5 * time.Millisecond)
				_ = json.NewEncoder(w).Encode([]string{uuidRaw})
			default:
				t.Fatalf("unexpected digest lookup: %q", hash)
			}
		case "/api/v1/log/entries/retrieve":
			var payload struct {
				EntryUUIDs []string `json:"entryUUIDs"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode entries payload: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			switch payload.EntryUUIDs[0] {
			case uuidSlow:
				w.Write(slowEntry)
			case uuidRaw:
				w.Write(rawEntry)
			default:
				t.Fatalf("unexpected uuid lookup: %q", payload.EntryUUIDs[0])
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	rc := NewRekorClientWithBase(ts.URL, ts.Client())
	results := rc.FetchRekorProvenances(context.Background(), []string{digestSlow, digestError, digestRaw})

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	if results[0].Digest != digestSlow {
		t.Fatalf("results[0].Digest = %q, want %q", results[0].Digest, digestSlow)
	}
	if results[1].Digest != digestError {
		t.Fatalf("results[1].Digest = %q, want %q", results[1].Digest, digestError)
	}
	if results[2].Digest != digestRaw {
		t.Fatalf("results[2].Digest = %q, want %q", results[2].Digest, digestRaw)
	}

	if results[0].Err != nil {
		t.Fatalf("results[0].Err = %v, want nil", results[0].Err)
	}
	if !results[0].HasCert {
		t.Fatal("results[0].HasCert = false, want true for Fulcio provenance")
	}
	if results[1].Err == nil {
		t.Fatal("results[1].Err = nil, want no-entries error")
	}
	if !strings.Contains(results[1].Err.Error(), "no Rekor entries") {
		t.Fatalf("results[1].Err = %v, want no Rekor entries error", results[1].Err)
	}
	if results[2].Err != nil {
		t.Fatalf("results[2].Err = %v, want nil", results[2].Err)
	}
	if results[2].HasCert {
		t.Fatal("results[2].HasCert = true, want false for raw public key provenance")
	}
}

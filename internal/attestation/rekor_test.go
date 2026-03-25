package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestParseRekorPublicKey(t *testing.T) {
	key, err := parseRekorPublicKey()
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

	// Temporarily override with an invalid key to force SET failure.
	orig := rekorPublicKeyOverride
	rekorPublicKeyOverride = "not-a-pem-key"
	defer func() { rekorPublicKeyOverride = orig }()

	prov := &RekorProvenance{}
	verifyRekorEntry(entry, prov)

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

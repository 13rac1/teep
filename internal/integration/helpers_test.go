package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/go-tdx-guest/pcs"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/13rac1/teep/internal/attestation"
)

// ---------------------------------------------------------------------------
// Fixture I/O
// ---------------------------------------------------------------------------

func readFixtureFrom(t *testing.T, dir, name string) []byte {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

func readHeadersFixture(t *testing.T, dir, name string) map[string][]string {
	t.Helper()
	data := readFixtureFrom(t, dir, name)
	var headers map[string][]string
	if err := json.Unmarshal(data, &headers); err != nil {
		t.Fatalf("parse headers fixture %s: %v", name, err)
	}
	return headers
}

// ---------------------------------------------------------------------------
// PCS getter
// ---------------------------------------------------------------------------

// buildPCSGetter builds a fixture-backed trust.HTTPSGetter for Intel PCS collateral.
// prefix is the fixture filename prefix ("neardirect" or "venice").
func buildPCSGetter(t *testing.T, fdir, prefix string, raw *attestation.RawAttestation) trust.HTTPSGetter {
	t.Helper()

	// Parse TDX quote offline to get FMSPC.
	tdxResult := attestation.VerifyTDXQuote(context.Background(), raw.IntelQuote, attestation.Nonce{}, true)
	if tdxResult.ParseErr != nil {
		t.Fatalf("parse TDX quote for FMSPC extraction: %v", tdxResult.ParseErr)
	}
	fmspc := tdxResult.FMSPC
	if fmspc == "" {
		t.Fatal("FMSPC not extracted from TDX quote")
	}
	t.Logf("PCS getter: FMSPC=%s", fmspc)

	tcbInfoBody := readFixtureFrom(t, fdir, prefix+"_pcs_tcbinfo.json")
	tcbInfoHeaders := readHeadersFixture(t, fdir, prefix+"_pcs_tcbinfo_headers.json")

	qeIdentityBody := readFixtureFrom(t, fdir, prefix+"_pcs_qeidentity.json")
	qeIdentityHeaders := readHeadersFixture(t, fdir, prefix+"_pcs_qeidentity_headers.json")

	pckCrlBody := readFixtureFrom(t, fdir, prefix+"_pcs_pckcrl.der")
	pckCrlHeaders := readHeadersFixture(t, fdir, prefix+"_pcs_pckcrl_headers.json")

	rootCrlBody := readFixtureFrom(t, fdir, prefix+"_pcs_rootcrl.der")

	return &tdxtesting.Getter{
		Responses: map[string]tdxtesting.HTTPResponse{
			pcs.TcbInfoURL(fmspc): {
				Header: tcbInfoHeaders,
				Body:   tcbInfoBody,
			},
			pcs.QeIdentityURL(): {
				Header: qeIdentityHeaders,
				Body:   qeIdentityBody,
			},
			pcs.PckCrlURL("platform"): {
				Header: pckCrlHeaders,
				Body:   pckCrlBody,
			},
			"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der": {
				Header: nil,
				Body:   rootCrlBody,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// PoC mock peers
// ---------------------------------------------------------------------------

// pocFixtureIs403 returns true if the stage1 fixture is a 403 error response
// (machine not whitelisted at capture time).
func pocFixtureIs403(data []byte) bool {
	var obj struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(data, &obj) == nil && obj.Error != ""
}

// buildPoCMockPeers creates httptest servers from PoC fixture files.
// prefix is "neardirect" or "venice".
func buildPoCMockPeers(t *testing.T, fdir, prefix string) []string {
	t.Helper()

	type peerFixtures struct {
		stage1    []byte
		stage2    []byte
		forbidden bool
	}

	peers := make([]peerFixtures, 3)
	for i := range 3 {
		s1 := readFixtureFrom(t, fdir, fmt.Sprintf("%s_poc_stage1_%d.json", prefix, i))
		peers[i] = peerFixtures{
			stage1:    s1,
			stage2:    readFixtureFrom(t, fdir, fmt.Sprintf("%s_poc_stage2_%d.json", prefix, i)),
			forbidden: pocFixtureIs403(s1),
		}
	}

	urls := make([]string, 0, len(peers))
	for i, p := range peers {
		callCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			t.Logf("PoC mock peer %d: call %d %s %s", i, callCount, r.Method, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			if p.forbidden {
				w.WriteHeader(http.StatusForbidden)
				w.Write(p.stage1)
				return
			}
			if callCount == 1 {
				w.Write(p.stage1)
			} else {
				w.Write(p.stage2)
			}
		}))
		t.Cleanup(srv.Close)
		urls = append(urls, srv.URL)
	}

	return urls
}

// ---------------------------------------------------------------------------
// Report factor helpers
// ---------------------------------------------------------------------------

func findFactor(t *testing.T, report *attestation.VerificationReport, name string) attestation.FactorResult {
	t.Helper()
	for _, f := range report.Factors {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("factor %q not found in report (factors: %v)", name, factorNames(report))
	return attestation.FactorResult{}
}

func factorNames(r *attestation.VerificationReport) []string {
	names := make([]string, len(r.Factors))
	for i, f := range r.Factors {
		names[i] = f.Name
	}
	return names
}

// ---------------------------------------------------------------------------
// Rekor mock helpers
// ---------------------------------------------------------------------------

// datadogAgentKeyPEM is the raw ECDSA P-256 public key used to cosign the
// datadog/agent container image. Its SHA-256 fingerprint matches the
// supply-chain policy (25bcab4ec8eede1e...).
const datadogAgentKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgLMCN19xdaSnmBi/BYD26q6AoWjK
Fdml3gKLajAqc2o72mewgyjHsYHsm3P7gP5jZMP33fzug1xX7obF21k/JQ==
-----END PUBLIC KEY-----`

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

// buildMockEntryResponse builds a full JSON response for POST /api/v1/log/entries/retrieve,
// including a valid SET signature and a trivial Merkle inclusion proof so that
// SET and inclusion verification pass in tests.
func buildMockEntryResponse(t *testing.T, privKey *ecdsa.PrivateKey, uuid, dsseBodyB64 string) []byte {
	t.Helper()

	const (
		mockIntegratedTime int64 = 1711324800 // 2024-03-25T00:00:00Z
		mockLogIndex       int64 = 0
		mockLogID                = "mock-log-id"
	)

	// Sign the SET bundle: {body, integratedTime, logIndex, logID}.
	type setBundle struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	}
	bundle := setBundle{
		Body:           dsseBodyB64,
		IntegratedTime: mockIntegratedTime,
		LogIndex:       mockLogIndex,
		LogID:          mockLogID,
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal SET bundle: %v", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(bundleJSON)
	if err != nil {
		t.Fatalf("canonicalize SET bundle: %v", err)
	}
	h := sha256.Sum256(canonicalized)
	setSig, err := ecdsa.SignASN1(rand.Reader, privKey, h[:])
	if err != nil {
		t.Fatalf("sign SET: %v", err)
	}
	setB64 := base64.StdEncoding.EncodeToString(setSig)

	// Build a trivial Merkle tree (size=1): leaf hash = root hash, empty proof.
	entryBytes, _ := base64.StdEncoding.DecodeString(dsseBodyB64)
	leafHash := rfc6962.DefaultHasher.HashLeaf(entryBytes)
	rootHash := hex.EncodeToString(leafHash)

	entry := []map[string]any{
		{uuid: map[string]any{
			"body":           dsseBodyB64,
			"integratedTime": mockIntegratedTime,
			"logIndex":       mockLogIndex,
			"logID":          mockLogID,
			"verification": map[string]any{
				"signedEntryTimestamp": setB64,
				"inclusionProof": map[string]any{
					"checkpoint": "mock-checkpoint",
					"hashes":     []string{},
					"logIndex":   mockLogIndex,
					"rootHash":   rootHash,
					"treeSize":   1,
				},
			},
		}},
	}
	raw, _ := json.Marshal(entry)
	return raw
}

// ---------------------------------------------------------------------------
// Mock setup (shared between NEAR AI and Venice tests)
// ---------------------------------------------------------------------------

// setupMocks sets up all external service mocks (NRAS, JWKS, Sigstore, Rekor)
// and returns PoC peer URLs + HTTP client. The caller must set up TDX getter
// and call t.Cleanup for the returned overrides.
func setupMocks(t *testing.T, fdir, prefix string, raw *attestation.RawAttestation) (pocPeers []string, client *http.Client, rekorClient *attestation.RekorClient) {
	t.Helper()

	// TDX collateral getter
	pcsGetter := buildPCSGetter(t, fdir, prefix, raw)
	origTDX := attestation.TDXCollateralGetter
	attestation.TDXCollateralGetter = pcsGetter
	t.Cleanup(func() { attestation.TDXCollateralGetter = origTDX })

	// NVIDIA NRAS
	nrasBody := readFixtureFrom(t, fdir, prefix+"_nras_response.json")
	nrasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("NRAS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write(nrasBody)
	}))
	t.Cleanup(nrasSrv.Close)
	origNRAS := attestation.NRASAttestURL
	attestation.NRASAttestURL = nrasSrv.URL
	t.Cleanup(func() { attestation.NRASAttestURL = origNRAS })

	// NVIDIA JWKS
	jwksBody := readFixtureFrom(t, fdir, prefix+"_nras_jwks.json")
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("JWKS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	}))
	t.Cleanup(jwksSrv.Close)
	origJWKS := attestation.NvidiaJWKSURL
	attestation.NvidiaJWKSURL = jwksSrv.URL
	t.Cleanup(func() { attestation.NvidiaJWKSURL = origJWKS })

	// Rekor — per-digest mock with valid SET signatures and inclusion proofs.
	//
	// Generate a test ECDSA key pair for signing mock Signed Entry Timestamps.
	// Override the production Rekor public key so SET verification passes.
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test Rekor key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal test Rekor public key: %v", err)
	}
	testPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	attestation.SetRekorPublicKeyOverride(string(testPubPEM))
	t.Cleanup(func() { attestation.SetRekorPublicKeyOverride("") })

	// Build a digest→repo map from the docker-compose manifest so we can
	// route each index query to the right mock entry.
	composeSource := raw.AppCompose
	if dc, err := attestation.ExtractDockerCompose(raw.AppCompose); err == nil && dc != "" {
		composeSource = dc
	}
	digestToRepo := attestation.ExtractImageDigestToRepoMap(composeSource)

	// Pre-build per-image entries with SET signatures.
	const fulcioUUID = "24296fb24b8ad77a1234567890abcdef"
	const datadogUUID = "24296fb24b8ad77adddddddddddddddd"
	fulcioDSSE := buildMockDSSEBody(realFulcioCertPEM)
	datadogDSSE := buildMockDSSEBody(datadogAgentKeyPEM)
	fulcioEntry := buildMockEntryResponse(t, testKey, fulcioUUID, fulcioDSSE)
	datadogEntry := buildMockEntryResponse(t, testKey, datadogUUID, datadogDSSE)

	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))

		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			// Parse {\"hash\":\"sha256:<digest>\"} to route by image.
			var req struct {
				Hash string `json:"hash"`
			}
			_ = json.Unmarshal(body, &req)
			digest := strings.TrimPrefix(req.Hash, "sha256:")
			repo := digestToRepo[digest]
			uuid := fulcioUUID
			if repo == "datadog/agent" {
				uuid = datadogUUID
			}
			resp, _ := json.Marshal([]string{uuid})
			w.Write(resp)

		case "/api/v1/log/entries/retrieve":
			// Parse {\"entryUUIDs\":[\"<uuid>\"]} to return the right entry.
			var req struct {
				EntryUUIDs []string `json:"entryUUIDs"`
			}
			_ = json.Unmarshal(body, &req)
			resp := fulcioEntry
			if len(req.EntryUUIDs) > 0 && req.EntryUUIDs[0] == datadogUUID {
				resp = datadogEntry
			}
			w.Write(resp)

		default:
			t.Errorf("unexpected Rekor request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rekorSrv.Close)
	rekorClient = attestation.NewRekorClientWithBase(rekorSrv.URL, &http.Client{})

	// PoC
	pocPeers = buildPoCMockPeers(t, fdir, prefix)
	client = &http.Client{}

	return pocPeers, client, rekorClient
}

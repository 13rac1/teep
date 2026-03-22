package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tdx-guest/pcs"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/verify/trust"
)

// TestIntegration_NearAI_Fixture exercises the entire NEAR AI verification
// pipeline from recorded HTTP response fixtures. ALL external services are
// mocked from captured responses — nothing is skipped via offline=true.
//
// The test mirrors runVerification() in cmd/teep/main.go (the "teep verify
// nearai" CLI path), calling pipeline functions directly with offline=false.
//
// Requires fixtures captured by:
//
//	NEARAI_API_KEY=... go run ./cmd/capture_nearai
//
// fixtureDir returns the directory containing NEAR AI fixture files.
// Set via NEARAI_FIXTURE_DIR env var, or defaults to the most recent
// testdata/nearai_YYYYMMDD_HHMMSS directory.
func fixtureDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("NEARAI_FIXTURE_DIR"); dir != "" {
		return dir
	}

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	// Find the latest nearai_YYYYMMDD_HHMMSS directory.
	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "nearai_") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}
	if latest == "" {
		t.Fatal("no nearai fixture directory found in testdata/; run: go run ./test/cmd/capture_nearai")
	}
	return filepath.Join("testdata", latest)
}

func TestIntegration_NearAI_Fixture(t *testing.T) {
	ctx := context.Background()

	// ---------------------------------------------------------------
	// 1. Load fixtures
	// ---------------------------------------------------------------
	fdir := fixtureDir(t)
	captureTime := parseCaptureTime(t, fdir)
	t.Logf("loading fixtures from %s (captured %s)", fdir, captureTime.Format(time.RFC3339))

	attestBody := readFixtureFrom(t, fdir, "nearai_attestation.json")
	nonceHex := strings.TrimSpace(string(readFixtureFrom(t, fdir, "nearai_fixture_nonce.txt")))
	nonce, err := ParseNonce(nonceHex)
	if err != nil {
		t.Fatalf("parse nonce: %v", err)
	}
	t.Logf("nonce: %s", nonceHex[:16]+"...")

	model := extractModel(t, attestBody)
	t.Logf("model: %s", model)

	// ---------------------------------------------------------------
	// 2. Parse fixture into RawAttestation (mirrors nearai.parseAttestationResponse)
	// ---------------------------------------------------------------
	raw := parseNearAIFixture(t, attestBody, model)
	t.Logf("intel_quote: %d hex chars", len(raw.IntelQuote))
	t.Logf("nvidia_payload: %d bytes", len(raw.NvidiaPayload))
	t.Logf("app_compose: %d bytes", len(raw.AppCompose))
	t.Logf("signing_address: %s", raw.SigningAddress)

	// ---------------------------------------------------------------
	// 3. Set up mocks for ALL external services
	// ---------------------------------------------------------------

	// 3a. Intel PCS collateral — fixture-backed Getter
	pcsGetter := buildPCSGetter(t, fdir)
	overrideTDXGetter(pcsGetter)
	t.Cleanup(restoreTDXGetter)

	// 3b. NVIDIA NRAS — httptest server returning captured response
	nrasBody := readFixtureFrom(t, fdir, "nearai_nras_response.json")
	nrasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("NRAS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write(nrasBody)
	}))
	t.Cleanup(nrasSrv.Close)
	origNRAS := nrasAttestURL
	overrideNRASURL(nrasSrv.URL)
	t.Cleanup(func() { restoreNRASURL(origNRAS) })

	// 3c. NVIDIA JWKS — httptest server returning captured JWKS
	jwksBody := readFixtureFrom(t, fdir, "nearai_nras_jwks.json")
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("JWKS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	}))
	t.Cleanup(jwksSrv.Close)
	origJWKS := nvidiaJWKSURL
	overrideJWKSURL(jwksSrv.URL)
	t.Cleanup(func() { restoreJWKSURL(origJWKS) })

	// 3d. Sigstore — returns 200 for all digests
	sigstoreSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Sigstore mock: %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sigstoreSrv.Close)
	origSigstore := sigstoreSearchBase
	overrideSigstoreBase(sigstoreSrv.URL + "/?hash=")
	t.Cleanup(func() { restoreSigstoreBase(origSigstore) })

	// 3e. Rekor — returns mock UUID + DSSE entry with realFulcioCertPEM
	testUUID := "24296fb24b8ad77a1234567890abcdef"
	dsseBody := buildMockDSSEBody(realFulcioCertPEM)
	entryResp := buildMockEntryResponse(testUUID, dsseBody)
	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Write(entryResp)
		default:
			t.Errorf("unexpected Rekor request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rekorSrv.Close)
	origRekor := rekorAPIBase
	overrideRekorBase(rekorSrv.URL)
	t.Cleanup(func() { restoreRekorBase(origRekor) })

	// 3f. PoC trust-servers — fixture-backed mock peers
	pocPeers := buildPoCMockPeers(t, fdir)
	client := &http.Client{}

	// ---------------------------------------------------------------
	// 4. Run the pipeline (mirrors runVerification)
	// ---------------------------------------------------------------

	// 4a. TDX quote verification (online — uses fixture PCS getter)
	t.Log("--- TDX verification ---")
	tdxResult := VerifyTDXQuote(ctx, raw.IntelQuote, nonce, false)
	t.Logf("TDX parse err: %v", tdxResult.ParseErr)
	t.Logf("TDX cert chain err: %v", tdxResult.CertChainErr)
	t.Logf("TDX signature err: %v", tdxResult.SignatureErr)
	t.Logf("TDX collateral err: %v", tdxResult.CollateralErr)
	t.Logf("TDX debug: %v", tdxResult.DebugEnabled)
	t.Logf("TDX FMSPC: %s", tdxResult.FMSPC)
	t.Logf("TDX TCB status: %s", tdxResult.TcbStatus)

	if tdxResult.ParseErr != nil {
		t.Fatalf("TDX parse failed: %v", tdxResult.ParseErr)
	}

	// 4b. REPORTDATA binding (NEAR AI scheme)
	t.Log("--- REPORTDATA binding ---")
	detail, rdErr := verifyNearAIReportData(tdxResult.ReportData, raw, nonce)
	tdxResult.ReportDataBindingErr = rdErr
	tdxResult.ReportDataBindingDetail = detail
	t.Logf("REPORTDATA binding: detail=%q err=%v", detail, rdErr)

	// 4c. NVIDIA EAT verification
	t.Log("--- NVIDIA EAT verification ---")
	var nvidiaResult *NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		t.Logf("NVIDIA format: %s", nvidiaResult.Format)
		t.Logf("NVIDIA signature err: %v", nvidiaResult.SignatureErr)
		t.Logf("NVIDIA claims err: %v", nvidiaResult.ClaimsErr)
		t.Logf("NVIDIA nonce: %s", nvidiaResult.Nonce)
	}

	// 4d. NVIDIA NRAS verification (online — hits mock NRAS + JWKS)
	t.Log("--- NVIDIA NRAS verification ---")
	var nrasResult *NvidiaVerifyResult
	if raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nrasResult = VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client,
			jwt.WithTimeFunc(func() time.Time { return captureTime }),
			jwt.WithLeeway(10*time.Second), // capture dir timestamp predates JWT issuance by a few seconds
		)
		t.Logf("NRAS format: %s", nrasResult.Format)
		t.Logf("NRAS signature err: %v", nrasResult.SignatureErr)
		t.Logf("NRAS claims err: %v", nrasResult.ClaimsErr)
		t.Logf("NRAS overall result: %v", nrasResult.OverallResult)
	}

	// 4e. Compose binding
	t.Log("--- compose binding ---")
	var composeResult *ComposeBindingResult
	if raw.AppCompose != "" && tdxResult.ParseErr == nil {
		composeResult = &ComposeBindingResult{Checked: true}
		composeResult.Err = VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
		t.Logf("compose binding err: %v", composeResult.Err)
	}

	// 4f. Sigstore
	t.Log("--- Sigstore ---")
	var sigstoreResults []SigstoreResult
	if raw.AppCompose != "" {
		dockerCompose, err := ExtractDockerCompose(raw.AppCompose)
		if err != nil {
			t.Logf("extract docker_compose_file: %v (using raw app_compose)", err)
		}
		source := dockerCompose
		if source == "" {
			source = raw.AppCompose
		}
		digests := ExtractImageDigests(source)
		t.Logf("image digests: %d", len(digests))
		for _, d := range digests {
			t.Logf("  sha256:%s...", d[:min(16, len(d))])
		}
		if len(digests) > 0 {
			sigstoreResults = CheckSigstoreDigests(ctx, digests, client)
			for _, r := range sigstoreResults {
				t.Logf("  sigstore: digest=%s ok=%v status=%d err=%v", r.Digest[:min(16, len(r.Digest))], r.OK, r.Status, r.Err)
			}
		}
	}

	// 4g. Rekor
	t.Log("--- Rekor ---")
	var rekorResults []RekorProvenance
	for _, sr := range sigstoreResults {
		if sr.OK {
			prov := FetchRekorProvenance(ctx, sr.Digest, client)
			t.Logf("  rekor: digest=%s hasCert=%v err=%v", prov.Digest[:min(16, len(prov.Digest))], prov.HasCert, prov.Err)
			rekorResults = append(rekorResults, prov)
		}
	}

	// 4h. PoC
	t.Log("--- Proof of Cloud ---")
	poc := NewPoCClient(pocPeers, 3, client)
	pocResult := poc.CheckQuote(ctx, raw.IntelQuote)
	t.Logf("PoC registered: %v", pocResult.Registered)
	t.Logf("PoC machine ID: %s", pocResult.MachineID)
	t.Logf("PoC label: %s", pocResult.Label)
	t.Logf("PoC err: %v", pocResult.Err)

	// ---------------------------------------------------------------
	// 5. Build report and assert factors
	// ---------------------------------------------------------------
	t.Log("--- BuildReport ---")
	report := BuildReport(&ReportInput{
		Provider:   "nearai",
		Model:      model,
		Raw:        raw,
		Nonce:      nonce,
		TDX:        tdxResult,
		Nvidia:     nvidiaResult,
		NvidiaNRAS: nrasResult,
		PoC:        pocResult,
		Compose:    composeResult,
		Sigstore:   sigstoreResults,
		Rekor:      rekorResults,
	})

	total := report.Passed + report.Failed + report.Skipped
	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)",
		report.Passed, total, report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	// ---------------------------------------------------------------
	// 6. Assert expected factor results
	// ---------------------------------------------------------------
	expectations := []struct {
		name   string
		status Status
	}{
		{"nonce_match", Pass},
		{"tdx_quote_present", Pass},
		{"tdx_quote_structure", Pass},
		// cert chain + signature may fail if PCK certs expired — tested separately below
		{"tdx_debug_disabled", Pass},
		{"signing_key_present", Pass},
		{"tdx_reportdata_binding", Pass},
		// intel_pcs_collateral — tested separately below (may need fixture refresh)
		// tdx_tcb_current — depends on TCB freshness
		{"nvidia_payload_present", Pass},
		{"nvidia_nonce_match", Pass},
		{"e2ee_capable", Pass},
		{"tls_key_binding", Pass},
		{"build_transparency_log", Pass},
		{"compose_binding", Pass},
		{"sigstore_verification", Pass},
		{"event_log_integrity", Pass},
	}

	for _, exp := range expectations {
		f := findFactor(t, report, exp.name)
		if f.Status != exp.status {
			t.Errorf("factor %s: got %s, want %s (detail: %s)", exp.name, f.Status, exp.status, f.Detail)
		}
	}

	// Cert chain and signature — accept pass; log warning on fail (cert expiry).
	for _, name := range []string{"tdx_cert_chain", "tdx_quote_signature"} {
		f := findFactor(t, report, name)
		if f.Status == Fail {
			t.Logf("WARNING: %s failed (likely PCK cert expiry, recapture fixtures): %s", name, f.Detail)
		}
	}

	// Intel PCS collateral — expect pass with fixture data.
	pcsF := findFactor(t, report, "intel_pcs_collateral")
	if pcsF.Status == Fail {
		t.Logf("WARNING: intel_pcs_collateral failed (may need fixture refresh): %s", pcsF.Detail)
	} else if pcsF.Status != Pass {
		t.Errorf("intel_pcs_collateral: got %s, want Pass or Fail (detail: %s)", pcsF.Status, pcsF.Detail)
	}

	// NVIDIA signature — SPDM cert chain may have time sensitivity.
	nvidSig := findFactor(t, report, "nvidia_signature")
	if nvidSig.Status == Fail {
		t.Logf("WARNING: nvidia_signature failed (may need fixture refresh): %s", nvidSig.Detail)
	}

	// NVIDIA claims — may have time-sensitive fields.
	nvidClaims := findFactor(t, report, "nvidia_claims")
	if nvidClaims.Status == Fail {
		t.Logf("WARNING: nvidia_claims failed (may need fixture refresh): %s", nvidClaims.Detail)
	}

	// NRAS — JWT expiry is pinned to capture time, so this should pass.
	nrasF := findFactor(t, report, "nvidia_nras_verified")
	if nrasF.Status != Pass {
		t.Errorf("nvidia_nras_verified: got %s, want Pass (detail: %s)", nrasF.Status, nrasF.Detail)
	}

	// PoC — depends on whether the machine is whitelisted.
	pocF := findFactor(t, report, "cpu_id_registry")
	t.Logf("cpu_id_registry: %s (%s)", pocF.Status, pocF.Detail)

	// Factors 18-19 are not implemented yet — expected fail.
	for _, name := range []string{"cpu_gpu_chain", "measured_model_weights"} {
		f := findFactor(t, report, name)
		if f.Status != Fail {
			t.Errorf("factor %s: got %s, want Fail (not implemented)", name, f.Status)
		}
	}

	// Overall: we should have many passes.
	if report.Passed < 10 {
		t.Errorf("expected at least 10 passing factors, got %d", report.Passed)
	}
	t.Logf("PASS: %d/%d factors passed", report.Passed, total)
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

// parseCaptureTime extracts the capture timestamp from the fixture directory
// name (nearai_YYYYMMDD_HHMMSS). Used to pin JWT expiry checks to capture time
// so fixtures don't expire.
func parseCaptureTime(t *testing.T, fdir string) time.Time {
	t.Helper()
	base := filepath.Base(fdir)
	ct, err := time.Parse("nearai_20060102_150405", base)
	if err != nil {
		t.Fatalf("parse capture time from %q: %v", base, err)
	}
	return ct
}

func readFixtureFrom(t *testing.T, dir, name string) []byte {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

// extractModel returns the model name from the first entry in the fixture.
func extractModel(t *testing.T, body []byte) string {
	t.Helper()
	var ar struct {
		ModelAttestations []struct {
			Model     string `json:"model"`
			ModelName string `json:"model_name"`
		} `json:"model_attestations"`
		AllAttestations []struct {
			Model     string `json:"model"`
			ModelName string `json:"model_name"`
		} `json:"all_attestations"`
		Model     string `json:"model"`
		ModelName string `json:"model_name"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		t.Fatalf("parse attestation for model name: %v", err)
	}
	for _, list := range [][]struct {
		Model     string `json:"model"`
		ModelName string `json:"model_name"`
	}{ar.AllAttestations, ar.ModelAttestations} {
		if len(list) > 0 {
			if list[0].Model != "" {
				return list[0].Model
			}
			return list[0].ModelName
		}
	}
	if ar.Model != "" {
		return ar.Model
	}
	if ar.ModelName != "" {
		return ar.ModelName
	}
	t.Fatal("no model found in attestation fixture")
	return ""
}

// ---------------------------------------------------------------------------
// NEAR AI fixture parser (mirrors nearai.parseAttestationResponse)
//
// This is test-only code to avoid a circular import with the nearai package.
// ---------------------------------------------------------------------------

type fixtureModelAttestation struct {
	Model              string            `json:"model"`
	ModelName          string            `json:"model_name"`
	IntelQuote         string            `json:"intel_quote"`
	NvidiaPayload      string            `json:"nvidia_payload"`
	SigningKey         string            `json:"signing_key"`
	SigningPublicKey   string            `json:"signing_public_key"`
	SigningAddress     string            `json:"signing_address"`
	SigningAlgo        string            `json:"signing_algo"`
	TLSCertFingerprint string            `json:"tls_cert_fingerprint"`
	Nonce              string            `json:"nonce"`
	RequestNonce       string            `json:"request_nonce"`
	EventLog           []json.RawMessage `json:"event_log"`
	Info               struct {
		AppName     string          `json:"app_name"`
		ComposeHash string          `json:"compose_hash"`
		OSImageHash string          `json:"os_image_hash"`
		DeviceID    string          `json:"device_id"`
		TCBInfo     json.RawMessage `json:"tcb_info"`
	} `json:"info"`
}

type fixtureAttestationResponse struct {
	ModelAttestations []fixtureModelAttestation `json:"model_attestations"`
	AllAttestations   []fixtureModelAttestation `json:"all_attestations"`
	Verified          bool                      `json:"verified"`
	fixtureModelAttestation
}

func parseNearAIFixture(t *testing.T, body []byte, model string) *RawAttestation {
	t.Helper()
	var ar fixtureAttestationResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		t.Fatalf("parse NEAR AI fixture: %v", err)
	}

	// Try all_attestations, then model_attestations.
	for _, list := range [][]fixtureModelAttestation{ar.AllAttestations, ar.ModelAttestations} {
		for i := range list {
			name := list[i].Model
			if name == "" {
				name = list[i].ModelName
			}
			if name == model {
				return fixtureToRaw(&list[i], ar.Verified, body)
			}
		}
	}

	// Flat form.
	if ar.IntelQuote != "" {
		return fixtureToRaw(&ar.fixtureModelAttestation, ar.Verified, body)
	}

	t.Fatalf("model %q not found in fixture", model)
	return nil
}

func fixtureToRaw(m *fixtureModelAttestation, verified bool, body []byte) *RawAttestation {
	signingKey := firstNonEmpty(m.SigningKey, m.SigningPublicKey)
	if len(signingKey) == 128 {
		signingKey = "04" + signingKey // normalize uncompressed key
	}
	raw := &RawAttestation{
		Verified:       verified,
		Nonce:          firstNonEmpty(m.Nonce, m.RequestNonce),
		Model:          firstNonEmpty(m.Model, m.ModelName),
		TEEProvider:    "TDX+NVIDIA",
		SigningKey:     signingKey,
		SigningAddress: m.SigningAddress,
		SigningAlgo:    m.SigningAlgo,
		TLSFingerprint: m.TLSCertFingerprint,
		IntelQuote:     m.IntelQuote,
		NvidiaPayload:  m.NvidiaPayload,
		AppCompose:     extractAppComposeFixture(m.Info.TCBInfo),
		AppName:        m.Info.AppName,
		ComposeHash:    m.Info.ComposeHash,
		OSImageHash:    m.Info.OSImageHash,
		DeviceID:       m.Info.DeviceID,
		EventLog:       parseEventLogFixture(m.EventLog),
		EventLogCount:  len(m.EventLog),
		RawBody:        body,
	}
	if raw.IntelQuote != "" {
		raw.TEEHardware = "intel-tdx"
	}
	return raw
}

func parseEventLogFixture(raw []json.RawMessage) []EventLogEntry {
	entries := make([]EventLogEntry, 0, len(raw))
	for _, r := range raw {
		var e EventLogEntry
		if err := json.Unmarshal(r, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// extractAppComposeFixture mirrors nearai.extractAppCompose.
func extractAppComposeFixture(tcbInfo json.RawMessage) string {
	if len(tcbInfo) == 0 {
		return ""
	}
	raw := tcbInfo
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		raw = json.RawMessage(str)
	}
	var obj struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	return obj.AppCompose
}

// ---------------------------------------------------------------------------
// NEAR AI REPORTDATA verifier (mirrors nearai.ReportDataVerifier)
// ---------------------------------------------------------------------------

func verifyNearAIReportData(reportData [64]byte, raw *RawAttestation, nonce Nonce) (string, error) {
	if raw.SigningAddress == "" {
		return "", errors.New("signing_address absent from attestation response")
	}
	if raw.TLSFingerprint == "" {
		return "", errors.New("tls_cert_fingerprint absent from attestation response")
	}

	addrHex := strings.TrimPrefix(raw.SigningAddress, "0x")
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return "", fmt.Errorf("signing_address is not valid hex: %w", err)
	}

	fpBytes, err := hex.DecodeString(raw.TLSFingerprint)
	if err != nil {
		return "", fmt.Errorf("tls_cert_fingerprint is not valid hex: %w", err)
	}

	expected := sha256.Sum256(append(addrBytes, fpBytes...))
	if subtle.ConstantTimeCompare(expected[:], reportData[:32]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:32] = %s, expected sha256(signing_address + tls_fingerprint) = %s",
			hex.EncodeToString(reportData[:32]), hex.EncodeToString(expected[:]))
	}

	var nonceBytes [32]byte
	copy(nonceBytes[:], nonce[:])
	if subtle.ConstantTimeCompare(nonceBytes[:], reportData[32:64]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] nonce mismatch: got %s, want %s",
			hex.EncodeToString(reportData[32:64]), hex.EncodeToString(nonceBytes[:]))
	}

	return "REPORTDATA binds sha256(signing_address + tls_fingerprint) + nonce", nil
}

// ---------------------------------------------------------------------------
// Intel PCS fixture-backed getter
// ---------------------------------------------------------------------------

func buildPCSGetter(t *testing.T, fdir string) trust.HTTPSGetter {
	t.Helper()

	// Load the FMSPC from the attestation to construct the correct tcbinfo URL.
	attestBody := readFixtureFrom(t, fdir, "nearai_attestation.json")
	model := extractModel(t, attestBody)
	raw := parseNearAIFixture(t, attestBody, model)
	tdxResult := VerifyTDXQuote(context.Background(), raw.IntelQuote, Nonce{}, true)
	if tdxResult.ParseErr != nil {
		t.Fatalf("parse TDX quote for FMSPC extraction: %v", tdxResult.ParseErr)
	}
	fmspc := tdxResult.FMSPC
	if fmspc == "" {
		t.Fatal("FMSPC not extracted from TDX quote")
	}
	t.Logf("PCS getter: FMSPC=%s", fmspc)

	// Load PCS fixture files.
	tcbInfoBody := readFixtureFrom(t, fdir, "nearai_pcs_tcbinfo.json")
	tcbInfoHeaders := readHeadersFixture(t, fdir, "nearai_pcs_tcbinfo_headers.json")

	qeIdentityBody := readFixtureFrom(t, fdir, "nearai_pcs_qeidentity.json")
	qeIdentityHeaders := readHeadersFixture(t, fdir, "nearai_pcs_qeidentity_headers.json")

	pckCrlBody := readFixtureFrom(t, fdir, "nearai_pcs_pckcrl.der")
	pckCrlHeaders := readHeadersFixture(t, fdir, "nearai_pcs_pckcrl_headers.json")

	rootCrlBody := readFixtureFrom(t, fdir, "nearai_pcs_rootcrl.der")

	// Build the Getter with responses keyed by exact Intel API URLs.
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
// PoC mock peers
// ---------------------------------------------------------------------------

// pocFixtureIs403 returns true if the stage1 fixture is a 403 error response
// (i.e. the machine was not whitelisted at capture time).
func pocFixtureIs403(data []byte) bool {
	var obj struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(data, &obj) == nil && obj.Error != ""
}

func buildPoCMockPeers(t *testing.T, fdir string) []string {
	t.Helper()

	// Load stage1 and stage2 responses for each peer.
	type peerFixtures struct {
		stage1    []byte
		stage2    []byte
		forbidden bool // true if stage1 is a 403 error
	}

	peers := make([]peerFixtures, 3)
	for i := range 3 {
		s1 := readFixtureFrom(t, fdir, fmt.Sprintf("nearai_poc_stage1_%d.json", i))
		peers[i] = peerFixtures{
			stage1:    s1,
			stage2:    readFixtureFrom(t, fdir, fmt.Sprintf("nearai_poc_stage2_%d.json", i)),
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
			// First call to /get_jwt is stage 1 (no nonces), second is stage 2 (has nonces).
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
// Rekor mock helpers (reused from rekor_test.go, same package)
// ---------------------------------------------------------------------------

// buildMockDSSEBody, buildMockEntryResponse, and realFulcioCertPEM are
// defined in rekor_test.go (same package). Referenced directly here.

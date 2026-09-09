package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
)

func dialAndClose(addr string) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- c.Close()
	}()
	return errCh
}

func waitDialResult(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("dial helper: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dial helper timed out")
	}
}

func TestMonitoredConn_CloseIdempotent(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	errCh := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	raw, err := base.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitDialResult(t, errCh)

	var active atomic.Int64
	active.Store(1)

	mc := &monitoredConn{Conn: raw, active: &active}

	t.Log("first Close")
	if err := mc.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if active.Load() != 0 {
		t.Errorf("active should be 0 after Close, got %d", active.Load())
	}

	t.Log("second Close (idempotent — decrements active only once)")
	_ = mc.Close()
	if active.Load() != 0 {
		t.Errorf("active should still be 0 after second Close, got %d", active.Load())
	}
}

func TestMonitoredListener_ThrottleLog(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer base.Close()

	ml := &monitoredListener{
		Listener: base,
		maxConns: 1,
	}
	// Simulate active == maxConns so each Accept evaluates the throttle check.
	ml.active.Store(1)
	now := time.Now().Unix()
	ml.lastWarn.Store(now)

	// First Accept is inside the 60-second throttle window, so lastWarn should
	// not be updated.
	errCh := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	conn, err := ml.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	waitDialResult(t, errCh)
	if got := ml.lastWarn.Load(); got != now {
		t.Errorf("lastWarn updated within throttle window: got %d, want %d", got, now)
	}
	conn.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after Close, want 1", got)
	}

	// Move lastWarn outside the throttle window; next Accept should update it.
	ml.lastWarn.Store(now - 61)
	errCh2 := dialAndClose(base.Addr().String())
	_ = base.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))

	conn2, err := ml.Accept()
	if err != nil {
		t.Fatalf("second Accept: %v", err)
	}
	waitDialResult(t, errCh2)
	if got := ml.lastWarn.Load(); got < now {
		t.Errorf("lastWarn was not updated after throttle window: got %d, want >= %d", got, now)
	}
	conn2.Close()
	if got := ml.active.Load(); got != 1 {
		t.Errorf("active = %d after second Close, want 1", got)
	}
}

// --------------------------------------------------------------------------
// inapplicableForProvider
// --------------------------------------------------------------------------

func TestInapplicableForProvider(t *testing.T) {
	tests := []struct {
		provider      string
		expectFactor  string
		expectPresent bool
	}{
		{"venice", "compose_binding", false},
		{"neardirect", "compose_binding", false},
		{"nearcloud", "compose_binding", false},
		{"nanogpt", "compose_binding", false},
		{"phalacloud", "compose_binding", false},
		{"tinfoil_v3_cloud", "compose_binding", true},
		{"tinfoil_v3_direct", "event_log_integrity", true},
		{"chutes", "compose_binding", true},
		{"unknown", "compose_binding", false}, // falls through to default
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			result := inapplicableForProvider(tc.provider)
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			_, ok := result[tc.expectFactor]
			if ok != tc.expectPresent {
				t.Errorf("inapplicableForProvider(%q)[%q] = %v, want %v",
					tc.provider, tc.expectFactor, ok, tc.expectPresent)
			}
		})
	}
}

// --------------------------------------------------------------------------
// truncTo
// --------------------------------------------------------------------------

func TestTruncTo(t *testing.T) {
	if got := truncTo("abcdef", 4); got != "abcd" {
		t.Errorf("truncTo(abcdef,4) = %q, want abcd", got)
	}
	if got := truncTo("ab", 10); got != "ab" {
		t.Errorf("truncTo(ab,10) = %q, want ab", got)
	}
	if got := truncTo("", 5); got != "" {
		t.Errorf("truncTo('',5) = %q, want ''", got)
	}
}

// --------------------------------------------------------------------------
// verifyTinfoilSupplyChain — nil guard
// --------------------------------------------------------------------------

func TestVerifyTinfoilSupplyChain_NonTinfoilFormat(t *testing.T) {
	s := &Server{}
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatDstack}
	result, _ := s.verifyTinfoilSupplyChain(t.Context(), raw, nil, nil, nil, "model")
	if result != nil {
		t.Errorf("expected nil for non-Tinfoil format, got %v", result)
	}
}

// --------------------------------------------------------------------------
// prefixModelID
// --------------------------------------------------------------------------

func TestPrefixModelID(t *testing.T) {
	tests := []struct {
		provName string
		model    json.RawMessage
		wantID   string
	}{
		{"venice", json.RawMessage(`{"id":"qwen3-32b","object":"model"}`), "venice:qwen3-32b"},
		{"tinfoil_v3_cloud", json.RawMessage(`{"id":"llama3-3-70b"}`), "tinfoil_v3_cloud:llama3-3-70b"},
	}
	for _, tc := range tests {
		result, err := prefixModelID(tc.provName, tc.model)
		if err != nil {
			t.Errorf("prefixModelID(%q, %s): %v", tc.provName, tc.model, err)
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(result, &obj); err != nil {
			t.Errorf("unmarshal result: %v", err)
			continue
		}
		var got string
		if err := json.Unmarshal(obj["id"], &got); err != nil {
			t.Errorf("unmarshal id: %v", err)
			continue
		}
		if got != tc.wantID {
			t.Errorf("prefixModelID(%q, %s) id = %q, want %q", tc.provName, tc.model, got, tc.wantID)
		}
	}
}

func TestPrefixModelID_MissingID(t *testing.T) {
	_, err := prefixModelID("test", json.RawMessage(`{"object":"model"}`))
	if err == nil {
		t.Error("expected error for missing id field")
	}
}

func TestPrefixModelID_InvalidJSON(t *testing.T) {
	_, err := prefixModelID("test", json.RawMessage(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --------------------------------------------------------------------------
// extractMultipartField — new branches not covered by relay_internal_test.go
// --------------------------------------------------------------------------

func buildMultipart(t *testing.T, fields map[string]string) (contentType string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField %q: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return mw.FormDataContentType(), buf.Bytes()
}

func TestExtractMultipartField_OversizedField(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": strings.Repeat("x", 1025)})
	_, err := extractMultipartField(ct, body, "model")
	if err == nil {
		t.Fatal("expected error for oversized field")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should mention exceeds: %v", err)
	}
}

// --------------------------------------------------------------------------
// rewriteMultipartModel
// --------------------------------------------------------------------------

func TestRewriteMultipartModel_Success(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "old-model", "file": "data"})
	result, err := rewriteMultipartModel(ct, body, "new-model")
	if err != nil {
		t.Fatalf("rewriteMultipartModel: %v", err)
	}
	// Read back the model field from the result.
	got, err := extractMultipartField(ct, result, "model")
	if err != nil {
		t.Fatalf("extract from rewritten: %v", err)
	}
	if got != "new-model" {
		t.Errorf("model = %q, want new-model", got)
	}
	// The file field should still be present.
	gotFile, err := extractMultipartField(ct, result, "file")
	if err != nil {
		t.Fatalf("extract file from rewritten: %v", err)
	}
	if gotFile != "data" {
		t.Errorf("file = %q, want data", gotFile)
	}
}

func TestRewriteMultipartModel_InvalidContentType(t *testing.T) {
	_, err := rewriteMultipartModel("application/json", []byte("{}"), "model")
	if err == nil {
		t.Fatal("expected error for non-multipart content type")
	}
}

func TestRewriteMultipartModel_MissingBoundary(t *testing.T) {
	_, err := rewriteMultipartModel("multipart/form-data", []byte("data"), "model")
	if err == nil {
		t.Fatal("expected error for missing boundary")
	}
}

// --------------------------------------------------------------------------
// rewriteModelInBody
// --------------------------------------------------------------------------

func TestRewriteModelInBody_JSON(t *testing.T) {
	body := []byte(`{"model":"old","messages":[]}`)
	result, err := rewriteModelInBody("application/json", body, "application/json", "new-model")
	if err != nil {
		t.Fatalf("rewriteModelInBody: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	var got string
	if err := json.Unmarshal(m["model"], &got); err != nil {
		t.Fatalf("unmarshal model: %v", err)
	}
	if got != "new-model" {
		t.Errorf("model = %q, want new-model", got)
	}
}

func TestRewriteModelInBody_InvalidJSON(t *testing.T) {
	_, err := rewriteModelInBody("application/json", []byte("not json"), "application/json", "model")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestRewriteModelInBody_Multipart(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "old", "file": "data"})
	result, err := rewriteModelInBody(ct, body, ct, "new-model")
	if err != nil {
		t.Fatalf("rewriteModelInBody multipart: %v", err)
	}
	got, err := extractMultipartField(ct, result, "model")
	if err != nil {
		t.Fatalf("extract model: %v", err)
	}
	if got != "new-model" {
		t.Errorf("model = %q, want new-model", got)
	}
}

// --------------------------------------------------------------------------
// fetchAndVerify — nil Attester
// --------------------------------------------------------------------------

func TestFetchAndVerify_NilAttester(t *testing.T) {
	s := newTestServer(t)
	s.signingKeyCache = attestation.NewSigningKeyCache(0)

	prov := &provider.Provider{Name: "test"}
	var report *attestation.VerificationReport
	var raw *attestation.RawAttestation
	logs := captureSlog(t, func() {
		report, raw = s.fetchAndVerify(t.Context(), prov, "model")
	})
	if report != nil {
		t.Errorf("expected nil report, got %v", report)
	}
	if raw != nil {
		t.Errorf("expected nil raw, got %v", raw)
	}
	for _, want := range []string{
		"msg=\"provider has no Attester\"",
		"provider=test",
		"model=model",
		"err=\"provider has no Attester\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

// --------------------------------------------------------------------------
// pinnedPreDispatchE2EE
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// parseAudioModelRequest
// --------------------------------------------------------------------------

func TestParseAudioModelRequest_Success(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "whisper-1", "file": "audio"})
	r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)

	model, stream, err := parseAudioModelRequest(r, body)
	if err != nil {
		t.Fatalf("parseAudioModelRequest: %v", err)
	}
	if model != "whisper-1" {
		t.Errorf("model = %q, want whisper-1", model)
	}
	if stream {
		t.Error("stream should be false for audio")
	}
}

func TestParseAudioModelRequest_EmptyModel(t *testing.T) {
	ct, body := buildMultipart(t, map[string]string{"model": "", "file": "audio"})
	r := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)

	_, _, err := parseAudioModelRequest(r, body)
	if err == nil {
		t.Fatal("expected error for empty model")
	}
}

// --------------------------------------------------------------------------
// normalizationStatusCode
// --------------------------------------------------------------------------

func TestNormalizationStatusCode_Regular(t *testing.T) {
	code := normalizationStatusCode(errors.New("regular error"))
	if code != http.StatusInternalServerError {
		t.Errorf("normalizationStatusCode(regular) = %d, want 500", code)
	}
}

func TestNormalizationStatusCode_RequestError(t *testing.T) {
	code := normalizationStatusCode(newRequestNormalizationError(errors.New("bad request")))
	if code != http.StatusBadRequest {
		t.Errorf("normalizationStatusCode(request) = %d, want 400", code)
	}
}

// --------------------------------------------------------------------------
// recordTokPerSec
// --------------------------------------------------------------------------

func TestRecordTokPerSec_Positive(t *testing.T) {
	ms := &modelStats{}
	ss := e2ee.StreamStats{Duration: 2 * time.Second, Chunks: 10}
	recordTokPerSec(ms, ss)
	if ms.lastTokDurMs.Load() != 2000 {
		t.Errorf("lastTokDurMs = %d, want 2000", ms.lastTokDurMs.Load())
	}
}

func TestRecordTokPerSec_ZeroDuration(t *testing.T) {
	ms := &modelStats{}
	ss := e2ee.StreamStats{Duration: 0, Chunks: 10}
	recordTokPerSec(ms, ss)
	if ms.lastTokDurMs.Load() != 0 {
		t.Errorf("lastTokDurMs should be 0 for zero duration, got %d", ms.lastTokDurMs.Load())
	}
}

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// enforceReport — blocked writes JSON body
// --------------------------------------------------------------------------

func TestEnforceReport_BlockedWritesJSONBody(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Fail, Enforced: true, Detail: "nonce did not match"},
		},
	}
	rec := httptest.NewRecorder()
	prov := &provider.Provider{Name: "test"}
	if s.enforceReport(t.Context(), rec, report, prov, "model") {
		t.Error("expected false for blocked report without force")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	// Response should be valid JSON containing the report.
	var decoded attestation.VerificationReport
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if decoded.Provider != "test" {
		t.Errorf("decoded.Provider = %q, want test", decoded.Provider)
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache hit
// --------------------------------------------------------------------------

func TestAttestAndCache_CacheHit(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors:  []attestation.FactorResult{{Name: "nonce_match", Status: attestation.Pass}},
	}
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: false}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "" {
		t.Errorf("failStatus = %q, want empty", failStatus)
	}
	if result.Report == nil {
		t.Fatal("expected non-nil report")
	}
	if result.E2EEActive {
		t.Error("E2EE should not be active without binding")
	}
	if s.stats.cacheHits.Load() != 1 {
		t.Errorf("cacheHits = %d, want 1", s.stats.cacheHits.Load())
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache miss, attestation fails
// --------------------------------------------------------------------------

func TestAttestAndCache_AttestFailed(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Provider with nil Attester → fetchAndVerify returns nil.
	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "attest_failed" {
		t.Errorf("failStatus = %q, want attest_failed", failStatus)
	}
	if result == nil {
		t.Fatal("expected non-nil result even on failure")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache miss, report blocked
// --------------------------------------------------------------------------

func TestAttestAndCache_ReportBlocked(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Use a provider with a mock attester that returns a report.
	// fetchAndVerify will run, but we need it to produce a blocked report.
	// The easiest approach: pre-populate the cache with a blocked report (cache hit)
	// and then call enforceReport which returns false.
	blockedReport := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Fail, Enforced: true},
		},
	}
	s.cache.Put("test", "model", blockedReport)

	prov := &provider.Provider{Name: "test"}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "blocked" {
		t.Errorf("failStatus = %q, want blocked", failStatus)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --------------------------------------------------------------------------
// attestAndCache — cache hit with E2EE active
// --------------------------------------------------------------------------

func TestAttestAndCache_E2EEActive(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "tee_reportdata_binding", Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", report)

	prov := &provider.Provider{Name: "test", E2EE: true}
	ms := &modelStats{}
	rec := httptest.NewRecorder()

	result, failStatus := s.attestAndCache(t.Context(), rec, prov, "model", ms)
	if failStatus != "" {
		t.Errorf("failStatus = %q, want empty", failStatus)
	}
	if !result.E2EEActive {
		t.Error("E2EE should be active with passing binding and E2EE enabled")
	}
	if s.stats.e2ee.Load() != 1 {
		t.Errorf("e2ee stat = %d, want 1", s.stats.e2ee.Load())
	}
}

// --------------------------------------------------------------------------
// buildDashboardData — blocked factors path
// --------------------------------------------------------------------------

// The tier bar draws passed/failed/warned as widths out of Total. A skip
// counts toward Total, so leaving it out of all three drew the remainder as
// background and a tier teep could not check looked fully covered.
func TestBuildDashboardData_SkipsCountAsWarned(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		providers:       map[string]*provider.Provider{"test": {Name: "test"}},
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	tier := attestation.TierCore
	s.cache.Put("test", "model", &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "tee_quote_present", Tier: tier, Status: attestation.Pass},
			{Name: "tee_measurement", Tier: tier, Status: attestation.Skip},
			{Name: "tee_boot_config", Tier: tier, Status: attestation.Skip},
			{Name: "tee_reportdata_binding", Tier: tier, Status: attestation.Fail},
			// N/A stays out of the denominator entirely.
			{Name: "compose_binding", Tier: tier, Status: attestation.NotApplicable},
		},
	})

	data := s.buildDashboardData()
	if len(data.Attestations) == 0 {
		t.Fatal("expected attestations in dashboard data")
	}
	var got *dashTier
	for i := range data.Attestations[0].Tiers {
		if data.Attestations[0].Tiers[i].Name == tier {
			got = &data.Attestations[0].Tiers[i]
		}
	}
	if got == nil {
		t.Fatalf("no %q tier in dashboard data", tier)
	}
	if got.Total != 4 {
		t.Errorf("Total = %d, want 4 (the N/A factor is not scored)", got.Total)
	}
	if sum := got.Passed + got.Failed + got.Warned; sum != got.Total {
		t.Errorf("passed+failed+warned = %d, want %d: the bar leaves %d factors uncoloured",
			sum, got.Total, got.Total-sum)
	}
	if got.Warned != 3 {
		t.Errorf("Warned = %d, want 3 (two skips and one allowed failure)", got.Warned)
	}
}

func TestBuildDashboardData_BlockedFactors(t *testing.T) {
	s := &Server{
		cfg:             &config.Config{ListenAddr: "127.0.0.1:8337"},
		cache:           attestation.NewCache(time.Minute),
		negCache:        attestation.NewNegativeCache(time.Minute),
		signingKeyCache: attestation.NewSigningKeyCache(time.Minute),
		providers: map[string]*provider.Provider{
			"test": {Name: "test"},
		},
		stats: stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Put a report with a blocked factor.
	report := &attestation.VerificationReport{
		Provider: "test",
		Model:    "model",
		Factors: []attestation.FactorResult{
			{Name: "nonce_match", Status: attestation.Fail, Enforced: true},
			{Name: attestation.FactorE2EECapable, Status: attestation.Pass},
		},
	}
	s.cache.Put("test", "model", report)

	data := s.buildDashboardData()

	if len(data.Attestations) == 0 {
		t.Fatal("expected attestations in dashboard data")
	}
	att := data.Attestations[0]
	if !att.Blocked {
		t.Error("expected Blocked=true")
	}
	if len(att.BlockedFactors) == 0 {
		t.Error("expected non-empty BlockedFactors")
	}
	if att.BlockedFactors[0] != "nonce_match" {
		t.Errorf("BlockedFactors[0] = %q, want nonce_match", att.BlockedFactors[0])
	}
	if att.E2EE != "capable" {
		t.Errorf("E2EE = %q, want capable", att.E2EE)
	}
}

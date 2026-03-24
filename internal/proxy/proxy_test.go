package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/proxy"
)

type stubPinnedHandler struct{}

func (stubPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	body := io.NopCloser(strings.NewReader(nonStreamResponse("ok")))
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}, nil
}

type blockedPinnedHandler struct{}

func (blockedPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	body := io.NopCloser(strings.NewReader(""))
	return &provider.PinnedResponse{
		StatusCode: http.StatusBadGateway,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
		Report: &attestation.VerificationReport{
			Provider: "neardirect",
			Model:    "test-model",
			Factors: []attestation.FactorResult{
				{Name: "nonce_match", Status: attestation.Fail, Enforced: true, Detail: "mismatch"},
			},
		},
	}, nil
}

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

// modelKey is a stable secp256k1 key pair used as the "model signing key" in
// tests that exercise E2EE. The private key lets the mock upstream encrypt
// responses; the public key hex is served by the mock attestation endpoint.
var modelKey *secp256k1.PrivateKey

func init() {
	var err error
	modelKey, err = secp256k1.GeneratePrivateKey()
	if err != nil {
		panic(fmt.Sprintf("generate model key: %v", err))
	}
}

// modelPubKeyHex returns the uncompressed model public key as a hex string.
func modelPubKeyHex() string {
	return hex.EncodeToString(modelKey.PubKey().SerializeUncompressed())
}

// attestationJSON builds a Venice-style attestation JSON payload. The
// intel_quote and nvidia_payload are left empty so TDX/NVIDIA factors all
// fail/skip, but nonce_match passes when echoNonce is true.
// When reportdataOK is true it injects a fake intel_quote field that causes
// the proxy to treat tdx_reportdata_binding as having been checked (but since
// the quote is not a real TDX quote, VerifyTDXQuote will set ParseErr, which
// causes tdx_reportdata_binding to Fail). Use withPassingTDX for the E2EE path.
func attestationJSON(nonce attestation.Nonce, echoNonce bool) string {
	nonceField := ""
	if echoNonce {
		nonceField = nonce.Hex()
	}
	return fmt.Sprintf(`{
		"verified": true,
		"nonce": %q,
		"model": "test-model",
		"tee_provider": "TDX+NVIDIA",
		"signing_key": %q,
		"signing_address": "0xtest",
		"intel_quote": "",
		"nvidia_payload": ""
	}`, nonceField, modelPubKeyHex())
}

// makeAttestationServer starts an httptest server for the attestation and
// models endpoints. When echoNonce is true the server echoes back the nonce
// query param.
func makeAttestationServer(t *testing.T, echoNonce bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/tee/attestation", func(w http.ResponseWriter, r *http.Request) {
		nonceHex := r.URL.Query().Get("nonce")
		var n attestation.Nonce
		if echoNonce && nonceHex != "" {
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(attestationJSON(n, echoNonce)))
	})
	mux.HandleFunc("/api/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(veniceModelsJSON))
	})
	return httptest.NewServer(mux)
}

// veniceModelsJSON is a minimal Venice /api/v1/models response for tests.
const veniceModelsJSON = `{
	"data": [
		{"id": "e2ee-test-model", "created": 1727966436, "object": "model", "owned_by": "venice.ai", "type": "text", "model_spec": {"capabilities": {"supportsE2EE": true, "supportsTeeAttestation": true}}},
		{"id": "tee-test-model", "created": 1727966436, "object": "model", "owned_by": "venice.ai", "type": "text", "model_spec": {"capabilities": {"supportsE2EE": false, "supportsTeeAttestation": true}}},
		{"id": "plain-model", "created": 1727966436, "object": "model", "owned_by": "venice.ai", "type": "text", "model_spec": {"capabilities": {"supportsE2EE": false, "supportsTeeAttestation": false}}}
	]
}`

// buildConfig returns a *config.Config wired to the given attestation server
// URL, with a single "venice" provider.
func buildConfig(attestBaseURL string, _ bool) *config.Config {
	return &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: attestBaseURL,
				APIKey:  "test-key",
				E2EE:    false,
			},
		},
		Enforced: []string{"nonce_match", "tdx_debug_disabled", "signing_key_present", "tdx_reportdata_binding"},
	}
}

// newProxy creates a proxy.Server using the given config, wires it to the
// given upstream chat completions server URL via the provider's BaseURL, and
// returns both an httptest.Server wrapping the proxy and the proxy itself.
func newProxyServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return httptest.NewServer(srv)
}

// postChat sends a POST /v1/chat/completions to the given proxy URL.
func postChat(t *testing.T, proxyURL, model string, stream bool) (*http.Response, error) {
	t.Helper()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hello"}],"stream":%v}`, model, stream)
	return http.Post(proxyURL+"/v1/chat/completions", "application/json", strings.NewReader(body))
}

// nonStreamResponse builds a minimal OpenAI non-streaming response JSON.
func nonStreamResponse(content string) string {
	return fmt.Sprintf(`{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"created": 1234567890,
		"model": "upstream-model",
		"choices": [{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],
		"usage": {"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}
	}`, content)
}

// streamSSE builds a simple SSE body with a single content chunk plus [DONE].
func streamSSE(content string) string {
	chunk := fmt.Sprintf(`{"id":"chatcmpl-test","object":"chat.completion.chunk","created":1234567890,"model":"upstream-model","choices":[{"index":0,"delta":{"role":"assistant","content":%q},"finish_reason":null}]}`, content)
	return fmt.Sprintf("data: %s\n\ndata: [DONE]\n\n", chunk)
}

// readSSEChunks reads all "data: ..." lines from an SSE response body,
// collecting non-DONE data payloads. Uses a 2 MiB scanner buffer to handle
// large encrypted chunks.
func readSSEChunks(t *testing.T, body io.Reader) []string {
	t.Helper()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 2<<20), 2<<20) // 2 MiB
	var chunks []string
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[len("data: "):]
		if data == "[DONE]" {
			break
		}
		chunks = append(chunks, data)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("SSE scan: %v", err)
	}
	return chunks
}

// extractContent extracts the delta.content or message.content from a raw
// SSE chunk JSON string.
func extractDeltaContent(t *testing.T, chunkJSON string) string {
	t.Helper()
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(chunkJSON), &chunk); err != nil {
		t.Fatalf("unmarshal SSE chunk: %v", err)
	}
	if len(chunk.Choices) == 0 {
		return ""
	}
	return chunk.Choices[0].Delta.Content
}

// extractMessageContent extracts message.content from a non-streaming response.
func extractMessageContent(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.Choices) == 0 {
		t.Fatal("no choices in response")
	}
	return resp.Choices[0].Message.Content
}

// --------------------------------------------------------------------------
// Route and basic tests
// --------------------------------------------------------------------------

func TestUnknownRoute404(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/unknown/path")
	if err != nil {
		t.Fatalf("GET /unknown/path: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestMissingModelField400(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestInvalidJSONBody400(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// /v1/models endpoint
// --------------------------------------------------------------------------

func TestHandleModels(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode models response: %v", err)
	}

	if result.Object != "list" {
		t.Errorf("object = %q, want %q", result.Object, "list")
	}

	// Venice mock returns 2 TEE/E2EE models (plain-model is filtered out).
	if len(result.Data) != 2 {
		t.Fatalf("data len = %d, want 2", len(result.Data))
	}

	// Verify all upstream fields are relayed through.
	type modelEntry struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
		Type    string `json:"type"`
	}
	ids := map[string]bool{}
	for _, raw := range result.Data {
		var m modelEntry
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal model entry: %v", err)
		}
		ids[m.ID] = true
		t.Logf("  model: id=%q created=%d object=%q owned_by=%q type=%q", m.ID, m.Created, m.Object, m.OwnedBy, m.Type)
		if m.Object != "model" {
			t.Errorf("model %q: object = %q, want %q", m.ID, m.Object, "model")
		}
		if m.OwnedBy != "venice.ai" {
			t.Errorf("model %q: owned_by = %q, want %q", m.ID, m.OwnedBy, "venice.ai")
		}
		if m.Created != 1727966436 {
			t.Errorf("model %q: created = %d, want 1727966436", m.ID, m.Created)
		}
	}
	if !ids["e2ee-test-model"] {
		t.Error("e2ee-test-model not in response")
	}
	if !ids["tee-test-model"] {
		t.Error("tee-test-model not in response")
	}
}

// stubModelLister returns canned models.
type stubModelLister struct {
	models []json.RawMessage
}

func (s stubModelLister) ListModels(_ context.Context) ([]json.RawMessage, error) {
	return s.models, nil
}

// errorModelLister always returns an error.
type errorModelLister struct{}

func (errorModelLister) ListModels(_ context.Context) ([]json.RawMessage, error) {
	return nil, errors.New("model listing unavailable")
}

// slowModelLister blocks until the context is cancelled.
type slowModelLister struct{}

func (slowModelLister) ListModels(ctx context.Context) ([]json.RawMessage, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestHandleModels_ProviderError(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
			},
		},
		Enforced: []string{},
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("neardirect")
	prov.ModelLister = errorModelLister{}
	prov.PinnedHandler = stubPinnedHandler{}

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	t.Logf("object=%q data_len=%d", result.Object, len(result.Data))
	if result.Object != "list" {
		t.Errorf("object = %q, want %q", result.Object, "list")
	}
	if len(result.Data) != 0 {
		t.Errorf("data len = %d, want 0 (provider errored)", len(result.Data))
	}
}

func TestHandleModels_MultipleProviders(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
			},
			"nearcloud": {
				Name:    "nearcloud",
				BaseURL: "https://cloud-api.near.ai",
				APIKey:  "key",
			},
		},
		Enforced: []string{},
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// Stub both providers with different models.
	direct := srv.ProviderByName("neardirect")
	direct.PinnedHandler = stubPinnedHandler{}
	direct.ModelLister = stubModelLister{
		models: []json.RawMessage{json.RawMessage(`{"id":"model-a","object":"model","owned_by":"near-ai"}`)},
	}

	cloud := srv.ProviderByName("nearcloud")
	cloud.PinnedHandler = stubPinnedHandler{}
	cloud.ModelLister = stubModelLister{
		models: []json.RawMessage{json.RawMessage(`{"id":"model-b","object":"model","owned_by":"near-ai"}`)},
	}

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var result struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	t.Logf("object=%q data_len=%d", result.Object, len(result.Data))
	if len(result.Data) != 2 {
		t.Fatalf("data len = %d, want 2 (one from each provider)", len(result.Data))
	}

	ids := map[string]bool{}
	for _, raw := range result.Data {
		var m struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		t.Logf("  model: %s", m.ID)
		ids[m.ID] = true
	}
	if !ids["model-a"] {
		t.Error("model-a missing from response")
	}
	if !ids["model-b"] {
		t.Error("model-b missing from response")
	}
}

func TestHandleModels_SlowProvider(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
			},
		},
		Enforced: []string{},
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("neardirect")
	prov.ModelLister = slowModelLister{}
	prov.PinnedHandler = stubPinnedHandler{}

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	// Use a short client timeout; the handler's 30s modelsTimeout will also
	// fire eventually, but we don't want to wait that long. A client-side
	// cancellation propagates through r.Context() → the 30s child context →
	// the slowModelLister, exercising the timeout/cancellation path.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxySrv.URL+"/v1/models", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Client timeout is expected — the slow lister never returns.
		t.Logf("client error (expected): %v", err)
		return
	}
	defer resp.Body.Close()

	// If the handler managed to respond before the client timed out,
	// it should have returned an empty list (the slow lister was cancelled).
	t.Logf("status=%d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var result struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	t.Logf("data_len=%d", len(result.Data))
	if len(result.Data) != 0 {
		t.Errorf("data len = %d, want 0 (slow provider should be skipped)", len(result.Data))
	}
}

// --------------------------------------------------------------------------
// /v1/tee/report endpoint
// --------------------------------------------------------------------------

func TestHandleReport_MissingParams(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/v1/tee/report")
	if err != nil {
		t.Fatalf("GET /v1/tee/report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleReport_NotFound(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/v1/tee/report?provider=venice&model=test-model")
	if err != nil {
		t.Fatalf("GET /v1/tee/report: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleReport_ReturnsCachedReport(t *testing.T) {
	// Set up upstream that returns a valid plaintext response.
	// After the first chat request the report is cached.
	var upstreamCalled bool
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nonStreamResponse("hi")))
	}))
	defer upstreamSrv.Close()

	attestSrv := makeAttestationServer(t, true)
	defer attestSrv.Close()

	// Config points attestation at attestSrv, but chat completions at upstreamSrv.
	// We can't easily split these with the current config model (BaseURL is shared),
	// so we test report caching by pre-seeding via a chat request.
	//
	// For this test the upstream model is upstream-model; we need the upstream
	// chat server to respond. We use a second provider "venice2" that uses
	// upstreamSrv as BaseURL (so /api/v1/chat/completions hits upstreamSrv).
	// The attestation fetch will try attestSrv.URL + "/api/v1/tee/attestation".
	// But we need the attestation call to also go to a server that handles it.
	// Use a combined server for simplicity.

	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			upstreamCalled = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse("hi")))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	// Make a chat request to populate the cache.
	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if !upstreamCalled {
		t.Fatal("upstream was not called")
	}

	// Now the cache should have a report for venice/test-model (no mapping).
	reportResp, err := http.Get(proxySrv.URL + "/v1/tee/report?provider=venice&model=test-model")
	if err != nil {
		t.Fatalf("GET /v1/tee/report: %v", err)
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
	if report.Provider != "venice" {
		t.Errorf("report.Provider = %q, want %q", report.Provider, "venice")
	}
	if report.Model != "test-model" {
		t.Errorf("report.Model = %q, want %q", report.Model, "test-model")
	}
}

// --------------------------------------------------------------------------
// Negative cache tests
// --------------------------------------------------------------------------

func TestNegativeCache503(t *testing.T) {
	// Attestation server returns 500 to trigger negative cache.
	attestSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server error"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	// First request: attestation fails → 502.
	resp1, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadGateway {
		t.Errorf("first request status = %d, want 502", resp1.StatusCode)
	}

	// Second request: negative cache → 503.
	resp2, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second request status = %d, want 503", resp2.StatusCode)
	}
}

// --------------------------------------------------------------------------
// Blocked attestation → 502 with report JSON
// --------------------------------------------------------------------------

func TestBlockedAttestation502(t *testing.T) {
	// Combined server handles both attestation and chat.
	// nonce_match is enforced; the attestation server does NOT echo the nonce,
	// so nonce_match will Fail. Since nonce_match is in Enforced, report.Blocked() = true.
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			// Return a mismatched nonce → nonce_match Fail.
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"verified": false,
				"nonce": "0000000000000000000000000000000000000000000000000000000000000000",
				"model": "upstream-model",
				"tee_provider": "TDX",
				"signing_key": %q,
				"intel_quote": "",
				"nvidia_payload": ""
			}`, modelPubKeyHex())
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{"nonce_match"},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var report attestation.VerificationReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatalf("decode report from 502 body: %v", err)
	}
	if !report.Blocked() {
		t.Error("report.Blocked() = false, want true")
	}
}

// --------------------------------------------------------------------------
// Plaintext non-streaming (E2EE false or tdx_reportdata_binding fails)
// --------------------------------------------------------------------------

func TestPlaintextNonStream(t *testing.T) {
	const wantContent = "Hello, world!"

	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse(wantContent)))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false, // plaintext
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	got := extractMessageContent(t, body)
	if got != wantContent {
		t.Errorf("content = %q, want %q", got, wantContent)
	}
}

func TestPlaintextStreaming(t *testing.T) {
	const wantContent = "streaming text"

	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write([]byte(streamSSE(wantContent)))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", true)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	chunks := readSSEChunks(t, resp.Body)
	if len(chunks) == 0 {
		t.Fatal("no SSE chunks received")
	}
	// The first chunk has role only; the second has content.
	var got string
	var gotSb782 strings.Builder
	for _, c := range chunks {
		gotSb782.WriteString(extractDeltaContent(t, c))
	}
	got += gotSb782.String()
	if got != wantContent {
		t.Errorf("aggregated content = %q, want %q", got, wantContent)
	}
}

// --------------------------------------------------------------------------
// E2EE streaming (happy path)
// --------------------------------------------------------------------------

// makeE2EEConfig returns a config pointing at the given base URL with E2EE
// enabled. tdx_reportdata_binding is NOT in Enforced (it will Fail since we
// don't have a real TDX quote, but we need E2EE to work in tests). We
// override reportdata handling by not enforcing it, and force E2EE by
// making reportdataBindingPassed return true when the factor passes.
//
// Since we can't pass a real TDX quote in tests, tdx_reportdata_binding will
// always Fail. That means E2EE will be disabled by the proxy's safety check.
// To test E2EE in unit tests without a real TDX environment, we need a way
// to override this check.
//
// Solution: inject a fake attestation that has tdx_reportdata_binding Pass.
// We can do this by returning an IntelQuote that is not empty but also not
// a valid TDX quote, causing VerifyTDXQuote to fail at ParseErr, which makes
// tdx_reportdata_binding Fail. This means we cannot test the full E2EE path
// through the proxy without a real TDX environment.
//
// Instead, we test the E2EE path using a custom attester that bypasses the
// proxy's attestation fetch and injects a pre-built VerificationReport with
// tdx_reportdata_binding Passing.
//
// Since proxy.Server's attestation is fetched via prov.Attester.FetchAttestation
// and the report is built via attestation.BuildReport, the only way to inject
// a passing tdx_reportdata_binding in a test is to provide a real TDX quote or
// to use the proxy's internal test hooks.
//
// For E2EE tests we use a different approach: we construct a combined server
// that returns a valid-looking attestation with a real REPORTDATA binding by
// computing SHA-256(signingKey || nonce) correctly. The proxy will call
// VerifyTDXQuote which will fail to parse our fake base64 quote with ParseErr.
// So tdx_reportdata_binding will still Fail.
//
// The conclusion: full E2EE integration requires real TDX hardware. We test the
// decrypt functions directly and test the proxy with E2EE disabled.
// See TestDecryptSSEChunk and TestDecryptNonStreamResponse below.

// TestE2EERefusesPlaintextFallback verifies the proxy refuses to send a
// plaintext request when E2EE is configured but tdx_reportdata_binding fails.
func TestE2EERefusesPlaintextFallback(t *testing.T) {
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse("should not reach here")))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    true, // E2EE requested but reportdata binding will fail
			},
		},
		// tdx_reportdata_binding is not enforced, but E2EE must still refuse
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 500; body=%s", resp.StatusCode, body)
	}
}

// --------------------------------------------------------------------------
// Upstream response forwarding
// --------------------------------------------------------------------------

func TestUpstreamNon200Forwarded(t *testing.T) {
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", resp.StatusCode)
	}
}

// --------------------------------------------------------------------------
// Model resolution across providers
// --------------------------------------------------------------------------

func TestSinglePinnedProvider_AllowsDynamicModelName(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	prov := srv.ProviderByName("neardirect")
	if prov == nil {
		t.Fatal("neardirect provider missing")
	}

	// Avoid network dependency: stub pinned chat handler.
	prov.PinnedHandler = stubPinnedHandler{}

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "zai-org/GLM-5-FP8", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func TestPinnedProvider_BlockedReportReturns502(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	prov := srv.ProviderByName("neardirect")
	if prov == nil {
		t.Fatal("neardirect provider missing")
	}
	prov.PinnedHandler = blockedPinnedHandler{}

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 502; body=%s", resp.StatusCode, body)
	}

	var report attestation.VerificationReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if !report.Blocked() {
		t.Fatal("report.Blocked() = false, want true")
	}
}

// --------------------------------------------------------------------------
// SSE parsing edge cases
// --------------------------------------------------------------------------

func TestSSEMultipleChunks(t *testing.T) {
	// Verify the proxy correctly relays multiple SSE chunks.
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)

			chunks := []string{"Hello", ", ", "world", "!"}
			for _, c := range chunks {
				line := fmt.Sprintf(`{"id":"c","choices":[{"delta":{"content":%q},"index":0}]}`, c)
				fmt.Fprintf(w, "data: %s\n\n", line)
				flusher.Flush()
			}
			fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", true)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	chunks := readSSEChunks(t, resp.Body)
	var got string
	var gotSb1131 strings.Builder
	for _, c := range chunks {
		gotSb1131.WriteString(extractDeltaContent(t, c))
	}
	got += gotSb1131.String()
	want := "Hello, world!"
	if got != want {
		t.Errorf("aggregated content = %q, want %q", got, want)
	}
}

// --------------------------------------------------------------------------
// Attestation cache: second request uses cached report
// --------------------------------------------------------------------------

func TestAttestationCacheHit(t *testing.T) {
	attestCalls := 0
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			attestCalls++
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse("hi")))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	for i := range 3 {
		resp, err := postChat(t, proxySrv.URL, "test-model", false)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	// Attestation should only be called once; the cache handles the rest.
	if attestCalls != 1 {
		t.Errorf("attestation called %d times, want 1 (cache miss on first, hits thereafter)", attestCalls)
	}
}

// --------------------------------------------------------------------------
// Model name rewriting
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Decryption unit tests (decrypt.go)
// --------------------------------------------------------------------------

// TestE2EEStreamingRefusesPlaintext verifies the proxy refuses to fall back to
// plaintext streaming when E2EE is configured but binding fails.
func TestE2EEStreamingRefusesPlaintext(t *testing.T) {
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(streamSSE("should not reach here")))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    true, // E2EE requested; will refuse due to no real TDX
			},
		},
		Enforced: []string{}, // no enforced factors → but E2EE still refuses plaintext
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", true)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 500; body=%s", resp.StatusCode, body)
	}
}

// TestDecryptChunkFunctions tests decryptSSEChunk and decryptNonStreamResponse
// by calling the proxy's streaming and non-streaming relay paths with
// pre-encrypted data.
//
// We do this by having the proxy in plaintext mode receive already-encrypted
// content (as if the upstream sent ciphertext without E2EE being active in the
// proxy). This confirms the relay correctly passes content through unchanged.
func TestPlaintextPassthrough_PreservesCiphertext(t *testing.T) {
	// Generate a test session whose public key we use to encrypt a test payload.
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	enc, err := attestation.Encrypt([]byte("secret"), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The proxy in plaintext mode should pass ciphertext through unchanged.
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse(enc)))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false, // plaintext mode
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	got := extractMessageContent(t, body)
	// Proxy should pass through the ciphertext unchanged.
	if got != enc {
		t.Errorf("ciphertext not preserved; got len %d, want len %d", len(got), len(enc))
	}
}

// --------------------------------------------------------------------------
// Internal decryption function tests (white-box via package-level funcs)
// --------------------------------------------------------------------------

// TestDecryptSSEChunk_RoundTrip exercises decryptSSEChunk via the streaming
// relay by serving encrypted SSE from the upstream and verifying the proxy
// decrypts it correctly.
//
// This requires E2EE to be active. Since we cannot produce a real TDX quote,
// we test this by directly testing the decrypt package functions.
// The following tests call the exported functions from the attestation package
// to verify the decryption logic is correct end-to-end.

func TestAttestationEncryptDecryptRoundTrip(t *testing.T) {
	// This test verifies the underlying crypto used by the proxy.
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	want := "Hello, proxy!"
	enc, err := attestation.Encrypt([]byte(want), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !attestation.IsEncryptedChunk(enc) {
		t.Error("IsEncryptedChunk returned false for valid ciphertext")
	}

	got, err := attestation.Decrypt(enc, session.PrivateKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != want {
		t.Errorf("decrypted = %q, want %q", got, want)
	}
}

// --------------------------------------------------------------------------
// reassembleNonStream (E2EE non-streaming path)
// --------------------------------------------------------------------------

func TestReassembleNonStream(t *testing.T) {
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Encrypt two content chunks using the session's public key (simulating
	// what the upstream TEE would do).
	enc1, err := attestation.Encrypt([]byte("Hello, "), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt chunk 1: %v", err)
	}
	enc2, err := attestation.Encrypt([]byte("world!"), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt chunk 2: %v", err)
	}

	// Build an SSE body with encrypted content in each chunk.
	var sse strings.Builder
	fmt.Fprintf(&sse, "data: %s\n\n", fmt.Sprintf(
		`{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":%q},"finish_reason":null}]}`,
		enc1,
	))
	fmt.Fprintf(&sse, "data: %s\n\n", fmt.Sprintf(
		`{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"content":%q},"finish_reason":null}]}`,
		enc2,
	))
	fmt.Fprintf(&sse, "data: [DONE]\n\n")

	result, err := proxy.ReassembleNonStream(strings.NewReader(sse.String()), session)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}

	t.Logf("result: %s", result)

	got := extractMessageContent(t, result)
	want := "Hello, world!"
	if got != want {
		t.Errorf("content = %q, want %q", got, want)
	}

	// Verify it's a proper non-streaming response shape.
	var resp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Index        int    `json:"index"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Object != "chat.completion" {
		t.Errorf("object = %q, want %q", resp.Object, "chat.completion")
	}
	if resp.ID != "chatcmpl-abc" {
		t.Errorf("id = %q, want %q", resp.ID, "chatcmpl-abc")
	}
	if resp.Model != "test-model" {
		t.Errorf("model = %q, want %q", resp.Model, "test-model")
	}
	if len(resp.Choices) != 1 || resp.Choices[0].FinishReason != "stop" {
		t.Errorf("choices = %+v, want 1 choice with finish_reason=stop", resp.Choices)
	}
}

func TestReassembleNonStream_WithReasoning(t *testing.T) {
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Encrypt content and reasoning chunks separately.
	encThink1, err := attestation.Encrypt([]byte("Let me "), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt think1: %v", err)
	}
	encThink2, err := attestation.Encrypt([]byte("think..."), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt think2: %v", err)
	}
	encContent, err := attestation.Encrypt([]byte("Hello!"), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt content: %v", err)
	}

	// Build SSE: two reasoning chunks, then one content chunk.
	var sse strings.Builder
	fmt.Fprintf(&sse, "data: %s\n\n", fmt.Sprintf(
		`{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","reasoning":%q},"finish_reason":null}]}`,
		encThink1,
	))
	fmt.Fprintf(&sse, "data: %s\n\n", fmt.Sprintf(
		`{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"reasoning":%q},"finish_reason":null}]}`,
		encThink2,
	))
	fmt.Fprintf(&sse, "data: %s\n\n", fmt.Sprintf(
		`{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"content":%q},"finish_reason":null}]}`,
		encContent,
	))
	fmt.Fprintf(&sse, "data: [DONE]\n\n")

	result, err := proxy.ReassembleNonStream(strings.NewReader(sse.String()), session)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}

	t.Logf("result: %s", result)

	// Parse and verify both fields present in message.
	var parsed struct {
		Choices []struct {
			Message struct {
				Role      string `json:"role"`
				Content   string `json:"content"`
				Reasoning string `json:"reasoning"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Choices) == 0 {
		t.Fatal("no choices")
	}
	msg := parsed.Choices[0].Message
	if msg.Role != "assistant" {
		t.Errorf("role = %q, want %q", msg.Role, "assistant")
	}
	if msg.Content != "Hello!" {
		t.Errorf("content = %q, want %q", msg.Content, "Hello!")
	}
	if msg.Reasoning != "Let me think..." {
		t.Errorf("reasoning = %q, want %q", msg.Reasoning, "Let me think...")
	}
}

// --------------------------------------------------------------------------
// Upstream body drain on non-200
// --------------------------------------------------------------------------

func TestUpstreamBodyDrained(t *testing.T) {
	// Verify the proxy drains the upstream body even on error responses.
	// If the body is not drained, the connection is not reused and can deadlock.
	drainCh := make(chan struct{})
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(bytes.Repeat([]byte("x"), 64*1024))
			close(drainCh)
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	// Drain proxy response.
	_, _ = io.ReadAll(resp.Body)

	// If drain didn't happen, this would timeout.
	select {
	case <-drainCh:
		// good
	case <-time.After(5 * time.Second):
		t.Error("upstream body was not drained")
	}
}

// --------------------------------------------------------------------------
// SSE scan large chunks
// --------------------------------------------------------------------------

func TestSSELargeChunk(t *testing.T) {
	// Verify the 1 MiB scanner buffer handles large SSE chunks.
	largeContent := strings.Repeat("x", 512*1024) // 512 KiB

	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(streamSSE(largeContent)))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", true)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}

	chunks := readSSEChunks(t, resp.Body)
	var got string
	var gotSb1568 strings.Builder
	for _, c := range chunks {
		gotSb1568.WriteString(extractDeltaContent(t, c))
	}
	got += gotSb1568.String()
	if got != largeContent {
		t.Errorf("content length = %d, want %d", len(got), len(largeContent))
	}
}

// --------------------------------------------------------------------------
// AuthorizationHeader is set in plaintext path via Venice Preparer
// --------------------------------------------------------------------------

// TestAuthorizationHeaderSetViaVenicePreparer verifies that on the plaintext
// path the proxy still injects the Authorization header. For Venice in plaintext
// mode, buildUpstreamBody returns session=nil, so prepareUpstreamHeaders falls
// through to the manual header-set path which uses prov.APIKey directly.
func TestAuthorizationHeaderSetViaVenicePreparer(t *testing.T) {
	var gotAuth string
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse("ok")))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "secret-key",
				E2EE:    false, // plaintext path
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}

	// On the plaintext path, Venice's Preparer is NOT called (it requires a full
	// session), so the proxy sets Authorization directly from prov.APIKey.
	if gotAuth != "Bearer secret-key" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer secret-key")
	}
}

// --------------------------------------------------------------------------
// SafePrefix
// --------------------------------------------------------------------------

func TestSafePrefix(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"short", "abc", 5, "abc"},
		{"exact", "abcde", 5, "abcde"},
		{"long", "abcdefgh", 5, "abcde"},
		{"empty", "", 5, ""},
		{"zero_n", "abc", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := proxy.SafePrefix(tc.s, tc.n)
			if got != tc.want {
				t.Errorf("SafePrefix(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// DecryptSSEChunk
// --------------------------------------------------------------------------

func TestDecryptSSEChunk(t *testing.T) {
	// Create a session and encrypt some content using the session's own pubkey.
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	plaintext := "Hello, SSE!"
	enc, err := attestation.Encrypt([]byte(plaintext), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("decrypt_success", func(t *testing.T) {
		chunk := fmt.Sprintf(`{"id":"c1","choices":[{"delta":{"content":%q},"index":0}]}`, enc)
		got, err := proxy.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}

		content := extractDeltaContent(t, got)
		if content != plaintext {
			t.Errorf("content = %q, want %q", content, plaintext)
		}
	})

	t.Run("empty_delta_passthrough", func(t *testing.T) {
		chunk := `{"id":"c1","choices":[{"delta":{"role":"assistant"},"index":0}]}`
		got, err := proxy.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}
		if got != chunk {
			t.Errorf("expected passthrough for empty delta, got %q", got)
		}
	})

	t.Run("no_choices_passthrough", func(t *testing.T) {
		chunk := `{"id":"c1","usage":{"prompt_tokens":5}}`
		got, err := proxy.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}
		if got != chunk {
			t.Errorf("expected passthrough for no choices, got %q", got)
		}
	})

	t.Run("non_encrypted_content_errors", func(t *testing.T) {
		chunk := `{"id":"c1","choices":[{"delta":{"content":"plain text"},"index":0}]}`
		_, err := proxy.DecryptSSEChunk(chunk, session)
		if err == nil {
			t.Fatal("expected error for non-encrypted content")
		}
		t.Logf("got expected error: %v", err)
	})

	t.Run("invalid_json_errors", func(t *testing.T) {
		_, err := proxy.DecryptSSEChunk("not json", session)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("reasoning_decrypted", func(t *testing.T) {
		reasoning := "Let me think..."
		encReasoning, err := attestation.Encrypt([]byte(reasoning), session.PrivateKey.PubKey())
		if err != nil {
			t.Fatalf("Encrypt reasoning: %v", err)
		}

		chunk := fmt.Sprintf(`{"id":"c1","choices":[{"delta":{"reasoning":%q},"index":0}]}`, encReasoning)
		got, err := proxy.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}

		// Parse and check reasoning was decrypted.
		var parsed struct {
			Choices []struct {
				Delta struct {
					Reasoning string `json:"reasoning"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(parsed.Choices) == 0 {
			t.Fatal("no choices in result")
		}
		if parsed.Choices[0].Delta.Reasoning != reasoning {
			t.Errorf("reasoning = %q, want %q", parsed.Choices[0].Delta.Reasoning, reasoning)
		}
	})

	t.Run("content_and_reasoning_both_decrypted", func(t *testing.T) {
		contentText := "Hello!"
		reasoningText := "I should say hello."
		encContent, err := attestation.Encrypt([]byte(contentText), session.PrivateKey.PubKey())
		if err != nil {
			t.Fatalf("Encrypt content: %v", err)
		}
		encReasoning, err := attestation.Encrypt([]byte(reasoningText), session.PrivateKey.PubKey())
		if err != nil {
			t.Fatalf("Encrypt reasoning: %v", err)
		}

		chunk := fmt.Sprintf(`{"id":"c1","choices":[{"delta":{"content":%q,"reasoning":%q},"index":0}]}`, encContent, encReasoning)
		got, err := proxy.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}

		var parsed struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					Reasoning string `json:"reasoning"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(parsed.Choices) == 0 {
			t.Fatal("no choices in result")
		}
		if parsed.Choices[0].Delta.Content != contentText {
			t.Errorf("content = %q, want %q", parsed.Choices[0].Delta.Content, contentText)
		}
		if parsed.Choices[0].Delta.Reasoning != reasoningText {
			t.Errorf("reasoning = %q, want %q", parsed.Choices[0].Delta.Reasoning, reasoningText)
		}
	})
}

// --------------------------------------------------------------------------
// DecryptNonStreamResponse
// --------------------------------------------------------------------------

func TestDecryptNonStreamResponse(t *testing.T) {
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	plaintext := "Hello, non-stream!"
	enc, err := attestation.Encrypt([]byte(plaintext), session.PrivateKey.PubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("decrypt_success", func(t *testing.T) {
		body := []byte(nonStreamResponse(enc))
		got, err := proxy.DecryptNonStreamResponse(body, session)
		if err != nil {
			t.Fatalf("DecryptNonStreamResponse: %v", err)
		}

		content := extractMessageContent(t, got)
		if content != plaintext {
			t.Errorf("content = %q, want %q", content, plaintext)
		}
	})

	t.Run("no_choices_passthrough", func(t *testing.T) {
		body := []byte(`{"id":"c1","usage":{"prompt_tokens":5}}`)
		got, err := proxy.DecryptNonStreamResponse(body, session)
		if err != nil {
			t.Fatalf("DecryptNonStreamResponse: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("expected passthrough for no choices")
		}
	})

	t.Run("empty_content_passthrough", func(t *testing.T) {
		body := []byte(nonStreamResponse(""))
		got, err := proxy.DecryptNonStreamResponse(body, session)
		if err != nil {
			t.Fatalf("DecryptNonStreamResponse: %v", err)
		}
		content := extractMessageContent(t, got)
		if content != "" {
			t.Errorf("content = %q, want empty", content)
		}
	})

	t.Run("non_encrypted_content_errors", func(t *testing.T) {
		body := []byte(nonStreamResponse("plain text"))
		_, err := proxy.DecryptNonStreamResponse(body, session)
		if err == nil {
			t.Fatal("expected error for non-encrypted content")
		}
		t.Logf("got expected error: %v", err)
	})

	t.Run("invalid_json_errors", func(t *testing.T) {
		_, err := proxy.DecryptNonStreamResponse([]byte("not json"), session)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("reasoning_decrypted", func(t *testing.T) {
		reasoning := "Thinking about it..."
		encReasoning, err := attestation.Encrypt([]byte(reasoning), session.PrivateKey.PubKey())
		if err != nil {
			t.Fatalf("Encrypt reasoning: %v", err)
		}

		body := fmt.Sprintf(`{
			"id": "chatcmpl-test",
			"object": "chat.completion",
			"created": 1234567890,
			"model": "test-model",
			"choices": [{"index":0,"message":{"role":"assistant","content":%q,"reasoning":%q},"finish_reason":"stop"}]
		}`, enc, encReasoning)
		got, err := proxy.DecryptNonStreamResponse([]byte(body), session)
		if err != nil {
			t.Fatalf("DecryptNonStreamResponse: %v", err)
		}

		var parsed struct {
			Choices []struct {
				Message struct {
					Content   string `json:"content"`
					Reasoning string `json:"reasoning"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(got, &parsed); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(parsed.Choices) == 0 {
			t.Fatal("no choices")
		}
		if parsed.Choices[0].Message.Content != plaintext {
			t.Errorf("content = %q, want %q", parsed.Choices[0].Message.Content, plaintext)
		}
		if parsed.Choices[0].Message.Reasoning != reasoning {
			t.Errorf("reasoning = %q, want %q", parsed.Choices[0].Message.Reasoning, reasoning)
		}
	})
}

func TestNewUnknownProviderError(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"badprovider": {
				Name:    "badprovider",
				BaseURL: "http://localhost",
				APIKey:  "key",
			},
		},
	}
	_, err := proxy.New(cfg)
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("error should mention unknown provider: %v", err)
	}
}

// --------------------------------------------------------------------------
// PrepareUpstreamHeaders
// --------------------------------------------------------------------------

type mockPreparer struct {
	called bool
	apiKey string
}

func (m *mockPreparer) PrepareRequest(req *http.Request, _ *attestation.Session) error {
	m.called = true
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	return nil
}

func TestPrepareUpstreamHeaders_NilSession(t *testing.T) {
	prov := &provider.Provider{
		Name:   "test",
		APIKey: "secret-key",
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := proxy.PrepareUpstreamHeaders(req, prov, nil); err != nil {
		t.Fatalf("PrepareUpstreamHeaders: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer secret-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer secret-key")
	}
}

func TestPrepareUpstreamHeaders_NilSessionEmptyKey(t *testing.T) {
	prov := &provider.Provider{
		Name: "test",
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := proxy.PrepareUpstreamHeaders(req, prov, nil); err != nil {
		t.Fatalf("PrepareUpstreamHeaders: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty with no APIKey, got %q", got)
	}
}

func TestPrepareUpstreamHeaders_WithSession(t *testing.T) {
	mock := &mockPreparer{apiKey: "prepared-key"}
	prov := &provider.Provider{
		Name:     "test",
		APIKey:   "fallback-key",
		Preparer: mock,
	}

	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := proxy.PrepareUpstreamHeaders(req, prov, session); err != nil {
		t.Fatalf("PrepareUpstreamHeaders: %v", err)
	}

	if !mock.called {
		t.Error("Preparer.PrepareRequest was not called")
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer prepared-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer prepared-key")
	}
}

// --------------------------------------------------------------------------
// relayStream tests
// --------------------------------------------------------------------------

// newMinimalServer creates a minimal proxy.Server for testing relay methods.
func newMinimalServer(t *testing.T) *proxy.Server {
	t.Helper()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "http://localhost",
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return srv
}

func TestRelayStream_EmptyBody(t *testing.T) {
	srv := newMinimalServer(t)
	rec := httptest.NewRecorder()

	srv.RelayStream(rec, strings.NewReader(""), nil)

	t.Logf("status: %d, body: %q", rec.Code, rec.Body.String())
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "empty upstream stream") {
		t.Errorf("body = %q, want 'empty upstream stream'", rec.Body.String())
	}
}

func TestRelayStream_NonDataLines(t *testing.T) {
	srv := newMinimalServer(t)
	rec := httptest.NewRecorder()

	// SSE with a comment line, a non-data event, then a data chunk and DONE.
	body := ": this is a comment\nevent: heartbeat\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
	srv.RelayStream(rec, strings.NewReader(body), nil)

	t.Logf("status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	output := rec.Body.String()
	t.Logf("output: %q", output)

	// Comment should be relayed.
	if !strings.Contains(output, ": this is a comment") {
		t.Error("comment line not relayed")
	}
	// Event line should be relayed.
	if !strings.Contains(output, "event: heartbeat") {
		t.Error("event line not relayed")
	}
	// Data chunk should be present.
	if !strings.Contains(output, "data: {\"choices\"") {
		t.Error("data chunk not relayed")
	}
	// DONE marker should be present.
	if !strings.Contains(output, "data: [DONE]") {
		t.Error("DONE marker not relayed")
	}
}

func TestRelayStream_PlaintextPassthrough(t *testing.T) {
	srv := newMinimalServer(t)
	rec := httptest.NewRecorder()

	body := streamSSE("hello world")
	srv.RelayStream(rec, strings.NewReader(body), nil)

	t.Logf("status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	chunks := readSSEChunks(t, strings.NewReader(rec.Body.String()))
	if len(chunks) != 1 {
		t.Fatalf("chunks = %d, want 1", len(chunks))
	}
	content := extractDeltaContent(t, chunks[0])
	t.Logf("content: %q", content)
	if content != "hello world" {
		t.Errorf("content = %q, want %q", content, "hello world")
	}
}

// --------------------------------------------------------------------------
// relayNonStream tests
// --------------------------------------------------------------------------

func TestRelayNonStream_NilSession(t *testing.T) {
	srv := newMinimalServer(t)
	rec := httptest.NewRecorder()

	body := nonStreamResponse("hello from upstream")
	srv.RelayNonStream(rec, strings.NewReader(body), nil)

	t.Logf("status: %d", rec.Code)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	content := extractMessageContent(t, rec.Body.Bytes())
	t.Logf("content: %q", content)
	if content != "hello from upstream" {
		t.Errorf("content = %q, want %q", content, "hello from upstream")
	}
}

func TestRelayReassembledNonStream_MalformedSSE(t *testing.T) {
	srv := newMinimalServer(t)
	rec := httptest.NewRecorder()

	// No valid SSE data lines — should fail during reassembly.
	srv.RelayReassembledNonStream(rec, strings.NewReader("not valid sse"), nil)

	t.Logf("status: %d, body: %q", rec.Code, rec.Body.String())
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --------------------------------------------------------------------------
// handleIndex tests
// --------------------------------------------------------------------------

func TestHandleIndex_Fresh(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	t.Logf("Content-Type: %s", ct)
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)
	t.Logf("response length: %d bytes", len(html))

	for _, want := range []string{"teep", "venice", "Provider", "Requests", "Attestation Cache"} {
		if !strings.Contains(html, want) {
			t.Errorf("response missing %q", want)
		}
	}
}

func TestHandleIndex_AfterRequest(t *testing.T) {
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			var n attestation.Nonce
			b, _ := hex.DecodeString(nonceHex)
			copy(n[:], b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(attestationJSON(n, true)))
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nonStreamResponse("hello")))
			return
		}
		http.NotFound(w, r)
	}))
	defer combined.Close()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: combined.URL,
				APIKey:  "key",
				E2EE:    false,
			},
		},
		Enforced: []string{},
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	// Make a chat request to populate stats.
	chatResp, err := postChat(t, proxySrv.URL, "test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	_, _ = io.ReadAll(chatResp.Body)
	chatResp.Body.Close()
	t.Logf("chat response status: %d", chatResp.StatusCode)

	// Now GET / and verify stats are reflected.
	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)
	t.Logf("index page length: %d bytes", len(html))

	// Should show model name in the models table.
	if !strings.Contains(html, "test-model") {
		t.Error("index page missing model name 'test-model' after request")
	}
}

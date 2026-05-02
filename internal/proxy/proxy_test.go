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
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/e2ee"
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

// signingKeyPinnedHandler returns a signing key on first call (cache miss)
// and no report on subsequent calls (simulating SPKI cache hits). It records
// the SigningKey from PinnedRequest to verify the proxy passes cached keys.
type signingKeyPinnedHandler struct {
	key          string
	calls        int
	lastReqSKKey string
}

func (h *signingKeyPinnedHandler) HandlePinned(_ context.Context, req *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	h.calls++
	h.lastReqSKKey = req.SigningKey
	body := io.NopCloser(strings.NewReader(nonStreamResponse("ok")))
	if h.calls == 1 {
		// First call: SPKI cache miss → return report + signing key.
		return &provider.PinnedResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       body,
			SigningKey: h.key,
			Report: &attestation.VerificationReport{
				Provider: "neardirect",
				Model:    "test-model",
				Factors: []attestation.FactorResult{
					{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
					{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "binding ok"},
				},
			},
		}, nil
	}
	// Subsequent calls: SPKI cache hit → no report, no signing key from handler.
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}, nil
}

// blockedThenOKPinnedHandler returns blocked on first call, then OK on subsequent calls.
type blockedThenOKPinnedHandler struct {
	calls int
}

func (h *blockedThenOKPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	h.calls++
	if h.calls == 1 {
		return &provider.PinnedResponse{
			StatusCode: http.StatusBadGateway,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Report: &attestation.VerificationReport{
				Provider: "neardirect",
				Model:    "test-model",
				Factors: []attestation.FactorResult{
					{Name: "nonce_match", Status: attestation.Fail, Enforced: true, Detail: "mismatch"},
				},
			},
		}, nil
	}
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(nonStreamResponse("recovered"))),
		Report: &attestation.VerificationReport{
			Provider: "neardirect",
			Model:    "test-model",
			Factors: []attestation.FactorResult{
				{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			},
		},
	}, nil
}

// reportDataFailPinnedHandler returns a passing report where
// tdx_reportdata_binding fails. Used for E2EE cache checks.
type reportDataFailPinnedHandler struct {
	calls int
}

func (h *reportDataFailPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	h.calls++
	body := io.NopCloser(strings.NewReader(nonStreamResponse("ok")))
	if h.calls == 1 {
		// First call: return report (cache miss), reportdata binding fails.
		return &provider.PinnedResponse{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       body,
			Report: &attestation.VerificationReport{
				Provider: "neardirect",
				Model:    "test-model",
				Factors: []attestation.FactorResult{
					{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
					{Name: "tdx_reportdata_binding", Status: attestation.Fail, Detail: "binding mismatch"},
				},
			},
		}, nil
	}
	// Second call: SPKI hit → no report (proxy uses cached).
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
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
		AllowFail: allowFailExcept("nonce_match", "tdx_debug_disabled", "signing_key_present", "tdx_reportdata_binding"),
	}
}

// allowFailExcept returns KnownFactors minus the given names, producing an
// AllowFail list that enforces only the excluded factors.
func allowFailExcept(exclude ...string) []string {
	ex := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		ex[n] = true
	}
	var out []string
	for _, n := range attestation.KnownFactors {
		if !ex[n] {
			out = append(out, n)
		}
	}
	return out
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
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(chunkJSON), &chunk); err != nil {
		t.Fatalf("unmarshal SSE chunk: %v", err)
	}
	if len(chunk.Choices) == 0 {
		return ""
	}
	// Thinking models (e.g. Qwen3.5) emit reasoning in reasoning_content
	// and may leave content empty. Fall back so callers see useful text.
	if c := chunk.Choices[0].Delta.Content; c != "" {
		return c
	}
	return chunk.Choices[0].Delta.ReasoningContent
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

// pathCapturingPinnedHandler records the PinnedRequest.Path from each call
// and returns a stub OK response.
type pathCapturingPinnedHandler struct {
	mu   sync.Mutex
	path string
}

func (h *pathCapturingPinnedHandler) HandlePinned(_ context.Context, req *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	h.mu.Lock()
	h.path = req.Path
	h.mu.Unlock()
	body := io.NopCloser(strings.NewReader(`{"object":"list","data":[{"object":"embedding","embedding":[0.1],"index":0}],"model":"test-model","usage":{"prompt_tokens":5,"total_tokens":5}}`))
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
		Report: &attestation.VerificationReport{
			Provider: "neardirect",
			Model:    "test-model",
			Factors: []attestation.FactorResult{
				{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			},
		},
	}, nil
}

// newNeardirectProxyServer creates a neardirect-backed proxy server with all
// endpoint paths wired and a stub PinnedHandler attached.
func newNeardirectProxyServer(t *testing.T, handler provider.PinnedHandler) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
			},
		},
		AllowFail: attestation.KnownFactors,
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("neardirect")
	prov.PinnedHandler = handler
	return httptest.NewServer(srv)
}

// sessionPinnedHandler returns a non-nil Session in PinnedResponse, simulating
// an upstream that returned E2EE-encrypted data on a non-chat endpoint.
type sessionPinnedHandler struct{}

// fakeDecryptor satisfies e2ee.Decryptor for testing.
type fakeDecryptor struct{}

func (fakeDecryptor) IsEncryptedChunk(string) bool   { return false }
func (fakeDecryptor) Decrypt(string) ([]byte, error) { return nil, errors.New("fake") }
func (fakeDecryptor) Zero()                          {}

func (sessionPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	body := io.NopCloser(strings.NewReader(`{"data":"encrypted"}`))
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
		Session:    fakeDecryptor{},
		Report: &attestation.VerificationReport{
			Provider: "neardirect",
			Model:    "test-model",
			Factors: []attestation.FactorResult{
				{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			},
		},
	}, nil
}

// --------------------------------------------------------------------------
// Embeddings endpoint tests
// --------------------------------------------------------------------------

func TestEmbeddings_MissingModel400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/embeddings", "application/json",
		strings.NewReader(`{"input":"hello"}`))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestEmbeddings_InvalidJSON400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/embeddings", "application/json",
		strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestEmbeddings_PinnedOK(t *testing.T) {
	handler := &pathCapturingPinnedHandler{}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/embeddings", "application/json",
		strings.NewReader(`{"model":"neardirect:test-model","input":"hello"}`))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	handler.mu.Lock()
	gotPath := handler.path
	handler.mu.Unlock()
	if gotPath != "/v1/embeddings" {
		t.Errorf("PinnedRequest.Path = %q, want /v1/embeddings", gotPath)
	}
}

func TestEmbeddings_ProviderDoesNotSupport400(t *testing.T) {
	// Venice has no EmbeddingsPath set.
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/embeddings", "application/json",
		strings.NewReader(`{"model":"test-model","input":"hello"}`))
	if err != nil {
		t.Fatalf("POST embeddings: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

// --------------------------------------------------------------------------
// Images endpoint tests
// --------------------------------------------------------------------------

func TestImages_MissingModel400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/images/generations", "application/json",
		strings.NewReader(`{"prompt":"a cat"}`))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImages_InvalidJSON400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/images/generations", "application/json",
		strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestImages_PinnedOK(t *testing.T) {
	handler := &pathCapturingPinnedHandler{}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/images/generations", "application/json",
		strings.NewReader(`{"model":"neardirect:test-model","prompt":"a cat","n":1}`))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	handler.mu.Lock()
	gotPath := handler.path
	handler.mu.Unlock()
	if gotPath != "/v1/images/generations" {
		t.Errorf("PinnedRequest.Path = %q, want /v1/images/generations", gotPath)
	}
}

func TestImages_PinnedE2EESessionRelayed(t *testing.T) {
	// When a pinned non-chat endpoint returns an E2EE session, the proxy
	// decrypts the response via RelayNonStream and forwards to the client.
	// fakeDecryptor.IsEncryptedChunk returns false, so the body passes through.
	proxySrv := newNeardirectProxyServer(t, sessionPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/images/generations", "application/json",
		strings.NewReader(`{"model":"neardirect:test-model","prompt":"a cat","n":1}`))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

func TestImages_ProviderDoesNotSupport400(t *testing.T) {
	// Venice has no ImagesPath set.
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/images/generations", "application/json",
		strings.NewReader(`{"model":"test-model","prompt":"a cat"}`))
	if err != nil {
		t.Fatalf("POST images: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

// headerPinnedHandler returns upstream response headers alongside the body,
// allowing tests to verify the proxy forwards them to the client.
type headerPinnedHandler struct {
	extraHeaders http.Header
}

func (h headerPinnedHandler) HandlePinned(_ context.Context, _ *provider.PinnedRequest) (*provider.PinnedResponse, error) {
	hdr := http.Header{"Content-Type": []string{"application/json"}}
	maps.Copy(hdr, h.extraHeaders)
	body := io.NopCloser(strings.NewReader(`{"data":"ok"}`))
	return &provider.PinnedResponse{
		StatusCode: http.StatusOK,
		Header:     hdr,
		Body:       body,
		Report: &attestation.VerificationReport{
			Provider: "neardirect",
			Model:    "test-model",
			Factors: []attestation.FactorResult{
				{Name: "nonce_match", Status: attestation.Pass, Detail: "match"},
			},
		},
	}, nil
}

func TestNonChat_PinnedOK_ForwardsUpstreamHeaders(t *testing.T) {
	// Regression: handlePinnedNonChat must forward upstream response headers
	// (rate-limit, request IDs, etc.) to the client, matching handlePinnedChat.
	handler := headerPinnedHandler{
		extraHeaders: http.Header{
			"X-Request-Id":          []string{"req-abc-123"},
			"X-Ratelimit-Remaining": []string{"42"},
		},
	}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	endpoints := []struct {
		path string
		body string
	}{
		{"/v1/embeddings", `{"model":"neardirect:test-model","input":"hello"}`},
		{"/v1/images/generations", `{"model":"neardirect:test-model","prompt":"a cat","n":1}`},
	}
	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			resp, err := http.Post(proxySrv.URL+ep.path, "application/json",
				strings.NewReader(ep.body))
			if err != nil {
				t.Fatalf("POST %s: %v", ep.path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
			}

			if got := resp.Header.Get("X-Request-Id"); got != "req-abc-123" {
				t.Errorf("X-Request-Id = %q, want %q", got, "req-abc-123")
			}
			if got := resp.Header.Get("X-Ratelimit-Remaining"); got != "42" {
				t.Errorf("X-Ratelimit-Remaining = %q, want %q", got, "42")
			}
		})
	}
}

// --------------------------------------------------------------------------
// Audio transcriptions endpoint tests
// --------------------------------------------------------------------------

func TestAudio_MissingModel400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	// Multipart form without model field.
	var buf bytes.Buffer
	buf.WriteString("--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\naudiodata\r\n--boundary--\r\n")
	resp, err := http.Post(proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary=boundary", &buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAudio_PinnedOK(t *testing.T) {
	handler := &pathCapturingPinnedHandler{}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	// Multipart form with model field.
	var buf bytes.Buffer
	buf.WriteString("--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nneardirect:test-model\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\naudiodata\r\n--boundary--\r\n")
	resp, err := http.Post(proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary=boundary", &buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	handler.mu.Lock()
	gotPath := handler.path
	handler.mu.Unlock()
	if gotPath != "/v1/audio/transcriptions" {
		t.Errorf("PinnedRequest.Path = %q, want /v1/audio/transcriptions", gotPath)
	}
}

func TestAudio_PinnedOK_FileBeforeModel(t *testing.T) {
	handler := &pathCapturingPinnedHandler{}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	// Multipart form with file field before model field (reversed order).
	var buf bytes.Buffer
	buf.WriteString("--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\naudiodata\r\n--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nneardirect:test-model\r\n--boundary--\r\n")
	resp, err := http.Post(proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary=boundary", &buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	handler.mu.Lock()
	gotPath := handler.path
	handler.mu.Unlock()
	if gotPath != "/v1/audio/transcriptions" {
		t.Errorf("PinnedRequest.Path = %q, want /v1/audio/transcriptions", gotPath)
	}
}

func TestAudio_ProviderDoesNotSupport400(t *testing.T) {
	// Venice has no AudioPath set.
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	var buf bytes.Buffer
	buf.WriteString("--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ntest-model\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\naudiodata\r\n--boundary--\r\n")
	resp, err := http.Post(proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary=boundary", &buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func TestAudio_NonPinnedE2EEFails400(t *testing.T) {
	// Chutes has E2EE=true and no PinnedHandler (app-layer E2EE).
	// Audio multipart must fail-closed for non-pinned E2EE.
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"chutes": {
				Name:    "chutes",
				BaseURL: "https://api.chutes.ai",
				APIKey:  "key",
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	// chutes has no AudioPath set by default, but force one to test the E2EE guard.
	prov := srv.ProviderByName("chutes")
	prov.AudioPath = "/v1/audio/transcriptions"

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	var buf bytes.Buffer
	buf.WriteString("--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ntest-model\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\naudiodata\r\n--boundary--\r\n")
	resp, err := http.Post(proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary=boundary", &buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func TestAudio_OversizedModelField400(t *testing.T) {
	// Regression: extractMultipartField must reject fields exceeding the size
	// limit instead of silently truncating them.
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	oversized := strings.Repeat("a", 1025)
	var buf bytes.Buffer
	buf.WriteString("--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n")
	buf.WriteString(oversized)
	buf.WriteString("\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.wav\"\r\nContent-Type: audio/wav\r\n\r\naudiodata\r\n--boundary--\r\n")
	resp, err := http.Post(proxySrv.URL+"/v1/audio/transcriptions",
		"multipart/form-data; boundary=boundary", &buf)
	if err != nil {
		t.Fatalf("POST audio: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

// --------------------------------------------------------------------------
// Rerank endpoint tests
// --------------------------------------------------------------------------

func TestRerank_MissingModel400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/rerank", "application/json",
		strings.NewReader(`{"query":"hello","documents":["a","b"]}`))
	if err != nil {
		t.Fatalf("POST rerank: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRerank_InvalidJSON400(t *testing.T) {
	proxySrv := newNeardirectProxyServer(t, stubPinnedHandler{})
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/rerank", "application/json",
		strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST rerank: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRerank_PinnedOK(t *testing.T) {
	handler := &pathCapturingPinnedHandler{}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/rerank", "application/json",
		strings.NewReader(`{"model":"neardirect:test-model","query":"hello","documents":["a","b"]}`))
	if err != nil {
		t.Fatalf("POST rerank: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	handler.mu.Lock()
	gotPath := handler.path
	handler.mu.Unlock()
	if gotPath != "/v1/rerank" {
		t.Errorf("PinnedRequest.Path = %q, want /v1/rerank", gotPath)
	}
}

func TestRerank_ProviderDoesNotSupport400(t *testing.T) {
	// Venice has no RerankPath set.
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/v1/rerank", "application/json",
		strings.NewReader(`{"model":"test-model","query":"hello","documents":["a","b"]}`))
	if err != nil {
		t.Fatalf("POST rerank: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

// --------------------------------------------------------------------------
// Embeddings negative cache hit returns 503
// --------------------------------------------------------------------------

func TestEmbeddings_NegativeCache503(t *testing.T) {
	handler := blockedPinnedHandler{}
	proxySrv := newNeardirectProxyServer(t, handler)
	defer proxySrv.Close()

	// First request: blocked attestation in pinned handler → 502.
	resp1, err := http.Post(proxySrv.URL+"/v1/embeddings", "application/json",
		strings.NewReader(`{"model":"neardirect:test-model","input":"hello"}`))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadGateway {
		t.Errorf("first request status = %d, want 502", resp1.StatusCode)
	}

	// Second request: negative cache → 503.
	resp2, err := http.Post(proxySrv.URL+"/v1/embeddings", "application/json",
		strings.NewReader(`{"model":"neardirect:test-model","input":"hello"}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second request status = %d, want 503", resp2.StatusCode)
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
	if !ids["venice:e2ee-test-model"] {
		t.Error("venice:e2ee-test-model not in response")
	}
	if !ids["venice:tee-test-model"] {
		t.Error("venice:tee-test-model not in response")
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
		AllowFail: attestation.KnownFactors,
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
		AllowFail: attestation.KnownFactors,
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
	if !ids["neardirect:model-a"] {
		t.Error("neardirect:model-a missing from response")
	}
	if !ids["nearcloud:model-b"] {
		t.Error("nearcloud:model-b missing from response")
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
		AllowFail: attestation.KnownFactors,
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	// Make a chat request to populate the cache.
	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
	resp1, err := postChat(t, proxySrv.URL, "venice:test-model", false)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadGateway {
		t.Errorf("first request status = %d, want 502", resp1.StatusCode)
	}

	// Second request: negative cache → 503.
	resp2, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
	// so nonce_match will Fail. Since nonce_match is not in AllowFail, report.Blocked() = true.
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
		AllowFail: allowFailExcept("nonce_match"),
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", true)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
		AllowFail: attestation.KnownFactors,
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

	resp, err := postChat(t, proxySrv.URL, "neardirect:zai-org/GLM-5-FP8", false)
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
		AllowFail: attestation.KnownFactors,
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

	resp, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", true)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	for i := range 3 {
		resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
		AllowFail: attestation.KnownFactors, // no enforced factors → but E2EE still refuses plaintext
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", true)
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
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	enc, err := e2ee.EncryptVenice([]byte("secret"), session.ClientPubKey())
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	want := "Hello, proxy!"
	enc, err := e2ee.EncryptVenice([]byte(want), session.ClientPubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !e2ee.IsEncryptedChunkVenice(enc) {
		t.Error("IsEncryptedChunk returned false for valid ciphertext")
	}

	got, err := session.Decrypt(enc)
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
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Encrypt two content chunks using the session's public key (simulating
	// what the upstream TEE would do).
	enc1, err := e2ee.EncryptVenice([]byte("Hello, "), session.ClientPubKey())
	if err != nil {
		t.Fatalf("Encrypt chunk 1: %v", err)
	}
	enc2, err := e2ee.EncryptVenice([]byte("world!"), session.ClientPubKey())
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

	result, ss, err := e2ee.ReassembleNonStream(strings.NewReader(sse.String()), session)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}

	t.Logf("result: %s (chunks=%d, tokens=%d, duration=%s)", result, ss.Chunks, ss.Tokens, ss.Duration)
	if ss.Chunks != 2 {
		t.Errorf("StreamStats.Chunks = %d, want 2", ss.Chunks)
	}
	if ss.Tokens != 0 {
		t.Errorf("StreamStats.Tokens = %d, want 0 (no usage event in fixture)", ss.Tokens)
	}

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
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Encrypt content and reasoning chunks separately.
	encThink1, err := e2ee.EncryptVenice([]byte("Let me "), session.ClientPubKey())
	if err != nil {
		t.Fatalf("Encrypt think1: %v", err)
	}
	encThink2, err := e2ee.EncryptVenice([]byte("think..."), session.ClientPubKey())
	if err != nil {
		t.Fatalf("Encrypt think2: %v", err)
	}
	encContent, err := e2ee.EncryptVenice([]byte("Hello!"), session.ClientPubKey())
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

	result, ss, err := e2ee.ReassembleNonStream(strings.NewReader(sse.String()), session)
	if err != nil {
		t.Fatalf("ReassembleNonStream: %v", err)
	}

	t.Logf("result: %s (chunks=%d, tokens=%d, duration=%s)", result, ss.Chunks, ss.Tokens, ss.Duration)
	if ss.Chunks != 3 {
		t.Errorf("StreamStats.Chunks = %d, want 3", ss.Chunks)
	}
	if ss.Tokens != 0 {
		t.Errorf("StreamStats.Tokens = %d, want 0 (no usage event in fixture)", ss.Tokens)
	}

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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", true)
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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
			got := e2ee.SafePrefix(tc.s, tc.n)
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
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	plaintext := "Hello, SSE!"
	enc, err := e2ee.EncryptVenice([]byte(plaintext), session.ClientPubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("decrypt_success", func(t *testing.T) {
		chunk := fmt.Sprintf(`{"id":"c1","choices":[{"delta":{"content":%q},"index":0}]}`, enc)
		got, err := e2ee.DecryptSSEChunk(chunk, session)
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
		got, err := e2ee.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}
		if got != chunk {
			t.Errorf("expected passthrough for empty delta, got %q", got)
		}
	})

	t.Run("no_choices_passthrough", func(t *testing.T) {
		chunk := `{"id":"c1","usage":{"prompt_tokens":5}}`
		got, err := e2ee.DecryptSSEChunk(chunk, session)
		if err != nil {
			t.Fatalf("DecryptSSEChunk: %v", err)
		}
		if got != chunk {
			t.Errorf("expected passthrough for no choices, got %q", got)
		}
	})

	t.Run("non_encrypted_content_errors", func(t *testing.T) {
		chunk := `{"id":"c1","choices":[{"delta":{"content":"plain text"},"index":0}]}`
		_, err := e2ee.DecryptSSEChunk(chunk, session)
		if err == nil {
			t.Fatal("expected error for non-encrypted content")
		}
		t.Logf("got expected error: %v", err)
	})

	t.Run("invalid_json_errors", func(t *testing.T) {
		_, err := e2ee.DecryptSSEChunk("not json", session)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("reasoning_decrypted", func(t *testing.T) {
		reasoning := "Let me think..."
		encReasoning, err := e2ee.EncryptVenice([]byte(reasoning), session.ClientPubKey())
		if err != nil {
			t.Fatalf("Encrypt reasoning: %v", err)
		}

		chunk := fmt.Sprintf(`{"id":"c1","choices":[{"delta":{"reasoning":%q},"index":0}]}`, encReasoning)
		got, err := e2ee.DecryptSSEChunk(chunk, session)
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
		encContent, err := e2ee.EncryptVenice([]byte(contentText), session.ClientPubKey())
		if err != nil {
			t.Fatalf("Encrypt content: %v", err)
		}
		encReasoning, err := e2ee.EncryptVenice([]byte(reasoningText), session.ClientPubKey())
		if err != nil {
			t.Fatalf("Encrypt reasoning: %v", err)
		}

		chunk := fmt.Sprintf(`{"id":"c1","choices":[{"delta":{"content":%q,"reasoning":%q},"index":0}]}`, encContent, encReasoning)
		got, err := e2ee.DecryptSSEChunk(chunk, session)
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
	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	plaintext := "Hello, non-stream!"
	enc, err := e2ee.EncryptVenice([]byte(plaintext), session.ClientPubKey())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("decrypt_success", func(t *testing.T) {
		body := []byte(nonStreamResponse(enc))
		got, err := e2ee.DecryptNonStreamResponse(body, session)
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
		got, err := e2ee.DecryptNonStreamResponse(body, session)
		if err != nil {
			t.Fatalf("DecryptNonStreamResponse: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("expected passthrough for no choices")
		}
	})

	t.Run("empty_content_passthrough", func(t *testing.T) {
		body := []byte(nonStreamResponse(""))
		got, err := e2ee.DecryptNonStreamResponse(body, session)
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
		_, err := e2ee.DecryptNonStreamResponse(body, session)
		if err == nil {
			t.Fatal("expected error for non-encrypted content")
		}
		t.Logf("got expected error: %v", err)
	})

	t.Run("invalid_json_errors", func(t *testing.T) {
		_, err := e2ee.DecryptNonStreamResponse([]byte("not json"), session)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("reasoning_decrypted", func(t *testing.T) {
		reasoning := "Thinking about it..."
		encReasoning, err := e2ee.EncryptVenice([]byte(reasoning), session.ClientPubKey())
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
		got, err := e2ee.DecryptNonStreamResponse([]byte(body), session)
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

func TestNew_NoProviders(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers:  map[string]*config.Provider{},
	}
	_, err := proxy.New(cfg)
	t.Logf("New(no providers) err: %v", err)
	if err == nil {
		t.Fatal("expected error for empty providers, got nil")
	}
	if !strings.Contains(err.Error(), "no providers configured") {
		t.Errorf("error should mention no providers: %v", err)
	}
}

// --------------------------------------------------------------------------
// PrepareUpstreamHeaders
// --------------------------------------------------------------------------

type mockPreparer struct {
	called bool
	apiKey string
}

func (m *mockPreparer) PrepareRequest(req *http.Request, _ http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string) error {
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

	if err := proxy.PrepareUpstreamHeaders(req, prov, nil, nil, false, "/v1/chat/completions"); err != nil {
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

	if err := proxy.PrepareUpstreamHeaders(req, prov, nil, nil, false, "/v1/chat/completions"); err != nil {
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

	session, err := e2ee.NewVeniceSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := proxy.PrepareUpstreamHeaders(req, prov, session, nil, false, "/v1/chat/completions"); err != nil {
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

func TestPrepareUpstreamHeaders_NearCloudSession(t *testing.T) {
	// Exercises the *e2ee.NearCloudSession type-switch branch.
	mock := &mockPreparer{apiKey: "nearcloud-key"}
	prov := &provider.Provider{
		Name:     "nearcloud",
		Preparer: mock,
	}

	session, err := e2ee.NewNearCloudSession()
	if err != nil {
		t.Fatalf("NewNearCloudSession: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/chat", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := proxy.PrepareUpstreamHeaders(req, prov, session, nil, false, "/v1/chat/completions"); err != nil {
		t.Fatalf("PrepareUpstreamHeaders: %v", err)
	}

	if !mock.called {
		t.Error("Preparer.PrepareRequest was not called")
	}
}

// --------------------------------------------------------------------------
// relayStream tests
// --------------------------------------------------------------------------

func TestRelayStream_EmptyBody(t *testing.T) {
	rec := httptest.NewRecorder()

	_, _ = e2ee.RelayStream(context.Background(), rec, strings.NewReader(""), nil)

	t.Logf("status: %d, body: %q", rec.Code, rec.Body.String())
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "empty upstream stream") {
		t.Errorf("body = %q, want 'empty upstream stream'", rec.Body.String())
	}
}

func TestRelayStream_NonDataLines(t *testing.T) {
	rec := httptest.NewRecorder()

	// SSE with a comment line, a non-data event, then a data chunk and DONE.
	body := ": this is a comment\nevent: heartbeat\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
	_, _ = e2ee.RelayStream(context.Background(), rec, strings.NewReader(body), nil)

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
	rec := httptest.NewRecorder()

	body := streamSSE("hello world")
	_, _ = e2ee.RelayStream(context.Background(), rec, strings.NewReader(body), nil)

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
	rec := httptest.NewRecorder()

	body := nonStreamResponse("hello from upstream")
	_, _ = e2ee.RelayNonStream(context.Background(), rec, strings.NewReader(body), nil)

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
	rec := httptest.NewRecorder()

	// No valid SSE data lines — should fail during reassembly.
	_, _ = e2ee.RelayReassembledNonStream(context.Background(), rec, strings.NewReader("not valid sse"), nil)

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

func TestHandleEvents(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	// Connect to the SSE endpoint and read the first event.
	resp, err := http.Get(proxySrv.URL + "/events")
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	t.Logf("Content-Type: %s", ct)
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	// Read at least one well-formed SSE data line.
	scanner := bufio.NewScanner(resp.Body)
	var gotData bool
	for scanner.Scan() {
		line := scanner.Text()
		t.Logf("SSE line: %s", line)
		if strings.HasPrefix(line, "data: ") {
			// Verify it's valid JSON.
			payload := line[len("data: "):]
			var obj map[string]any
			if err := json.Unmarshal([]byte(payload), &obj); err != nil {
				t.Fatalf("SSE data is not valid JSON: %v\npayload: %s", err, payload)
			}
			t.Logf("SSE payload keys: %v", keys(obj))
			// Expect dashboard data fields.
			for _, key := range []string{"listen_addr", "uptime", "providers", "requests", "cache", "models"} {
				if _, ok := obj[key]; !ok {
					t.Errorf("SSE payload missing key %q", key)
				}
			}
			gotData = true
			break
		}
	}
	if !gotData {
		t.Fatal("no SSE data event received")
	}
	resp.Body.Close()
}

func TestHandleEvents_MaxConns(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	// Open maxSSEConns (10) connections.
	const maxConns = 10
	conns := make([]io.Closer, 0, maxConns)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := range maxConns {
		resp, err := http.Get(proxySrv.URL + "/events")
		if err != nil {
			t.Fatalf("GET /events [%d]: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("connection %d: status = %d, want 200", i, resp.StatusCode)
		}
		t.Logf("connection %d: status=%d", i, resp.StatusCode)
		conns = append(conns, resp.Body)
	}

	// The 11th connection should get 503.
	resp, err := http.Get(proxySrv.URL + "/events")
	if err != nil {
		t.Fatalf("GET /events [overflow]: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("overflow connection: status=%d", resp.StatusCode)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("overflow status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// keys returns the top-level keys of a map for test logging.
func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	// Make a chat request to populate stats.
	chatResp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
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

// --------------------------------------------------------------------------
// Phase 4: Cache coherence and signing key tests
// --------------------------------------------------------------------------

func TestSigningKeyCacheReuse(t *testing.T) {
	// Two sequential requests to a pinned E2EE provider. First triggers
	// attestation + signing key cache population. Second uses the cached
	// signing key (verify signing key is passed to PinnedRequest).
	handler := &signingKeyPinnedHandler{key: "test-signing-key-hex"}
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("neardirect")
	if prov == nil {
		t.Fatal("neardirect provider missing")
	}
	prov.PinnedHandler = handler
	prov.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) { return "completions.near.ai", true }

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	// First request: attestation + signing key cached.
	resp1, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp1.StatusCode)
	}
	if handler.calls != 1 {
		t.Fatalf("handler calls = %d, want 1", handler.calls)
	}
	// First request should NOT have a signing key from cache.
	if handler.lastReqSKKey != "" {
		t.Errorf("first request SigningKey should be empty, got %q", handler.lastReqSKKey)
	}

	// Second request: SPKI hit, signing key should come from cache.
	resp2, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want 200", resp2.StatusCode)
	}
	if handler.calls != 2 {
		t.Fatalf("handler calls = %d, want 2", handler.calls)
	}
	// Second request should receive the cached signing key.
	if handler.lastReqSKKey != "test-signing-key-hex" {
		t.Errorf("second request SigningKey = %q, want %q", handler.lastReqSKKey, "test-signing-key-hex")
	}
}

func TestBlockedReport_NegCacheAndAttestCacheInteraction(t *testing.T) {
	// Blocked attestation → negative cache record. Verify second request
	// gets 503 (neg cache) not 502 (re-attest). Third request after
	// negative cache expiry should succeed (recovery).
	handler := &blockedThenOKPinnedHandler{}
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
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	// Use a very short negative cache TTL so the test can expire it quickly.
	srv.SetNegativeCache(attestation.NewNegativeCache(50 * time.Millisecond))
	prov := srv.ProviderByName("neardirect")
	if prov == nil {
		t.Fatal("neardirect provider missing")
	}
	prov.PinnedHandler = handler

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	// Request 1: blocked → 502 + negative cache populated.
	resp1, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadGateway {
		t.Fatalf("request 1 status = %d, want 502", resp1.StatusCode)
	}
	if handler.calls != 1 {
		t.Fatalf("handler calls = %d, want 1", handler.calls)
	}

	// Request 2: negative cache → 503. Handler should NOT be called again.
	resp2, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request 2 status = %d, want 503 (neg cache)", resp2.StatusCode)
	}
	if handler.calls != 1 {
		t.Errorf("handler calls = %d, want still 1 (neg cache should intercept)", handler.calls)
	}

	// Wait for negative cache to expire by polling with a deadline instead of a fixed sleep.
	deadline := time.Now().Add(2 * time.Second)
	var lastStatus int
	var lastErr error
	for {
		if time.Now().After(deadline) {
			t.Fatalf("request 3 did not succeed before deadline; last status = %d, last error = %v", lastStatus, lastErr)
		}

		// Request 3 attempt: expect negative cache to have expired → re-attest → handler returns OK.
		resp3, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
		lastErr = err
		if err != nil {
			// Retry until deadline to avoid flakiness due to timing.
			time.Sleep(10 * time.Millisecond)
			continue
		}

		lastStatus = resp3.StatusCode
		resp3.Body.Close()
		if resp3.StatusCode == http.StatusOK {
			break
		}

		// Still seeing negative-cache behavior; wait briefly and retry until deadline.
		time.Sleep(10 * time.Millisecond)
	}
	if handler.calls != 2 {
		t.Errorf("handler calls = %d, want 2 (re-attest after neg cache expiry)", handler.calls)
	}
}

func TestPinnedPath_E2EE_ReportDataBindingCacheCheck(t *testing.T) {
	// E2EE provider: first request caches report where
	// tdx_reportdata_binding fails. Second request (SPKI cache hit)
	// should be rejected with 502 because cached report has no binding.
	handler := &reportDataFailPinnedHandler{}
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("neardirect")
	if prov == nil {
		t.Fatal("neardirect provider missing")
	}
	prov.PinnedHandler = handler
	prov.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) { return "completions.near.ai", true }

	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	// Request 1: attestation returns report where reportdata binding fails.
	// For an E2EE provider, the proxy must refuse the request even on first
	// request (SPKI miss) to prevent plaintext downgrade.
	resp1, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadGateway {
		t.Fatalf("request 1 status = %d, want 502 (reportdata binding failed; E2EE must refuse)", resp1.StatusCode)
	}
	if handler.calls != 1 {
		t.Fatalf("handler calls after request 1 = %d, want 1 (handler called for attestation)", handler.calls)
	}

	// Request 2: provider/model is now negative-cached after the first
	// REPORTDATA binding failure → request is blocked immediately with 503.
	resp2, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("request 2 status = %d, want 503 (negative-cached after binding failure)", resp2.StatusCode)
	}
}

// TestPinnedPath_E2EE_NilReportBlocked verifies that an E2EE provider on the
// pinned path blocks the request when the pinned handler returns a nil report
// (SPKI cache hit) and the attestation cache is empty. Previously this was a
// fail-open: enforceReport returned true for nil reports, and the E2EE binding
// check short-circuited on report==nil.
func TestPinnedPath_E2EE_NilReportBlocked(t *testing.T) {
	// Handler always returns nil report (simulates SPKI cache hit with no
	// attestation). Also returns 200 + body so we can distinguish "blocked
	// by proxy" (502) from "handler error."
	handler := &stubPinnedHandler{}
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"neardirect": {
				Name:    "neardirect",
				BaseURL: "https://completions.near.ai",
				APIKey:  "key",
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("neardirect")
	if prov == nil {
		t.Fatal("neardirect provider missing")
	}
	prov.PinnedHandler = handler
	prov.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) { return "completions.near.ai", true }

	// Do NOT populate the attestation cache — simulate cache expiry.
	proxySrv := httptest.NewServer(srv)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "neardirect:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("status=%d body=%s", resp.StatusCode, string(body))

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (E2EE with nil report must be blocked)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "no attestation report available") {
		t.Errorf("expected 'no attestation report available' in body, got: %s", string(body))
	}
}

// --- Nonce pool unit tests ---

// mockE2EEFetcher records calls for nonce pool fast-path testing.
type mockE2EEFetcher struct {
	mu              sync.Mutex
	material        *provider.E2EEMaterial
	fetchErr        error
	fetchCalls      int
	invalidateCalls int
	lastChuteID     string
}

func (m *mockE2EEFetcher) FetchE2EEMaterial(_ context.Context, _ string) (*provider.E2EEMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fetchCalls++
	return m.material, m.fetchErr
}

func (m *mockE2EEFetcher) MarkFailed(_, _ string) {}

func (m *mockE2EEFetcher) Invalidate(chuteID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateCalls++
	m.lastChuteID = chuteID
}

// passthroughEncryptor returns the body unmodified with no E2EE session or
// Chutes metadata. It allows nonce pool tests to verify routing and retry
// logic without real encryption. Instance tracking for MarkFailed is carried
// by buildUpstreamBody's chuteID/instanceID return values (from raw), not
// from meta.
type passthroughEncryptor struct{}

func (passthroughEncryptor) EncryptRequest(body []byte, _ *attestation.RawAttestation, _ string) ([]byte, e2ee.Decryptor, *e2ee.ChutesE2EE, error) {
	return body, nil, nil, nil
}

// noopPreparer sets only Authorization, without rewriting the URL.
type noopPreparer struct {
	apiKey string
}

func (p noopPreparer) PrepareRequest(req *http.Request, _ http.Header, _ *e2ee.ChutesE2EE, _ bool, _ string) error {
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return nil
}

// mockAttester records FetchAttestation calls for fallback-path testing.
type mockAttester struct {
	mu    sync.Mutex
	calls int
}

func (m *mockAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return nil, errors.New("mock: fresh attestation not available")
}

// passingReport returns a minimal VerificationReport with tdx_reportdata_binding
// passing so that e2eeActive is true on attestation cache hits.
func passingReport(provName, model string) *attestation.VerificationReport { //nolint:unparam // model varies by test intent
	return &attestation.VerificationReport{
		Provider: provName,
		Model:    model,
		Factors: []attestation.FactorResult{
			{Name: "tdx_reportdata_binding", Status: attestation.Pass, Detail: "test"},
		},
	}
}

// newNoncePoolTestServer creates a proxy server with a venice provider
// configured for nonce pool testing. It replaces the Encryptor and Preparer
// with passthroughs so tests can focus on the nonce pool routing logic.
// The returned server's upstream points at upstreamURL for chat completions.
func newNoncePoolTestServer(t *testing.T, upstreamURL string) (srv *proxy.Server, ts *httptest.Server) {
	t.Helper()

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: upstreamURL,
				APIKey:  "test-key",
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	prov := srv.ProviderByName("venice")
	prov.Encryptor = passthroughEncryptor{}
	return srv, httptest.NewServer(srv)
}

// TestNoncePoolAccept verifies that when the signing key cache has a key
// matching the nonce pool's E2EPubKey, the pool material is used without
// falling back to fresh attestation.
func TestNoncePoolAccept(t *testing.T) {
	const signingKey = "matching-signing-key"
	const wantContent = "nonce pool accepted"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nonStreamResponse(wantContent)))
	}))
	defer upstream.Close()

	srv, proxySrv := newNoncePoolTestServer(t, upstream.URL)
	defer proxySrv.Close()

	fetcher := &mockE2EEFetcher{
		material: &provider.E2EEMaterial{
			InstanceID: "inst-1",
			E2EPubKey:  signingKey,
			E2ENonce:   "nonce-1",
			ChuteID:    "chute-1",
		},
	}
	prov := srv.ProviderByName("venice")
	prov.E2EEMaterialFetcher = fetcher

	srv.PutAttestationCache("venice", "test-model", passingReport("venice", "test-model"))
	srv.PutSigningKeyCache("venice", "test-model", signingKey)

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	got := extractMessageContent(t, func() []byte { b, _ := io.ReadAll(resp.Body); return b }())
	if got != wantContent {
		t.Errorf("content = %q, want %q", got, wantContent)
	}

	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	if fetcher.fetchCalls != 1 {
		t.Errorf("fetchCalls = %d, want 1", fetcher.fetchCalls)
	}
	if fetcher.invalidateCalls != 0 {
		t.Errorf("invalidateCalls = %d, want 0", fetcher.invalidateCalls)
	}
}

// TestNoncePoolReject_ColdSigningKeyCache verifies that when the signing key
// cache is empty, the nonce pool is skipped entirely (no nonce consumed) and
// the proxy falls back to fresh attestation.
func TestNoncePoolReject_ColdSigningKeyCache(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nonStreamResponse("ok")))
	}))
	defer upstream.Close()

	srv, proxySrv := newNoncePoolTestServer(t, upstream.URL)
	defer proxySrv.Close()

	fetcher := &mockE2EEFetcher{
		material: &provider.E2EEMaterial{
			InstanceID: "inst-1",
			E2EPubKey:  "some-key",
			E2ENonce:   "nonce-1",
			ChuteID:    "chute-1",
		},
	}
	attester := &mockAttester{}
	prov := srv.ProviderByName("venice")
	prov.E2EEMaterialFetcher = fetcher
	prov.Attester = attester

	// Pre-populate attestation cache but NOT the signing key cache.
	srv.PutAttestationCache("venice", "test-model", passingReport("venice", "test-model"))

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	// Fallback attestation fails (mock attester), so proxy returns 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fallback attestation fails)", resp.StatusCode)
	}

	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	if fetcher.fetchCalls != 0 {
		t.Errorf("fetchCalls = %d, want 0 (cold cache should skip nonce pool)", fetcher.fetchCalls)
	}

	attester.mu.Lock()
	defer attester.mu.Unlock()
	if attester.calls != 1 {
		t.Errorf("attester.calls = %d, want 1 (fallback to fresh attestation)", attester.calls)
	}
}

// TestNoncePoolMismatch_Invalidate verifies that when the nonce pool's
// E2EPubKey differs from the cached signing key, the pool is invalidated
// and the proxy falls back to fresh attestation.
func TestNoncePoolMismatch_Invalidate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nonStreamResponse("ok")))
	}))
	defer upstream.Close()

	srv, proxySrv := newNoncePoolTestServer(t, upstream.URL)
	defer proxySrv.Close()

	fetcher := &mockE2EEFetcher{
		material: &provider.E2EEMaterial{
			InstanceID: "inst-1",
			E2EPubKey:  "new-different-key",
			E2ENonce:   "nonce-1",
			ChuteID:    "chute-1",
		},
	}
	attester := &mockAttester{}
	prov := srv.ProviderByName("venice")
	prov.E2EEMaterialFetcher = fetcher
	prov.Attester = attester

	// Pre-populate both caches, but with a different key than the fetcher returns.
	srv.PutAttestationCache("venice", "test-model", passingReport("venice", "test-model"))
	srv.PutSigningKeyCache("venice", "test-model", "old-cached-key")

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	// Fallback attestation fails (mock attester), so proxy returns 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fallback attestation fails after mismatch)", resp.StatusCode)
	}

	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	if fetcher.fetchCalls != 1 {
		t.Errorf("fetchCalls = %d, want 1", fetcher.fetchCalls)
	}
	if fetcher.invalidateCalls != 1 {
		t.Errorf("invalidateCalls = %d, want 1 (mismatch should invalidate pool)", fetcher.invalidateCalls)
	}
	if fetcher.lastChuteID != "chute-1" {
		t.Errorf("lastChuteID = %q, want %q", fetcher.lastChuteID, "chute-1")
	}

	attester.mu.Lock()
	defer attester.mu.Unlock()
	if attester.calls != 1 {
		t.Errorf("attester.calls = %d, want 1 (fallback to fresh attestation after mismatch)", attester.calls)
	}
}

// --- Chutes instance failover retry tests ---

// mockMarkingFetcher is a mockE2EEFetcher that also records MarkFailed calls
// and can return different materials per call.
type mockMarkingFetcher struct {
	mu              sync.Mutex
	materials       []*provider.E2EEMaterial // one per call; cycles last entry
	fetchErr        error
	fetchCalls      int
	invalidateCalls int
	markFailedCalls int
	lastMarkedInst  string
}

func (m *mockMarkingFetcher) FetchE2EEMaterial(_ context.Context, _ string) (*provider.E2EEMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.fetchCalls
	m.fetchCalls++
	if m.fetchErr != nil {
		return nil, m.fetchErr
	}
	if idx >= len(m.materials) {
		idx = len(m.materials) - 1
	}
	return m.materials[idx], nil
}

func (m *mockMarkingFetcher) MarkFailed(_, instanceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markFailedCalls++
	m.lastMarkedInst = instanceID
}

func (m *mockMarkingFetcher) Invalidate(_ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateCalls++
}

// newChutesRetryTestServer creates a proxy with a "chutes" provider wired
// for unit testing instance failover. The encryptor is replaced with a
// passthrough so tests can focus on the retry routing logic.
func newChutesRetryTestServer(t *testing.T, upstreamURL string) (srv *proxy.Server, ts *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"chutes": {
				Name:    "chutes",
				BaseURL: upstreamURL,
				APIKey:  "test-key",
				E2EE:    true,
			},
		},
		AllowFail: attestation.KnownFactors,
	}
	srv, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	prov := srv.ProviderByName("chutes")
	// Override defaults set by the chutes provider case in proxy.New:
	// BaseURL is hardcoded to llm.chutes.ai, and the encryptor/preparer
	// use real Chutes crypto. Replace with passthroughs so tests can
	// focus on the retry routing logic. passthroughEncryptor returns
	// meta=nil so the relay uses the non-E2EE path; instance tracking
	// for MarkFailed comes from buildUpstreamBody's ChuteID/InstanceID
	// fields, not from meta.
	prov.BaseURL = upstreamURL
	prov.Encryptor = passthroughEncryptor{}
	prov.Preparer = noopPreparer{apiKey: "test-key"}
	return srv, httptest.NewServer(srv)
}

// TestChutesRetry_FailoverOnUpstream502 verifies that when a Chutes E2EE
// request gets a 502 from the upstream instance, the proxy retries with
// a different instance from the nonce pool. passthroughEncryptor returns
// meta=nil so the relay uses the non-E2EE path; instance tracking for
// MarkFailed comes from buildUpstreamBody's struct fields. We verify
// retry behavior via the mock fetcher's call counts and upstream request
// counts.
func TestChutesRetry_FailoverOnUpstream502(t *testing.T) {
	const signingKey = "chutes-signing-key"
	const wantContent = "retry succeeded"

	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamRequests.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("instance down"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nonStreamResponse(wantContent)))
	}))
	defer upstream.Close()

	srv, proxySrv := newChutesRetryTestServer(t, upstream.URL)
	defer proxySrv.Close()

	fetcher := &mockMarkingFetcher{
		materials: []*provider.E2EEMaterial{
			{InstanceID: "inst-A", E2EPubKey: signingKey, E2ENonce: "nonce-1", ChuteID: "chute-1"},
			{InstanceID: "inst-B", E2EPubKey: signingKey, E2ENonce: "nonce-2", ChuteID: "chute-1"},
		},
	}
	prov := srv.ProviderByName("chutes")
	prov.E2EEMaterialFetcher = fetcher

	srv.PutAttestationCache("chutes", "test-model", passingReport("chutes", "test-model"))
	srv.PutSigningKeyCache("chutes", "test-model", signingKey)

	resp, err := postChat(t, proxySrv.URL, "chutes:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	got := extractMessageContent(t, func() []byte { b, _ := io.ReadAll(resp.Body); return b }())
	if got != wantContent {
		t.Errorf("content = %q, want %q", got, wantContent)
	}

	if n := upstreamRequests.Load(); n != 2 {
		t.Errorf("upstream received %d requests, want 2 (first fails, second succeeds)", n)
	}

	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	if fetcher.fetchCalls != 2 {
		t.Errorf("fetchCalls = %d, want 2 (one per attempt)", fetcher.fetchCalls)
	}
	if fetcher.markFailedCalls != 1 {
		t.Errorf("markFailedCalls = %d, want 1 (first attempt only)", fetcher.markFailedCalls)
	}
	if fetcher.lastMarkedInst != "inst-A" {
		t.Errorf("lastMarkedInst = %q, want %q (first attempt instance)", fetcher.lastMarkedInst, "inst-A")
	}
}

// TestChutesRetry_NoRetryOnSuccess verifies that when the first Chutes E2EE
// attempt succeeds, no retry is triggered.
func TestChutesRetry_NoRetryOnSuccess(t *testing.T) {
	const signingKey = "chutes-signing-key"
	const wantContent = "first try ok"

	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nonStreamResponse(wantContent)))
	}))
	defer upstream.Close()

	srv, proxySrv := newChutesRetryTestServer(t, upstream.URL)
	defer proxySrv.Close()

	fetcher := &mockMarkingFetcher{
		materials: []*provider.E2EEMaterial{
			{InstanceID: "inst-A", E2EPubKey: signingKey, E2ENonce: "nonce-1", ChuteID: "chute-1"},
		},
	}
	prov := srv.ProviderByName("chutes")
	prov.E2EEMaterialFetcher = fetcher

	srv.PutAttestationCache("chutes", "test-model", passingReport("chutes", "test-model"))
	srv.PutSigningKeyCache("chutes", "test-model", signingKey)

	resp, err := postChat(t, proxySrv.URL, "chutes:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	if n := upstreamRequests.Load(); n != 1 {
		t.Errorf("upstream received %d requests, want 1", n)
	}

	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	if fetcher.fetchCalls != 1 {
		t.Errorf("fetchCalls = %d, want 1 (single attempt)", fetcher.fetchCalls)
	}
	if fetcher.markFailedCalls != 0 {
		t.Errorf("markFailedCalls = %d, want 0", fetcher.markFailedCalls)
	}
}

// TestChutesRetry_AllAttemptsFail verifies that when all retry attempts fail,
// the proxy returns the last error status to the client.
func TestChutesRetry_AllAttemptsFail(t *testing.T) {
	const signingKey = "chutes-signing-key"

	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("all instances down"))
	}))
	defer upstream.Close()

	srv, proxySrv := newChutesRetryTestServer(t, upstream.URL)
	defer proxySrv.Close()

	fetcher := &mockMarkingFetcher{
		materials: []*provider.E2EEMaterial{
			{InstanceID: "inst-A", E2EPubKey: signingKey, E2ENonce: "nonce-1", ChuteID: "chute-1"},
			{InstanceID: "inst-B", E2EPubKey: signingKey, E2ENonce: "nonce-2", ChuteID: "chute-1"},
			{InstanceID: "inst-C", E2EPubKey: signingKey, E2ENonce: "nonce-3", ChuteID: "chute-1"},
		},
	}
	prov := srv.ProviderByName("chutes")
	prov.E2EEMaterialFetcher = fetcher

	srv.PutAttestationCache("chutes", "test-model", passingReport("chutes", "test-model"))
	srv.PutSigningKeyCache("chutes", "test-model", signingKey)

	resp, err := postChat(t, proxySrv.URL, "chutes:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()

	// After all 3 attempts fail with 503, the last status is forwarded.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}

	if n := upstreamRequests.Load(); n != 3 {
		t.Errorf("upstream received %d requests, want 3", n)
	}

	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	// 3 attempts = 3 fetches (buildUpstreamBody uses the nonce pool on every
	// attempt in this test because attestation and signing key are cached).
	if fetcher.fetchCalls != 3 {
		t.Errorf("fetchCalls = %d, want 3", fetcher.fetchCalls)
	}
	// All 3 instances are marked failed (including the final attempt).
	if fetcher.markFailedCalls != 3 {
		t.Errorf("markFailedCalls = %d, want 3", fetcher.markFailedCalls)
	}
}

// TestFetchAndVerify_FakeTDXQuote verifies that verifyTDX is exercised when
// the attestation response contains a non-empty (but invalid) intel_quote.
// All factors are in AllowFail so the request still succeeds.
func TestFetchAndVerify_FakeTDXQuote(t *testing.T) {
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Use a fake base64-encoded "quote" — VerifyTDXQuote will fail
			// to parse it, but verifyTDX will still exercise its main path.
			fmt.Fprintf(w, `{
				"verified": true,
				"nonce": %q,
				"model": "test-model",
				"tee_provider": "TDX",
				"signing_key": %q,
				"signing_address": "0xtest",
				"intel_quote": "ZmFrZXF1b3Rl",
				"nvidia_payload": ""
			}`, nonceHex, modelPubKeyHex())
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
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
			"venice": {Name: "venice", BaseURL: combined.URL, APIKey: "key", E2EE: false},
		},
		AllowFail: attestation.KnownFactors, // all factors allowed to fail
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

// TestFetchAndVerify_FakeNvidiaPayload verifies that verifyNVIDIA is exercised
// when the attestation response contains a non-empty nvidia_payload.
// All factors are in AllowFail so the request still succeeds.
func TestFetchAndVerify_FakeNvidiaPayload(t *testing.T) {
	combined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/tee/attestation") {
			nonceHex := r.URL.Query().Get("nonce")
			w.Header().Set("Content-Type", "application/json")
			// Use a fake nvidia_payload (not starting with '{' to avoid NRAS).
			fmt.Fprintf(w, `{
				"verified": true,
				"nonce": %q,
				"model": "test-model",
				"tee_provider": "TDX+NVIDIA",
				"signing_key": %q,
				"signing_address": "0xtest",
				"intel_quote": "",
				"nvidia_payload": "fakenv.payload.notjwt"
			}`, nonceHex, modelPubKeyHex())
			return
		}
		if r.URL.Path == "/api/v1/chat/completions" {
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
			"venice": {Name: "venice", BaseURL: combined.URL, APIKey: "key", E2EE: false},
		},
		Offline:   true, // avoid NRAS online calls
		AllowFail: attestation.KnownFactors,
	}

	proxySrv := newProxyServer(t, cfg)
	defer proxySrv.Close()

	resp, err := postChat(t, proxySrv.URL, "venice:test-model", false)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

func TestChutesRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		resp *http.Response
		want bool
	}{
		{"nil error, nil resp", nil, nil, true},
		{"connection error", errors.New("dial tcp: connection refused"), nil, true},
		{"context canceled", context.Canceled, nil, false},
		{"429 not retried", nil, &http.Response{StatusCode: http.StatusTooManyRequests}, false},
		{"500 retried", nil, &http.Response{StatusCode: http.StatusInternalServerError}, true},
		{"502 retried", nil, &http.Response{StatusCode: http.StatusBadGateway}, true},
		{"503 retried", nil, &http.Response{StatusCode: http.StatusServiceUnavailable}, true},
		{"504 retried", nil, &http.Response{StatusCode: http.StatusGatewayTimeout}, true},
		{"200 not retried", nil, &http.Response{StatusCode: http.StatusOK}, false},
		{"400 not retried", nil, &http.Response{StatusCode: http.StatusBadRequest}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := proxy.ChutesRetryableError(tc.err, tc.resp)
			if got != tc.want {
				t.Errorf("ChutesRetryableError(%v, status=%v) = %v, want %v",
					tc.err, proxy.RespStatusCode(tc.resp), got, tc.want)
			}
		})
	}
}

func TestRespStatusCode_Nil(t *testing.T) {
	if got := proxy.RespStatusCode(nil); got != 0 {
		t.Errorf("RespStatusCode(nil) = %d, want 0", got)
	}
	t.Logf("RespStatusCode(nil) = 0")
}

func TestRespStatusCode_NonNil(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK}
	if got := proxy.RespStatusCode(resp); got != http.StatusOK {
		t.Errorf("RespStatusCode(200 resp) = %d, want 200", got)
	}
}

// --------------------------------------------------------------------------
// Dashboard routes: GET / and GET /events
// --------------------------------------------------------------------------

func TestNew_WithProviderAllowFailConfig(t *testing.T) {
	// Ensure proxy.New accepts a config containing provider-specific allow_fail entries.
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		MaxConns:   10,
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "venice",
				BaseURL: "https://api.venice.ai",
				APIKey:  "test-key",
				E2EE:    false,
			},
		},
		ProviderAllowFail: map[string][]string{
			"venice": {"cpu_gpu_chain"},
		},
	}
	_, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
}

func TestDashboardIndex(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("GET /: status=%d content-type=%s", resp.StatusCode, resp.Header.Get("Content-Type"))

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestDashboardEvents(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	// Use a short-lived context to cancel the SSE stream after reading first bytes.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxySrv.URL+"/events", http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil && ctx.Err() == nil {
		// Only fatal if the error isn't due to context cancellation.
		t.Fatalf("GET /events: %v", err)
	}
	if resp != nil {
		t.Logf("GET /events: status=%d content-type=%s", resp.StatusCode, resp.Header.Get("Content-Type"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	}
}

// TestNew_ProviderNameWithColon verifies that proxy.New rejects a provider
// name containing ":" at startup, enforcing the invariant that resolveModel
// can use strings.Cut on ":" as an unambiguous provider/model delimiter.
func TestNew_ProviderNameWithColon(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"evil:venice": {
				Name:    "evil:venice",
				BaseURL: "https://example.com",
				APIKey:  "test-key",
			},
		},
	}
	_, err := proxy.New(cfg)
	t.Logf("proxy.New with colon provider name: %v", err)
	if err == nil {
		t.Error("expected error for provider name containing ':', got nil")
	}
}

func TestNew_ProviderStructNameWithColon(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "evil:venice",
				BaseURL: "https://example.com",
				APIKey:  "test-key",
			},
		},
	}
	_, err := proxy.New(cfg)
	t.Logf("proxy.New with provider struct name containing colon: %v", err)
	if err == nil {
		t.Error("expected error for provider struct name containing ':', got nil")
	}
}

func TestNew_ProviderKeyNameMismatch(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Providers: map[string]*config.Provider{
			"venice": {
				Name:    "nearcloud",
				BaseURL: "https://example.com",
				APIKey:  "test-key",
			},
		},
	}
	_, err := proxy.New(cfg)
	t.Logf("proxy.New with mismatched provider key/name: %v", err)
	if err == nil {
		t.Error("expected error for mismatched provider map key and name, got nil")
	}
}

func TestMetrics(t *testing.T) {
	attestSrv := makeAttestationServer(t, false)
	defer attestSrv.Close()

	proxySrv := newProxyServer(t, buildConfig(attestSrv.URL, false))
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("GET /metrics: status=%d content-type=%s", resp.StatusCode, resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type = %q, want text/plain; version=0.0.4", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	t.Logf("metrics body:\n%s", body)

	wantMetrics := []string{
		"# HELP teep_requests_total",
		"# TYPE teep_requests_total counter",
		"teep_requests_total ",
		"# HELP teep_errors_total",
		"# TYPE teep_errors_total counter",
		"# HELP teep_attestation_cache_hits_total",
		"# HELP teep_attestation_cache_misses_total",
		"# HELP teep_e2ee_sessions_total",
		"# HELP teep_plaintext_sessions_total",
		"# HELP teep_upstream_requests_total",
		"# HELP teep_upstream_errors_total",
		"# HELP teep_uptime_seconds",
		"# TYPE teep_uptime_seconds gauge",
	}
	for _, want := range wantMetrics {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %q", want)
		}
	}
}

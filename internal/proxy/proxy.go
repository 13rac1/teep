// Package proxy implements the teep HTTP proxy server. It sits between an
// OpenAI-compatible client and a TEE-capable AI backend (Venice, NEAR AI),
// performing attestation verification and optional E2EE on every request.
//
// Request flow for POST /v1/chat/completions:
//
//  1. Parse model name from request body.
//  2. Resolve model → provider. Unknown model → 400.
//  3. Check negative cache. Blocked → 503.
//  4. Check attestation cache. On miss, fetch + verify + cache.
//  5. Any enforced factor Fail → 502 with report JSON.
//  6. If E2EE and tdx_reportdata_binding Pass: encrypt messages, set headers.
//     Otherwise: warn and forward plaintext-over-HTTPS.
//  7. Forward to upstream. Parse streaming SSE or buffer non-streaming body.
//  8. Decrypt each chunk (E2EE). Abort on any decryption failure.
//  9. Re-emit SSE to client (streaming) or return assembled JSON (non-streaming).
//
// 10. Zero session key material.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearai"
	"github.com/13rac1/teep/internal/provider/venice"
)

const (
	// attestationCacheTTL is how long a VerificationReport is considered fresh.
	attestationCacheTTL = 5 * time.Minute

	// negativeCacheTTL is how long a failed attestation blocks retries.
	negativeCacheTTL = 30 * time.Second

	// sseScannerBufSize is the bufio.Scanner buffer for SSE parsing.
	// Encrypted chunks can be large; 1 MiB is sufficient.
	sseScannerBufSize = 1 << 20 // 1 MiB
)

// chatRequest is a minimal parse of an OpenAI chat completions request.
// Only fields the proxy needs to inspect or rewrite are decoded here.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// chatMessage is one message in the chat history.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Server is the teep proxy HTTP server.
type Server struct {
	cfg            *config.Config
	providers      map[string]*provider.Provider // provider name → Provider
	cache          *attestation.Cache
	negCache       *attestation.NegativeCache
	spkiCache      *attestation.SPKICache
	mux            *http.ServeMux
	attestClient   *http.Client // for attestation fetches
	upstreamClient *http.Client // for chat completions forwards
}

// New builds a Server from cfg. Providers are wired with their Attester and
// Preparer implementations based on provider name.
func New(cfg *config.Config) (*Server, error) {
	spkiCache := attestation.NewSPKICache()
	s := &Server{
		cfg:          cfg,
		providers:    make(map[string]*provider.Provider, len(cfg.Providers)),
		cache:        attestation.NewCache(attestationCacheTTL),
		negCache:     attestation.NewNegativeCache(negativeCacheTTL),
		spkiCache:    spkiCache,
		mux:          http.NewServeMux(),
		attestClient: config.NewAttestationClient(),
		upstreamClient: &http.Client{
			Transport: &http.Transport{
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}

	modelOwner := make(map[string]string) // client model → provider name
	for name, cp := range cfg.Providers {
		p, err := fromConfig(cp, spkiCache, cfg.Offline, cfg.Enforced)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}
		for model := range p.ModelMap {
			if prev, ok := modelOwner[model]; ok {
				return nil, fmt.Errorf("model %q mapped by both %q and %q", model, prev, name)
			}
			modelOwner[model] = name
		}
		s.providers[name] = p
		slog.Info("registered provider", "provider", name, "base_url", cp.BaseURL, "api_key", config.RedactKey(cp.APIKey), "e2ee", cp.E2EE, "models", len(cp.ModelMap))
	}

	s.mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	s.mux.HandleFunc("GET /v1/models", s.handleModels)
	s.mux.HandleFunc("GET /v1/tee/report", s.handleReport)

	return s, nil
}

// ListenAndServe starts the proxy HTTP server on the configured listen address.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("teep proxy listening", "addr", s.cfg.ListenAddr)
	return srv.ListenAndServe()
}

// ServeHTTP implements http.Handler so Server can be used with httptest.NewServer.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// fromConfig constructs a provider.Provider from a config.Provider, attaching
// the correct Attester, Preparer, and PinnedHandler for the known provider names.
func fromConfig(cp *config.Provider, spkiCache *attestation.SPKICache, offline bool, enforced []string) (*provider.Provider, error) {
	p := &provider.Provider{
		Name:     cp.Name,
		BaseURL:  cp.BaseURL,
		APIKey:   cp.APIKey,
		ModelMap: cp.ModelMap,
		E2EE:     cp.E2EE,
	}
	switch cp.Name {
	case "venice":
		p.ChatPath = "/api/v1/chat/completions"
		p.Attester = venice.NewAttester(cp.BaseURL, cp.APIKey)
		p.Preparer = venice.NewPreparer(cp.APIKey)
		p.ReportDataVerifier = venice.ReportDataVerifier{}
	case "nearai":
		p.ChatPath = "/v1/chat/completions"
		rdVerifier := nearai.ReportDataVerifier{}
		p.Attester = nearai.NewAttester(cp.BaseURL, cp.APIKey)
		p.Preparer = nearai.NewPreparer(cp.APIKey)
		p.ReportDataVerifier = rdVerifier
		p.PinnedHandler = nearai.NewPinnedHandler(
			nearai.NewEndpointResolver(),
			spkiCache,
			cp.APIKey,
			offline,
			enforced,
			rdVerifier,
		)
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, nearai)", cp.Name)
	}
	return p, nil
}

// resolveModel finds the provider and upstream model name for a client model.
// It returns (nil, "", false) when no provider has the model.
func (s *Server) resolveModel(clientModel string) (*provider.Provider, string, bool) {
	for _, p := range s.providers {
		if _, ok := p.ModelMap[clientModel]; ok {
			mapped := p.MapModel(clientModel)
			return p, mapped, true
		}
	}
	return nil, "", false
}

// reportdataBindingPassed returns true if the tdx_reportdata_binding factor
// passed in the report. If it is absent, Skipped, or Failed, E2EE is refused.
func reportdataBindingPassed(report *attestation.VerificationReport) bool {
	for _, f := range report.Factors {
		if f.Name == "tdx_reportdata_binding" {
			return f.Status == attestation.Pass
		}
	}
	return false
}

// fetchAndVerify fetches attestation from the provider and runs all 21
// verification factors. On failure it records the provider/model in the
// negative cache. Returns nil on fetch error.
func (s *Server) fetchAndVerify(ctx context.Context, prov *provider.Provider, upstreamModel string) *attestation.VerificationReport {
	if prov.Attester == nil {
		slog.Error("provider has no Attester", "provider", prov.Name, "model", upstreamModel)
		s.negCache.Record(prov.Name, upstreamModel)
		return nil
	}

	nonce := attestation.NewNonce()
	slog.Debug("attestation fetch starting", "provider", prov.Name, "model", upstreamModel)
	fetchStart := time.Now()
	raw, err := prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
	if err != nil {
		slog.Error("attestation fetch failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		s.negCache.Record(prov.Name, upstreamModel)
		return nil
	}
	slog.Debug("attestation fetch complete", "provider", prov.Name, "elapsed", time.Since(fetchStart))

	var tdxResult *attestation.TDXVerifyResult
	if raw.IntelQuote != "" {
		slog.Debug("TDX verification starting", "provider", prov.Name)
		tdxStart := time.Now()
		tdxResult = attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, s.cfg.Offline)
		if prov.ReportDataVerifier != nil && tdxResult.ParseErr == nil {
			detail, err := prov.ReportDataVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
			tdxResult.ReportDataBindingErr = err
			tdxResult.ReportDataBindingDetail = detail
		}
		slog.Debug("TDX verification complete", "provider", prov.Name, "elapsed", time.Since(tdxStart))
	}

	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		slog.Debug("NVIDIA verification starting", "provider", prov.Name)
		nvidiaStart := time.Now()
		nvidiaResult = attestation.VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		slog.Debug("NVIDIA verification complete", "provider", prov.Name, "elapsed", time.Since(nvidiaStart))
	}

	var nrasResult *attestation.NvidiaVerifyResult
	if !s.cfg.Offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.Debug("NVIDIA NRAS verification starting", "provider", prov.Name)
		nrasStart := time.Now()
		nrasResult = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, s.attestClient)
		slog.Debug("NVIDIA NRAS verification complete", "provider", prov.Name, "elapsed", time.Since(nrasStart))
	}

	var pocResult *attestation.PoCResult
	if !s.cfg.Offline && raw.IntelQuote != "" {
		slog.Debug("Proof of Cloud check starting", "provider", prov.Name)
		pocStart := time.Now()
		poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, s.attestClient)
		pocResult = poc.CheckQuote(ctx, raw.IntelQuote)
		slog.Debug("Proof of Cloud check complete", "provider", prov.Name, "elapsed", time.Since(pocStart),
			"registered", pocResult != nil && pocResult.Registered)
	}

	return attestation.BuildReport(prov.Name, upstreamModel, raw, nonce, s.cfg.Enforced, tdxResult, nvidiaResult, nrasResult, pocResult)
}

// handleChatCompletions is the core proxy handler for POST /v1/chat/completions.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MiB max
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		http.Error(w, `"model" field is required`, http.StatusBadRequest)
		return
	}

	prov, upstreamModel, ok := s.resolveModel(req.Model)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown model %q", req.Model), http.StatusBadRequest)
		return
	}

	if s.negCache.IsBlocked(prov.Name, upstreamModel) {
		http.Error(w,
			fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel),
			http.StatusServiceUnavailable)
		return
	}

	// Connection-pinned providers (NEAR AI) handle attestation + chat on a
	// single TLS connection. No separate attestation cache or E2EE needed.
	if prov.PinnedHandler != nil {
		s.handlePinnedChat(w, r, prov, upstreamModel, body, req)
		return
	}

	report, cached := s.cache.Get(prov.Name, upstreamModel)
	if !cached {
		report = s.fetchAndVerify(r.Context(), prov, upstreamModel)
		if report == nil {
			http.Error(w, "attestation fetch failed; see server logs", http.StatusBadGateway)
			return
		}
		s.cache.Put(prov.Name, upstreamModel, report)
	}

	if report.Blocked() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(report) //nolint:errchkjson // response body already committed
		return
	}

	e2eeActive := prov.E2EE && reportdataBindingPassed(report)

	upstreamBody, session, err := s.buildUpstreamBody(r.Context(), body, req, upstreamModel, e2eeActive, prov)
	if err != nil {
		slog.Error("build upstream body failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, "failed to prepare upstream request", http.StatusInternalServerError)
		return
	}
	if session != nil {
		defer session.Zero()
	}

	upstreamURL := prov.BaseURL + prov.ChatPath
	ctx := r.Context()
	var cancel context.CancelFunc
	if !req.Stream {
		ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Minute)
	}
	defer cancel()
	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(upstreamBody))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	if err := prepareUpstreamHeaders(upstreamReq, prov, session); err != nil {
		slog.Error("PrepareRequest failed", "provider", prov.Name, "err", err)
		http.Error(w, "failed to prepare upstream request headers", http.StatusInternalServerError)
		return
	}

	resp, err := s.upstreamClient.Do(upstreamReq)
	if err != nil {
		slog.Error("upstream request failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 10<<20))
		return
	}

	if req.Stream {
		s.relayStream(w, resp.Body, session)
		return
	}
	s.relayNonStream(w, resp.Body, session)
}

// handlePinnedChat handles chat completions for connection-pinned providers.
// Attestation and chat happen on the same TLS connection via PinnedHandler.
func (s *Server) handlePinnedChat(
	w http.ResponseWriter, r *http.Request,
	prov *provider.Provider, upstreamModel string,
	body []byte, req chatRequest,
) {
	// Rewrite the model field to the upstream name.
	rewritten, err := rewriteModelField(body, upstreamModel)
	if err != nil {
		slog.Error("rewrite model field failed", "provider", prov.Name, "err", err)
		http.Error(w, "failed to prepare request", http.StatusInternalServerError)
		return
	}

	// Build forwarded headers.
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	// Forward Authorization from client if present.
	if auth := r.Header.Get("Authorization"); auth != "" {
		headers.Set("Authorization", auth)
	}

	pinnedReq := provider.PinnedRequest{
		Method:  http.MethodPost,
		Path:    prov.ChatPath,
		Headers: headers,
		Body:    rewritten,
		Model:   upstreamModel,
	}

	ctx := r.Context()
	var cancel context.CancelFunc
	if req.Stream {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Minute)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	}
	defer cancel()

	pinnedResp, err := prov.PinnedHandler.HandlePinned(ctx, &pinnedReq)
	if err != nil {
		slog.Error("pinned chat failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, fmt.Sprintf("pinned connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer pinnedResp.Body.Close()

	// Cache the verification report if one was produced (SPKI cache miss).
	if pinnedResp.Report != nil {
		s.cache.Put(prov.Name, upstreamModel, pinnedResp.Report)
	}

	// Copy response headers, excluding hop-by-hop headers that Go's
	// HTTP stack manages (matching proxy.py's filtering).
	// net/http canonicalizes keys, so compare against canonical forms.
	for key, vals := range pinnedResp.Header {
		switch key {
		case "Transfer-Encoding", "Content-Encoding", "Content-Length", "Connection":
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	// Relay the response.
	if pinnedResp.StatusCode != http.StatusOK {
		w.WriteHeader(pinnedResp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(pinnedResp.Body, 10<<20))
		return
	}

	// No E2EE session for pinned providers (they use TLS pinning).
	if req.Stream {
		s.relayStream(w, pinnedResp.Body, nil)
		return
	}
	s.relayNonStream(w, pinnedResp.Body, nil)
}

// buildUpstreamBody constructs the body to forward upstream. If e2eeActive is
// true it fetches a fresh signing key, creates an ephemeral session, encrypts
// each message, and forces stream=true (required for per-chunk decryption).
// Returns the encoded body, the session (nil for plaintext), and any error.
func (s *Server) buildUpstreamBody(
	ctx context.Context,
	rawBody []byte,
	req chatRequest,
	upstreamModel string,
	e2eeActive bool,
	prov *provider.Provider,
) ([]byte, *attestation.Session, error) {
	if !e2eeActive {
		if prov.E2EE {
			slog.Warn("E2EE disabled — tdx_reportdata_binding not verified; forwarding plaintext over HTTPS", "provider", prov.Name, "model", upstreamModel)
		}
		rewritten, err := rewriteModelField(rawBody, upstreamModel)
		if err != nil {
			return nil, nil, fmt.Errorf("rewrite model field: %w", err)
		}
		return rewritten, nil, nil
	}

	// Fetch a fresh attestation to get the current signing key.
	// The verification cache holds reports; it intentionally does not cache
	// signing keys — each E2EE session must use a fresh key.
	//
	// CRITICAL: Re-verify REPORTDATA binding on this fresh response.
	// Without this, a MITM could substitute the signing key in the second
	// fetch while the cached report (from the first fetch) still shows
	// tdx_reportdata_binding as Pass.
	nonce := attestation.NewNonce()
	raw, err := prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch signing key: %w", err)
	}
	if raw.SigningKey == "" {
		return nil, nil, errors.New("attestation response missing signing_key")
	}
	if raw.IntelQuote == "" {
		return nil, nil, errors.New("fresh attestation missing TDX quote; cannot verify signing key binding")
	}
	tdxResult := attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, true)
	if tdxResult.ParseErr != nil {
		return nil, nil, fmt.Errorf("fresh TDX quote parse failed: %w", tdxResult.ParseErr)
	}
	if prov.ReportDataVerifier != nil {
		_, err := prov.ReportDataVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
		if err != nil {
			return nil, nil, fmt.Errorf("fresh signing key REPORTDATA binding failed: %w", err)
		}
	}

	session, err := attestation.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("create E2EE session: %w", err)
	}
	if err := session.SetModelKey(raw.SigningKey); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("set model key: %w", err)
	}

	encMessages := make([]chatMessage, len(req.Messages))
	for i, msg := range req.Messages {
		ciphertext, err := attestation.Encrypt([]byte(msg.Content), session.ModelPubKey())
		if err != nil {
			session.Zero()
			return nil, nil, fmt.Errorf("encrypt message %d: %w", i, err)
		}
		encMessages[i] = chatMessage{Role: msg.Role, Content: ciphertext}
	}

	// Reassemble the full request as a generic map so we preserve unknown fields.
	var full map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &full); err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("re-parse body for E2EE rewrite: %w", err)
	}

	modelJSON, err := json.Marshal(upstreamModel)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal model name: %w", err)
	}
	full["model"] = modelJSON

	messagesJSON, err := json.Marshal(encMessages)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal encrypted messages: %w", err)
	}
	full["messages"] = messagesJSON

	// Force stream=true so we can decrypt per-chunk.
	full["stream"] = json.RawMessage("true")

	out, err := json.Marshal(full)
	if err != nil {
		session.Zero()
		return nil, nil, fmt.Errorf("marshal E2EE request body: %w", err)
	}
	return out, session, nil
}

// prepareUpstreamHeaders injects auth and E2EE headers into the upstream request.
// When session is non-nil (E2EE path), it delegates to the provider's Preparer.
// When session is nil (plaintext fallback), it sets only the Authorization header
// directly, because provider-specific Preparers may require a fully initialised
// session (e.g. Venice requires ModelKeyHex to be set).
func prepareUpstreamHeaders(req *http.Request, prov *provider.Provider, session *attestation.Session) error {
	if session != nil && prov.Preparer != nil {
		return prov.Preparer.PrepareRequest(req, session)
	}
	// Plaintext path: inject the Authorization header manually so the upstream
	// request is authenticated. This is safe because we are on HTTPS.
	if prov.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+prov.APIKey)
	}
	return nil
}

// rewriteModelField replaces the "model" field in a JSON body with upstreamModel.
// All other fields are preserved exactly.
func rewriteModelField(body []byte, upstreamModel string) ([]byte, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(body, &full); err != nil {
		return nil, err
	}
	modelJSON, err := json.Marshal(upstreamModel)
	if err != nil {
		return nil, err
	}
	full["model"] = modelJSON
	return json.Marshal(full)
}

// relayStream reads an SSE stream from body, decrypts chunks when session is
// non-nil, and writes the decrypted SSE lines to w. It aborts immediately if
// any decryption fails — no plaintext fallthrough.
func (s *Server) relayStream(w http.ResponseWriter, body io.Reader, session *attestation.Session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	scanner := bufio.NewScanner(body)
	buf := make([]byte, sseScannerBufSize)
	scanner.Buffer(buf, sseScannerBufSize)

	// Read the first line before committing a 200 status. If the upstream
	// body is empty or immediately errors, return a proper HTTP error.
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			http.Error(w, "upstream stream error", http.StatusBadGateway)
		} else {
			http.Error(w, "empty upstream stream", http.StatusBadGateway)
		}
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Process first line, then loop for the rest.
	done := s.relaySSELine(w, flusher, scanner.Text(), session)
	if done {
		return
	}

	for scanner.Scan() {
		if s.relaySSELine(w, flusher, scanner.Text(), session) {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("SSE scanner error", "err", err)
	}
}

// relaySSELine processes a single SSE line, writing it to w. Returns true if
// the stream should end (DONE marker or decryption error).
func (s *Server) relaySSELine(w http.ResponseWriter, flusher http.Flusher, line string, session *attestation.Session) bool {
	if !strings.HasPrefix(line, "data: ") {
		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
		return false
	}

	data := line[len("data: "):]
	if data == "[DONE]" {
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
		return true
	}

	if session == nil {
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return false
	}

	decrypted, err := decryptSSEChunk(data, session)
	if err != nil {
		slog.Error("stream decryption failed", "err", err)
		fmt.Fprintf(w, "event: error\ndata: {\"error\":{\"message\":\"stream decryption failed\",\"type\":\"decryption_error\"}}\n\n")
		flusher.Flush()
		return true
	}

	fmt.Fprintf(w, "data: %s\n\n", decrypted)
	flusher.Flush()
	return false
}

// relayNonStream reads a non-streaming JSON response from body, decrypts the
// content field if session is non-nil, and writes the result to w.
func (s *Server) relayNonStream(w http.ResponseWriter, body io.Reader, session *attestation.Session) {
	responseBody, err := io.ReadAll(io.LimitReader(body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
		return
	}

	decrypted, err := decryptNonStreamResponse(responseBody, session)
	if err != nil {
		slog.Error("non-stream decryption failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decrypted)
}

// handleModels returns the list of client-facing model names available across
// all configured providers.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	type modelEntry struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	type response struct {
		Object string       `json:"object"`
		Data   []modelEntry `json:"data"`
	}

	var models []modelEntry
	for _, prov := range s.providers {
		for clientModel := range prov.ModelMap {
			models = append(models, modelEntry{
				ID:      clientModel,
				Object:  "model",
				OwnedBy: prov.Name,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response{Object: "list", Data: models}) //nolint:errchkjson // response body already committed
}

// handleReport returns the cached VerificationReport for the given provider
// and model as JSON. Query parameters: provider, model.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	provName := r.URL.Query().Get("provider")
	model := r.URL.Query().Get("model")

	if provName == "" || model == "" {
		http.Error(w, `query parameters "provider" and "model" are required`, http.StatusBadRequest)
		return
	}

	report, ok := s.cache.Get(provName, model)
	if !ok {
		http.Error(w, fmt.Sprintf("no cached report for provider=%q model=%q", provName, model), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report) //nolint:errchkjson // response body already committed
}

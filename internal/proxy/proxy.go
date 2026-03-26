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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// attestationCacheTTL is how long a VerificationReport is considered fresh.
	attestationCacheTTL = 5 * time.Minute

	// negativeCacheTTL is how long a failed attestation blocks retries.
	negativeCacheTTL = 30 * time.Second

	// signingKeyCacheTTL is how long a REPORTDATA-verified signing key is
	// reused for E2EE without re-fetching attestation. Must be ≥ the SPKI
	// cache TTL (1 h) to avoid "no signing key available" errors on pinned
	// connections where an SPKI cache hit skips attestation.
	signingKeyCacheTTL = 1 * time.Hour

	// upstreamNonStreamTimeout is the context deadline for non-streaming
	// upstream requests. Must be generous — attestation + E2EE setup can
	// consume 20+ seconds before the upstream request even starts, and
	// large models may need minutes to generate a full response.
	upstreamNonStreamTimeout = 5 * time.Minute

	// upstreamStreamTimeout is the context deadline for streaming upstream
	// requests. Streaming responses can run for a long time.
	upstreamStreamTimeout = 30 * time.Minute

	// sseScannerBufSize is the bufio.Scanner buffer for SSE parsing.
	// Encrypted chunks can be large; 1 MiB is sufficient.
	sseScannerBufSize = 1 << 20 // 1 MiB
)

// sseScannerBufPool reuses 1 MiB scanner buffers across SSE requests.
var sseScannerBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, sseScannerBufSize)
		return &buf
	},
}

// stats holds live operational counters for the status page.
// All fields are read/written atomically — no mutex needed.
type stats struct {
	startTime   time.Time
	requests    atomic.Int64
	errors      atomic.Int64
	streaming   atomic.Int64
	nonStream   atomic.Int64
	e2ee        atomic.Int64
	plaintext   atomic.Int64
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
	modelsMu    sync.RWMutex
	models      map[string]*modelStats
}

// modelStats holds per-model counters.
type modelStats struct {
	requests      atomic.Int64
	errors        atomic.Int64
	lastVerifyMs  atomic.Int64 // last verification duration in ms
	lastRequestAt atomic.Int64 // unix timestamp
}

// getModelStats returns (or creates) the modelStats for a provider/model key.
func (st *stats) getModelStats(prov, model string) *modelStats {
	key := prov + "/" + model
	st.modelsMu.RLock()
	if ms, ok := st.models[key]; ok {
		st.modelsMu.RUnlock()
		return ms
	}
	st.modelsMu.RUnlock()

	st.modelsMu.Lock()
	defer st.modelsMu.Unlock()
	if ms, ok := st.models[key]; ok {
		return ms
	}
	ms := &modelStats{}
	st.models[key] = ms
	return ms
}

// fmtDur formats a duration as seconds with 3 decimal places (e.g. "4.200s").
func fmtDur(d time.Duration) string {
	return fmt.Sprintf("%.3fs", d.Seconds())
}

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
	cfg             *config.Config
	providers       map[string]*provider.Provider // provider name → Provider
	cache           *attestation.Cache
	negCache        *attestation.NegativeCache
	signingKeyCache *attestation.SigningKeyCache
	spkiCache       *attestation.SPKICache
	rekorClient     *attestation.RekorClient
	pocSigningKey   ed25519.PublicKey // optional EdDSA key for PoC JWT verification (GW-M-11)
	mux             *http.ServeMux
	attestClient    *http.Client // for attestation fetches
	upstreamClient  *http.Client // for chat completions forwards
	stats           stats
}

// New builds a Server from cfg. Providers are wired with their Attester and
// Preparer implementations based on provider name.
func New(cfg *config.Config) (*Server, error) {
	spkiCache := attestation.NewSPKICache()
	attestClient := config.NewAttestationClient(cfg.Offline)
	s := &Server{
		cfg:             cfg,
		providers:       make(map[string]*provider.Provider, len(cfg.Providers)),
		cache:           attestation.NewCache(attestationCacheTTL),
		negCache:        attestation.NewNegativeCache(negativeCacheTTL),
		signingKeyCache: attestation.NewSigningKeyCache(signingKeyCacheTTL),
		spkiCache:       spkiCache,
		rekorClient:     attestation.NewRekorClient(attestClient),
		mux:             http.NewServeMux(),
		attestClient:    attestClient,
		upstreamClient: tlsct.NewHTTPClientWithTransport(0, &http.Transport{
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}, !cfg.Offline),
		stats: stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	// Parse optional PoC EdDSA signing key (GW-M-11).
	if cfg.PoCSigningKey != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(cfg.PoCSigningKey)
		if err != nil {
			return nil, fmt.Errorf("poc_signing_key: invalid base64: %w", err)
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("poc_signing_key: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
		}
		s.pocSigningKey = ed25519.PublicKey(keyBytes)
		slog.Info("PoC JWT EdDSA signature verification enabled")
	}

	for name, cp := range cfg.Providers {
		p, err := fromConfig(cp, spkiCache, cfg.Offline, cfg.Enforced, cfg.MeasurementPolicy, cfg.GatewayMeasurementPolicy, s.rekorClient, s.pocSigningKey)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}
		s.providers[name] = p
		slog.Info("registered provider", "provider", name, "base_url", cp.BaseURL, "api_key", config.RedactKey(cp.APIKey), "e2ee", cp.E2EE)
	}

	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	s.mux.HandleFunc("GET /v1/models", s.handleModels)
	s.mux.HandleFunc("GET /v1/tee/report", s.handleReport)

	return s, nil
}

// ListenAndServe starts the proxy HTTP server on the configured listen address.
// It blocks until ctx is cancelled (e.g. via signal.NotifyContext), then
// initiates a graceful shutdown with a 5-second deadline to drain in-flight
// requests (which zeros any active E2EE sessions via their defers).
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("teep proxy listening", "addr", s.cfg.ListenAddr)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// ServeHTTP implements http.Handler so Server can be used with httptest.NewServer.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// fromConfig constructs a provider.Provider from a config.Provider, attaching
// the correct Attester, Preparer, and PinnedHandler for the known provider names.
func fromConfig(
	cp *config.Provider,
	spkiCache *attestation.SPKICache,
	offline bool,
	enforced []string,
	policy attestation.MeasurementPolicy,
	gatewayPolicy attestation.MeasurementPolicy,
	rekorClient *attestation.RekorClient,
	pocSigningKey ed25519.PublicKey,
) (*provider.Provider, error) {
	p := &provider.Provider{
		Name:    cp.Name,
		BaseURL: cp.BaseURL,
		APIKey:  cp.APIKey,
		E2EE:    cp.E2EE,
	}
	switch cp.Name {
	case "venice":
		p.ChatPath = "/api/v1/chat/completions"
		p.Attester = venice.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.Preparer = venice.NewPreparer(cp.APIKey)
		p.ReportDataVerifier = venice.ReportDataVerifier{}
		p.SupplyChainPolicy = venice.SupplyChainPolicy()
		p.ModelLister = venice.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
	case "neardirect":
		p.ChatPath = "/v1/chat/completions"
		rdVerifier := neardirect.ReportDataVerifier{}
		p.Attester = neardirect.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.Preparer = neardirect.NewPreparer(cp.APIKey)
		p.ReportDataVerifier = rdVerifier
		p.SupplyChainPolicy = neardirect.SupplyChainPolicy()
		resolver := neardirect.NewEndpointResolver(offline)
		p.PinnedHandler = neardirect.NewPinnedHandler(
			resolver,
			spkiCache,
			cp.APIKey,
			offline,
			enforced,
			policy,
			rdVerifier,
			rekorClient,
		)
		p.ModelLister = neardirect.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
	case "nearcloud":
		p.ChatPath = "/v1/chat/completions"
		p.E2EEVersion = attestation.E2EEv2
		rdVerifier := neardirect.ReportDataVerifier{}
		p.Attester = nearcloud.NewAttester(cp.APIKey, offline)
		p.Preparer = neardirect.NewPreparer(cp.APIKey)
		p.ReportDataVerifier = rdVerifier
		p.SupplyChainPolicy = nearcloud.SupplyChainPolicy()
		p.PinnedHandler = nearcloud.NewPinnedHandler(
			spkiCache,
			cp.APIKey,
			offline,
			enforced,
			policy,
			gatewayPolicy,
			rdVerifier,
			rekorClient,
			pocSigningKey,
		)
		p.ModelLister = neardirect.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
	case "nanogpt":
		p.ChatPath = "/v1/chat/completions"
		p.Attester = nanogpt.NewAttester(cp.BaseURL, cp.APIKey, offline)
		// NanoGPT uses the same dstack REPORTDATA binding as Venice.
		p.ReportDataVerifier = venice.ReportDataVerifier{}
		p.SupplyChainPolicy = nanogpt.SupplyChainPolicy()
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, neardirect, nearcloud, nanogpt)", cp.Name)
	}
	return p, nil
}

// resolveModel finds the provider for a client model. The model name is passed
// through to the upstream unchanged. Returns (nil, "", false) when no providers
// are configured.
func (s *Server) resolveModel(clientModel string) (*provider.Provider, string, bool) {
	for _, p := range s.providers {
		return p, clientModel, true
	}
	return nil, "", false
}

// fetchAndVerify fetches attestation from the provider and runs all
// verification factors. On failure it records the provider/model in the
// negative cache. Returns (nil, nil) on fetch error.
//
// The raw attestation is returned alongside the report so callers can reuse
// it for E2EE key exchange without a second round-trip. The REPORTDATA
// binding has already been verified against the raw's signing key.
func (s *Server) fetchAndVerify(ctx context.Context, prov *provider.Provider, upstreamModel string) (*attestation.VerificationReport, *attestation.RawAttestation) {
	if prov.Attester == nil {
		slog.Error("provider has no Attester", "provider", prov.Name, "model", upstreamModel)
		s.negCache.Record(prov.Name, upstreamModel)
		return nil, nil
	}

	totalStart := time.Now()
	nonce := attestation.NewNonce()
	var fetchDur, tdxDur, nvidiaDur, nrasDur, pocDur, composeDur time.Duration

	slog.Debug("attestation fetch starting", "provider", prov.Name, "model", upstreamModel)
	fetchStart := time.Now()
	raw, err := prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
	if err != nil {
		slog.Error("attestation fetch failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		s.negCache.Record(prov.Name, upstreamModel)
		return nil, nil
	}
	fetchDur = time.Since(fetchStart)
	slog.Debug("attestation fetch complete", "provider", prov.Name, "elapsed", fetchDur)

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
		tdxDur = time.Since(tdxStart)
		slog.Debug("TDX verification complete", "provider", prov.Name, "elapsed", tdxDur)
	}

	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		slog.Debug("NVIDIA verification starting", "provider", prov.Name)
		nvidiaStart := time.Now()
		nvidiaResult = attestation.VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		nvidiaDur = time.Since(nvidiaStart)
		slog.Debug("NVIDIA verification complete", "provider", prov.Name, "elapsed", nvidiaDur)
	}

	var nrasResult *attestation.NvidiaVerifyResult
	if !s.cfg.Offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.Debug("NVIDIA NRAS verification starting", "provider", prov.Name)
		nrasStart := time.Now()
		nrasResult = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, s.attestClient)
		nrasDur = time.Since(nrasStart)
		slog.Debug("NVIDIA NRAS verification complete", "provider", prov.Name, "elapsed", nrasDur)
	}

	var pocResult *attestation.PoCResult
	if !s.cfg.Offline && raw.IntelQuote != "" {
		slog.Debug("Proof of Cloud check starting", "provider", prov.Name)
		pocStart := time.Now()
		poc := attestation.NewPoCClientWithSigningKey(attestation.PoCPeers, attestation.PoCQuorum, s.attestClient, s.pocSigningKey)
		pocResult = poc.CheckQuote(ctx, raw.IntelQuote)
		pocDur = time.Since(pocStart)
		slog.Debug("Proof of Cloud check complete", "provider", prov.Name, "elapsed", pocDur,
			"registered", pocResult != nil && pocResult.Registered)
	}

	var composeResult *attestation.ComposeBindingResult
	var sigstoreResults []attestation.SigstoreResult
	var imageRepos []string
	var digestToRepo map[string]string
	if raw.AppCompose != "" && tdxResult != nil && tdxResult.ParseErr == nil {
		composeStart := time.Now()
		composeResult = &attestation.ComposeBindingResult{Checked: true}
		composeResult.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)

		if composeResult.Err == nil {
			cd := attestation.ExtractComposeDigests(raw.AppCompose)
			imageRepos = cd.Repos
			digestToRepo = cd.DigestToRepo
			digests := cd.Digests
			if len(digests) > 0 && !s.cfg.Offline {
				sigstoreResults = s.rekorClient.CheckSigstoreDigests(ctx, digests)
			}
		}
		composeDur = time.Since(composeStart)
	}

	var rekorResults []attestation.RekorProvenance
	if len(sigstoreResults) > 0 && !s.cfg.Offline {
		for _, sr := range sigstoreResults {
			if sr.OK {
				rekorResults = append(rekorResults, s.rekorClient.FetchRekorProvenance(ctx, sr.Digest))
			}
		}
	}

	totalDur := time.Since(totalStart)
	slog.Info("verification complete",
		"provider", prov.Name,
		"model", upstreamModel,
		"total", fmtDur(totalDur),
		"fetch", fmtDur(fetchDur),
		"tdx", fmtDur(tdxDur),
		"nvidia", fmtDur(nvidiaDur),
		"nras", fmtDur(nrasDur),
		"poc", fmtDur(pocDur),
		"compose", fmtDur(composeDur),
	)

	ms := s.stats.getModelStats(prov.Name, upstreamModel)
	ms.lastVerifyMs.Store(totalDur.Milliseconds())

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          prov.Name,
		Model:             upstreamModel,
		Raw:               raw,
		Nonce:             nonce,
		Enforced:          s.cfg.Enforced,
		Policy:            s.cfg.MeasurementPolicy,
		SupplyChainPolicy: prov.SupplyChainPolicy,
		ImageRepos:        imageRepos,
		DigestToRepo:      digestToRepo,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           composeResult,
		Sigstore:          sigstoreResults,
		Rekor:             rekorResults,
	})
	return report, raw
}

// handleChatCompletions is the core proxy handler for POST /v1/chat/completions.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()

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

	// Per-request timing: populated as the request progresses, logged on exit.
	var attestDur, e2eeDur, upstreamDur time.Duration
	var status string
	defer func() {
		slog.Info("request complete",
			"provider", prov.Name,
			"model", upstreamModel,
			"stream", req.Stream,
			"status", status,
			"attest", fmtDur(attestDur),
			"e2ee", fmtDur(e2eeDur),
			"upstream", fmtDur(upstreamDur),
			"total", fmtDur(time.Since(requestStart)),
		)
	}()

	s.stats.requests.Add(1)
	ms := s.stats.getModelStats(prov.Name, upstreamModel)
	ms.requests.Add(1)
	ms.lastRequestAt.Store(time.Now().Unix())
	if req.Stream {
		s.stats.streaming.Add(1)
	} else {
		s.stats.nonStream.Add(1)
	}

	if s.negCache.IsBlocked(prov.Name, upstreamModel) {
		status = "neg_cached"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		http.Error(w,
			fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel),
			http.StatusServiceUnavailable)
		return
	}

	// Connection-pinned providers (NEAR AI) handle attestation + chat on a
	// single TLS connection. No separate attestation cache or E2EE needed.
	if prov.PinnedHandler != nil {
		status = "pinned"
		s.handlePinnedChat(w, r, prov, upstreamModel, body, req)
		return
	}

	attestStart := time.Now()
	var raw *attestation.RawAttestation // non-nil on cache miss; reused for E2EE
	report, cached := s.cache.Get(prov.Name, upstreamModel)
	if cached {
		s.stats.cacheHits.Add(1)
	} else {
		s.stats.cacheMisses.Add(1)
		report, raw = s.fetchAndVerify(r.Context(), prov, upstreamModel)
		if report == nil {
			status = "attest_failed"
			s.stats.errors.Add(1)
			ms.errors.Add(1)
			http.Error(w, "attestation fetch failed; see server logs", http.StatusBadGateway)
			return
		}
		s.cache.Put(prov.Name, upstreamModel, report)
	}
	attestDur = time.Since(attestStart)

	if report.Blocked() {
		status = "blocked"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		if err := json.NewEncoder(w).Encode(report); err != nil {
			slog.Error("encode response", "error", err)
		}
		return
	}

	// Only cache the signing key after attestation passes. Caching before
	// the Blocked() check would allow a key from a failed attestation to
	// be reused for E2EE on a subsequent cache-hit request.
	if raw != nil && raw.SigningKey != "" {
		if prev, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); ok && prev != raw.SigningKey {
			slog.Warn("signing key rotated (VM restart?)", "provider", prov.Name, "model", upstreamModel)
		}
		s.signingKeyCache.Put(prov.Name, upstreamModel, raw.SigningKey)
	}

	e2eeActive := prov.E2EE && report.ReportDataBindingPassed()
	if e2eeActive {
		s.stats.e2ee.Add(1)
	} else {
		s.stats.plaintext.Add(1)
	}

	e2eeStart := time.Now()
	upstreamBody, session, err := s.buildUpstreamBody(r.Context(), body, req, upstreamModel, e2eeActive, prov, raw)
	if err != nil {
		status = "e2ee_failed"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		slog.Error("build upstream body failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, "failed to prepare upstream request", http.StatusInternalServerError)
		return
	}
	e2eeDur = time.Since(e2eeStart)
	if session != nil {
		defer session.Zero()
	}

	upstreamURL := prov.BaseURL + prov.ChatPath
	ctx := r.Context()
	var cancel context.CancelFunc
	if !req.Stream {
		ctx, cancel = context.WithTimeout(ctx, upstreamNonStreamTimeout)
	} else {
		ctx, cancel = context.WithTimeout(ctx, upstreamStreamTimeout)
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

	upstreamStart := time.Now()
	resp, err := s.upstreamClient.Do(upstreamReq)
	if err != nil {
		status = "upstream_failed"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		slog.Error("upstream request failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		status = fmt.Sprintf("upstream_%d", resp.StatusCode)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 10<<20))
		return
	}

	// E2EE forces stream=true upstream (buildUpstreamBody), so the response
	// is always SSE. When the client requested non-streaming, reassemble the
	// decrypted SSE chunks into a single JSON response.
	if session != nil {
		if req.Stream {
			s.relayStream(w, resp.Body, session)
		} else {
			s.relayReassembledNonStream(w, resp.Body, session)
		}
		upstreamDur = time.Since(upstreamStart)
		status = "ok"
		return
	}
	if req.Stream {
		s.relayStream(w, resp.Body, session)
		upstreamDur = time.Since(upstreamStart)
		status = "ok"
		return
	}
	s.relayNonStream(w, resp.Body, session)
	upstreamDur = time.Since(upstreamStart)
	status = "ok"
}

// handlePinnedChat handles chat completions for connection-pinned providers.
// Attestation and chat happen on the same TLS connection via PinnedHandler.
func (s *Server) handlePinnedChat(
	w http.ResponseWriter, r *http.Request,
	prov *provider.Provider, upstreamModel string,
	body []byte, req chatRequest,
) {
	// Build forwarded headers.
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	// Forward Authorization from client if present.
	if auth := r.Header.Get("Authorization"); auth != "" {
		headers.Set("Authorization", auth)
	}

	// E2EE providers must never send plaintext. On SPKI cache hit, verify
	// that tdx_reportdata_binding passed in the cached report; refuse the
	// request entirely if binding is unverified (cache miss is handled by
	// the pinned handler itself, which will block internally).
	if prov.E2EE {
		if cached, ok := s.cache.Get(prov.Name, upstreamModel); ok && !cached.ReportDataBindingPassed() {
			slog.Error("E2EE required but tdx_reportdata_binding not passed; refusing request",
				"provider", prov.Name, "model", upstreamModel)
			http.Error(w, "E2EE required but REPORTDATA binding not verified; refusing plaintext", http.StatusBadGateway)
			return
		}
	}

	pinnedReq := provider.PinnedRequest{
		Method:  http.MethodPost,
		Path:    prov.ChatPath,
		Headers: headers,
		Body:    body,
		Model:   upstreamModel,
		E2EE:    prov.E2EE,
	}
	// Supply the cached signing key for E2EE on SPKI cache hits.
	if prov.E2EE {
		if cachedKey, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); ok {
			pinnedReq.SigningKey = cachedKey
		}
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
		s.negCache.Record(prov.Name, upstreamModel)
		slog.Error("pinned chat failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, fmt.Sprintf("pinned connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer pinnedResp.Body.Close()

	// Use the report from this request (SPKI miss) or cached report (SPKI hit)
	// to enforce fail-closed policy before forwarding any upstream response.
	report := pinnedResp.Report
	if report != nil {
		s.cache.Put(prov.Name, upstreamModel, report)
	} else if cached, ok := s.cache.Get(prov.Name, upstreamModel); ok {
		report = cached
	}
	if report != nil && report.Blocked() {
		s.negCache.Record(prov.Name, upstreamModel)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		if err := json.NewEncoder(w).Encode(report); err != nil {
			slog.Error("encode response", "error", err)
		}
		return
	}
	if pinnedResp.SigningKey != "" {
		s.signingKeyCache.Put(prov.Name, upstreamModel, pinnedResp.SigningKey)
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

	// E2EE: use the session from the pinned response for decryption.
	// When E2EE is active, upstream was forced to stream=true so the response
	// is always SSE, matching the non-pinned E2EE path.
	session := pinnedResp.Session
	if session != nil {
		s.stats.e2ee.Add(1)
		defer session.Zero()
		if req.Stream {
			s.relayStream(w, pinnedResp.Body, session)
		} else {
			s.relayReassembledNonStream(w, pinnedResp.Body, session)
		}
		return
	}
	s.stats.plaintext.Add(1)
	if req.Stream {
		s.relayStream(w, pinnedResp.Body, nil)
		return
	}
	s.relayNonStream(w, pinnedResp.Body, nil)
}

// buildUpstreamBody constructs the body to forward upstream. If e2eeActive is
// true it creates an ephemeral session, encrypts each message, and forces
// stream=true (required for per-chunk decryption).
//
// When freshRaw is non-nil (cache miss path), its signing key is reused — the
// REPORTDATA binding was already verified by fetchAndVerify. When freshRaw is
// nil (cache hit), a fresh attestation is fetched and re-verified.
//
// Returns the encoded body, the session (nil for plaintext), and any error.
func (s *Server) buildUpstreamBody(
	ctx context.Context,
	rawBody []byte,
	req chatRequest,
	upstreamModel string,
	e2eeActive bool,
	prov *provider.Provider,
	freshRaw *attestation.RawAttestation,
) ([]byte, *attestation.Session, error) {
	if !e2eeActive {
		if prov.E2EE {
			return nil, nil, fmt.Errorf("E2EE required for %s but tdx_reportdata_binding not passed; refusing plaintext", prov.Name)
		}
		return rawBody, nil, nil
	}

	raw := freshRaw
	if raw == nil {
		// Cache hit path: try the signing key cache before re-fetching attestation.
		if cachedKey, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); ok {
			slog.Debug("E2EE key exchange: using cached signing key", "provider", prov.Name, "model", upstreamModel)
			raw = &attestation.RawAttestation{SigningKey: cachedKey}
		} else {
			// Signing key not cached: fetch fresh attestation and re-verify.
			slog.Debug("E2EE key exchange: fetching fresh attestation (cache hit path)", "provider", prov.Name, "model", upstreamModel)
			nonce := attestation.NewNonce()
			var err error
			raw, err = prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
			if err != nil {
				return nil, nil, fmt.Errorf("fetch signing key: %w", err)
			}
			if raw.IntelQuote == "" {
				return nil, nil, errors.New("fresh attestation missing TDX quote; cannot verify signing key binding")
			}
			// offline=true: only REPORTDATA binding is needed here, not full
			// online verification (Intel PCS collateral). The primary
			// fetchAndVerify() path already did online verification for
			// the cached report.
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
			s.signingKeyCache.Put(prov.Name, upstreamModel, raw.SigningKey)
		}
	} else {
		slog.Debug("E2EE key exchange: reusing attestation from verification (cache miss path)", "provider", prov.Name, "model", upstreamModel)
	}

	if raw.SigningKey == "" {
		return nil, nil, errors.New("attestation response missing signing_key")
	}

	// Dispatch E2EE version based on provider configuration.
	if prov.E2EEVersion == attestation.E2EEv2 {
		return attestation.EncryptChatMessagesV2(rawBody, raw.SigningKey)
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
	bufp, ok := sseScannerBufPool.Get().(*[]byte)
	if !ok {
		panic("sseScannerBufPool: unexpected type")
	}
	defer sseScannerBufPool.Put(bufp)
	scanner.Buffer((*bufp)[:cap(*bufp)], sseScannerBufSize)

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

// relayReassembledNonStream reads an SSE stream from the E2EE upstream,
// decrypts each chunk, and writes a single non-streaming JSON response.
func (s *Server) relayReassembledNonStream(w http.ResponseWriter, body io.Reader, session *attestation.Session) {
	result, err := reassembleNonStream(body, session)
	if err != nil {
		slog.Error("E2EE non-stream reassembly failed", "err", err)
		http.Error(w, "response decryption failed", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

// modelsListResponse is the OpenAI-compatible response for GET /v1/models.
type modelsListResponse struct {
	Object string            `json:"object"`
	Data   []json.RawMessage `json:"data"`
}

// modelsTimeout is the context deadline for upstream model listing calls.
const modelsTimeout = 30 * time.Second

// handleModels returns available models from all configured providers.
// Each provider's model entries are relayed as raw JSON to preserve all
// upstream fields (pricing, capabilities, constraints, etc.).
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), modelsTimeout)
	defer cancel()

	all := make([]json.RawMessage, 0)
	for _, p := range s.providers {
		if p.ModelLister == nil {
			continue
		}
		models, err := p.ModelLister.ListModels(ctx)
		if err != nil {
			slog.Warn("model listing failed", "provider", p.Name, "err", err)
			continue
		}
		all = append(all, models...)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(modelsListResponse{Object: "list", Data: all}); err != nil {
		slog.Error("encoding models response", "err", err)
	}
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
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.Error("encode response", "error", err)
	}
}

// handleIndex serves a live stats dashboard at /.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	var provName, baseURL, e2ee string
	for name, p := range s.providers {
		provName = name
		baseURL = p.BaseURL
		if p.E2EE {
			e2ee = "enabled"
		} else {
			e2ee = "disabled"
		}
	}

	uptime := time.Since(s.stats.startTime).Truncate(time.Second)
	requests := s.stats.requests.Load()
	errCount := s.stats.errors.Load()
	streaming := s.stats.streaming.Load()
	nonStream := s.stats.nonStream.Load()
	e2eeCount := s.stats.e2ee.Load()
	plainCount := s.stats.plaintext.Load()
	hits := s.stats.cacheHits.Load()
	misses := s.stats.cacheMisses.Load()

	var hitRate string
	if total := hits + misses; total > 0 {
		hitRate = fmt.Sprintf("%.0f%%", float64(hits)/float64(total)*100)
	} else {
		hitRate = "—"
	}

	// Per-model rows.
	var modelRows strings.Builder
	s.stats.modelsMu.RLock()
	for k, m := range s.stats.models {
		verifyMs := m.lastVerifyMs.Load()
		var verifyStr string
		if verifyMs > 0 {
			verifyStr = fmt.Sprintf("%dms", verifyMs)
		} else {
			verifyStr = "—"
		}
		var agoStr string
		if lastReq := m.lastRequestAt.Load(); lastReq > 0 {
			agoStr = time.Since(time.Unix(lastReq, 0)).Truncate(time.Second).String() + " ago"
		} else {
			agoStr = "—"
		}
		fmt.Fprintf(&modelRows,
			"  <tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(k), m.requests.Load(), m.errors.Load(), verifyStr, agoStr)
	}
	s.stats.modelsMu.RUnlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>teep</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 20px; color: #222; line-height: 1.6; }
  h1 { font-size: 1.4em; }
  h2 { font-size: 1.1em; margin-top: 1.5em; }
  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
  table { border-collapse: collapse; width: 100%%; }
  td, th { text-align: left; padding: 4px 12px 4px 0; }
  th { color: #666; font-weight: normal; }
  .muted { color: #888; font-size: 0.85em; }
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0; }
  .stat-grid table { width: auto; }
</style>
</head>
<body>
<h1>teep</h1>
<p>TEE attestation proxy on <code>%s</code> &mdash; up %s</p>

<h2>Provider</h2>
<table>
  <tr><th>Name</th><td>%s</td></tr>
  <tr><th>Upstream</th><td>%s</td></tr>
  <tr><th>E2EE</th><td>%s</td></tr>
</table>

<h2>Requests</h2>
<div class="stat-grid">
<table>
  <tr><th>Total</th><td>%d</td></tr>
  <tr><th>Streaming</th><td>%d</td></tr>
  <tr><th>Non-stream</th><td>%d</td></tr>
</table>
<table>
  <tr><th>E2EE</th><td>%d</td></tr>
  <tr><th>Plaintext</th><td>%d</td></tr>
  <tr><th>Errors</th><td>%d</td></tr>
</table>
</div>

<h2>Attestation Cache</h2>
<table>
  <tr><th>Entries</th><td>%d</td></tr>
  <tr><th>Negative</th><td>%d</td></tr>
  <tr><th>Hit rate</th><td>%s (%d hit, %d miss)</td></tr>
</table>

<h2>Models</h2>
<table>
  <tr><th>Model</th><th>Requests</th><th>Errors</th><th>Verify</th><th>Last request</th></tr>
%s</table>

<h2>Endpoints</h2>
<table>
  <tr><td><code>POST /v1/chat/completions</code></td><td>Proxy with TEE attestation</td></tr>
  <tr><td><code>GET /v1/models</code></td><td>List models</td></tr>
  <tr><td><code>GET /v1/tee/report</code></td><td>Cached attestation report</td></tr>
</table>

<p class="muted">Auto-refreshes every 5s. Point any OpenAI-compatible client at <code>http://%s/v1</code></p>
</body>
</html>
`, s.cfg.ListenAddr, uptime,
		provName, baseURL, e2ee,
		requests, streaming, nonStream,
		e2eeCount, plainCount, errCount,
		s.cache.Len(), s.negCache.Len(),
		hitRate, hits, misses,
		modelRows.String(),
		s.cfg.ListenAddr)
}

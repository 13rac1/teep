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
//  5. Any enforced factor Fail (not in allow_fail) → 502 with report JSON.
//  6. If E2EE and tdx_reportdata_binding Pass: encrypt messages, set headers.
//     If E2EE required but binding fails: block request (no plaintext fallback).
//  7. Forward to upstream. Parse streaming SSE or buffer non-streaming body.
//  8. Decrypt each chunk (E2EE). Abort on any decryption failure.
//  9. Re-emit SSE to client (streaming) or return assembled JSON (non-streaming).
//
// 10. Zero session key material.
package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
	chutesProvider "github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/reqid"
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

	// chutesMaxAttempts is the maximum number of Chutes E2EE upstream
	// attempts. Retries attempt failover to a different instance from the
	// nonce pool when available, with full E2EE re-encryption. Failover is
	// acceptable because every instance's key is verified via TDX attestation
	// before use.
	chutesMaxAttempts = 3
)

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
	lastTokCount  atomic.Int64 // effective tokens from last request
	lastTokDurMs  atomic.Int64 // stream duration in milliseconds
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

// recordTokPerSec stores raw token count and duration from StreamStats.
// Tokens/sec is computed at render time in buildDashboardData.
func recordTokPerSec(ms *modelStats, ss e2ee.StreamStats) {
	if ss.Duration <= 0 {
		return
	}
	ms.lastTokCount.Store(int64(ss.EffectiveTokens()))
	ms.lastTokDurMs.Store(ss.Duration.Milliseconds())
}

// fmtDur formats a duration as seconds with 3 decimal places (e.g. "4.200s").
func fmtDur(d time.Duration) string {
	return fmt.Sprintf("%.3fs", d.Seconds())
}

// chutesRetryableError returns true if the upstream error or response status
// indicates a Chutes instance-level failure that warrants failover to a
// different instance. Returns false for client-induced cancellations
// (context.Canceled) so we don't burn retries after the caller is gone.
func chutesRetryableError(err error, resp *http.Response) bool {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false // client disconnected; retrying is pointless
		}
		return true // connection error, timeout, etc.
	}
	if resp == nil {
		return true
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// respStatusCode returns the HTTP status code from a response, or 0 if nil.
func respStatusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// upstreamBody holds the result of buildUpstreamBody: the encrypted (or
// plaintext) body, any E2EE session state, and Chutes instance tracking IDs
// for the retry loop's MarkFailed calls.
type upstreamBody struct {
	Body       []byte
	Session    e2ee.Decryptor
	Meta       *e2ee.ChutesE2EE
	ChuteID    string // For MarkFailed (from raw attestation, not meta)
	InstanceID string // For MarkFailed (from raw attestation, not meta)
}

// zeroE2EESessions zeroes crypto material from a failed E2EE attempt.
func zeroE2EESessions(session e2ee.Decryptor, meta *e2ee.ChutesE2EE) {
	if session != nil {
		session.Zero()
	}
	if meta != nil && meta.Session != nil {
		meta.Session.Zero()
	}
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
	sseConns        atomic.Int64 // active SSE /events connections
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
		mDefaults, gwDefaults := defaults.MeasurementDefaults(name)
		mergedPolicy := config.MergedMeasurementPolicy(name, cfg, mDefaults)
		mergedGWPolicy := config.MergedGatewayMeasurementPolicy(name, cfg, gwDefaults)
		p, err := fromConfig(cp, spkiCache, cfg.Offline, config.MergedAllowFail(name, cfg), mergedPolicy, mergedGWPolicy, s.rekorClient, s.pocSigningKey)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}
		s.providers[name] = p
		slog.Info("registered provider", "provider", name, "base_url", cp.BaseURL, "api_key", config.RedactKey(cp.APIKey), "e2ee", cp.E2EE)
	}

	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /events", s.handleEvents)
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
		Handler:           s,
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
// Unmatched routes are logged before returning 404.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w}
	s.mux.ServeHTTP(rec, r)
	if rec.status == http.StatusNotFound {
		ctx := reqid.WithID(r.Context(), reqid.New())
		slog.WarnContext(ctx, "unmatched route", "method", r.Method, "path", r.URL.Path)
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
// It implements http.Flusher by delegating to the underlying writer.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// fromConfig constructs a provider.Provider from a config.Provider, attaching
// the correct Attester, Preparer, and PinnedHandler for the known provider names.
func fromConfig(
	cp *config.Provider,
	spkiCache *attestation.SPKICache,
	offline bool,
	allowFail []string,
	policy attestation.MeasurementPolicy,
	gatewayPolicy attestation.MeasurementPolicy,
	rekorClient *attestation.RekorClient,
	pocSigningKey ed25519.PublicKey,
) (*provider.Provider, error) {
	p := &provider.Provider{
		Name:                     cp.Name,
		BaseURL:                  cp.BaseURL,
		APIKey:                   cp.APIKey,
		E2EE:                     cp.E2EE,
		MeasurementPolicy:        policy,
		GatewayMeasurementPolicy: gatewayPolicy,
	}
	switch cp.Name {
	case "venice":
		p.ChatPath = "/api/v1/chat/completions"
		p.Attester = venice.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.Preparer = venice.NewPreparer(cp.APIKey)
		p.Encryptor = venice.NewE2EE()
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
			allowFail,
			policy,
			rdVerifier,
			rekorClient,
		)
		p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
	case "nearcloud":
		p.ChatPath = "/v1/chat/completions"
		p.Encryptor = nearcloud.NewE2EE()
		rdVerifier := neardirect.ReportDataVerifier{}
		p.Attester = nearcloud.NewAttester(cp.APIKey, offline)
		p.Preparer = neardirect.NewPreparer(cp.APIKey)
		p.ReportDataVerifier = rdVerifier
		p.SupplyChainPolicy = nearcloud.SupplyChainPolicy()
		p.PinnedHandler = nearcloud.NewPinnedHandler(
			spkiCache,
			cp.APIKey,
			offline,
			allowFail,
			policy,
			gatewayPolicy,
			rdVerifier,
			rekorClient,
			pocSigningKey,
		)
		p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
	case "nanogpt":
		p.ChatPath = "/v1/chat/completions"
		p.Attester = nanogpt.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.ReportDataVerifier = multi.Verifier{
			Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
				attestation.FormatDstack: venice.ReportDataVerifier{},
			},
		}
		p.SupplyChainPolicy = nanogpt.SupplyChainPolicy()
	case "phalacloud":
		p.ChatPath = "/chat/completions"
		p.Attester = phalacloud.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.Preparer = phalacloud.NewPreparer(cp.APIKey)
		p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
		p.ReportDataVerifier = multi.Verifier{
			Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
				attestation.FormatDstack: venice.ReportDataVerifier{},
			},
		}
		p.SupplyChainPolicy = nil // no supply chain policy yet
	case "chutes":
		p.BaseURL = chutesProvider.DefaultLLMBaseURL
		p.ChatPath = "/v1/chat/completions"
		p.SkipSigningKeyCache = true
		attester := chutesProvider.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.Attester = attester
		p.Encryptor = chutesProvider.NewE2EE()
		p.Preparer = chutesProvider.NewPreparer(cp.APIKey, p.ChatPath, cp.BaseURL)
		p.ReportDataVerifier = chutesProvider.ReportDataVerifier{}
		p.SupplyChainPolicy = nil // cosign+IMA model, no docker-compose
		p.ModelLister = chutesProvider.NewModelLister(chutesProvider.DefaultModelsBaseURL, cp.APIKey, config.NewAttestationClient(offline))
		p.E2EEMaterialFetcher = chutesProvider.NewNoncePool(
			cp.BaseURL, cp.APIKey, attester.Resolver(), config.NewAttestationClient(offline),
		)
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, neardirect, nearcloud, nanogpt, phalacloud, chutes)", cp.Name)
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
		slog.ErrorContext(ctx, "provider has no Attester", "provider", prov.Name, "model", upstreamModel)
		s.negCache.Record(prov.Name, upstreamModel)
		return nil, nil
	}

	totalStart := time.Now()
	nonce := attestation.NewNonce()

	slog.DebugContext(ctx, "attestation fetch starting", "provider", prov.Name, "model", upstreamModel)
	fetchStart := time.Now()
	raw, err := prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
	if err != nil {
		slog.ErrorContext(ctx, "attestation fetch failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		s.negCache.Record(prov.Name, upstreamModel)
		return nil, nil
	}
	fetchDur := time.Since(fetchStart)
	slog.DebugContext(ctx, "attestation fetch complete", "provider", prov.Name, "elapsed", fetchDur)

	tdxResult, tdxDur := s.verifyTDX(ctx, raw, nonce, prov)
	nvidiaResult, nvidiaDur := verifyNVIDIA(ctx, raw, nonce, prov.Name)
	nrasResult, nrasDur := s.verifyNVIDIAOnline(ctx, raw, prov.Name)
	pocResult, pocDur := s.verifyPoC(ctx, raw, prov.Name)
	sc, composeDur := s.verifySupplyChain(ctx, raw, tdxResult)

	totalDur := time.Since(totalStart)
	slog.InfoContext(ctx, "verification complete",
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
		AllowFail:         config.MergedAllowFail(prov.Name, s.cfg),
		Policy:            prov.MeasurementPolicy,
		GatewayPolicy:     prov.GatewayMeasurementPolicy,
		SupplyChainPolicy: prov.SupplyChainPolicy,
		ImageRepos:        sc.ImageRepos,
		DigestToRepo:      sc.DigestToRepo,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Compose:           sc.Compose,
		Sigstore:          sc.Sigstore,
		Rekor:             sc.Rekor,
		E2EEConfigured:    prov.E2EE,
	})
	return report, raw
}

// verifyTDX runs TDX quote verification and REPORTDATA binding.
func (s *Server) verifyTDX(
	ctx context.Context,
	raw *attestation.RawAttestation,
	nonce attestation.Nonce,
	prov *provider.Provider,
) (*attestation.TDXVerifyResult, time.Duration) {
	if raw.IntelQuote == "" {
		return nil, 0
	}
	slog.DebugContext(ctx, "TDX verification starting", "provider", prov.Name)
	start := time.Now()
	result := attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, s.cfg.Offline)
	if prov.ReportDataVerifier != nil && result.ParseErr == nil {
		detail, err := prov.ReportDataVerifier.VerifyReportData(result.ReportData, raw, nonce)
		if errors.Is(err, multi.ErrNoVerifier) {
			slog.DebugContext(ctx, "no REPORTDATA verifier for backend format", "format", raw.BackendFormat)
		} else {
			result.ReportDataBindingErr = err
			result.ReportDataBindingDetail = detail
		}
	}
	dur := time.Since(start)
	slog.DebugContext(ctx, "TDX verification complete", "provider", prov.Name, "elapsed", dur)
	return result, dur
}

// verifyNVIDIA runs offline NVIDIA payload or GPU direct verification.
func verifyNVIDIA(
	ctx context.Context,
	raw *attestation.RawAttestation,
	nonce attestation.Nonce,
	provName string,
) (*attestation.NvidiaVerifyResult, time.Duration) {
	if raw.NvidiaPayload != "" {
		slog.DebugContext(ctx, "NVIDIA verification starting", "provider", provName)
		start := time.Now()
		result := attestation.VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		dur := time.Since(start)
		slog.DebugContext(ctx, "NVIDIA verification complete", "provider", provName, "elapsed", dur)
		return result, dur
	}
	if len(raw.GPUEvidence) > 0 {
		slog.DebugContext(ctx, "NVIDIA GPU direct verification starting", "provider", provName, "gpus", len(raw.GPUEvidence))
		serverNonce, err := attestation.ParseNonce(raw.Nonce)
		if err != nil {
			return &attestation.NvidiaVerifyResult{
				SignatureErr: fmt.Errorf("parse server nonce: %w", err),
			}, 0
		}
		start := time.Now()
		result := attestation.VerifyNVIDIAGPUDirect(raw.GPUEvidence, serverNonce)
		dur := time.Since(start)
		slog.DebugContext(ctx, "NVIDIA GPU direct verification complete", "provider", provName, "elapsed", dur)
		return result, dur
	}
	return nil, 0
}

// verifyNVIDIAOnline runs NVIDIA NRAS online verification.
func (s *Server) verifyNVIDIAOnline(
	ctx context.Context,
	raw *attestation.RawAttestation,
	provName string,
) (*attestation.NvidiaVerifyResult, time.Duration) {
	if s.cfg.Offline {
		return nil, 0
	}
	if raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting", "provider", provName)
		start := time.Now()
		result := attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, s.attestClient)
		dur := time.Since(start)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete", "provider", provName, "elapsed", dur)
		return result, dur
	}
	if len(raw.GPUEvidence) > 0 {
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting (synthesized EAT)", "provider", provName)
		eatJSON := attestation.GPUEvidenceToEAT(raw.GPUEvidence, raw.Nonce)
		start := time.Now()
		result := attestation.VerifyNVIDIANRAS(ctx, eatJSON, s.attestClient)
		dur := time.Since(start)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete (synthesized EAT)", "provider", provName, "elapsed", dur)
		return result, dur
	}
	return nil, 0
}

// verifyPoC runs the Proof of Cloud check against quorum peers.
func (s *Server) verifyPoC(
	ctx context.Context,
	raw *attestation.RawAttestation,
	provName string,
) (*attestation.PoCResult, time.Duration) {
	if s.cfg.Offline || raw.IntelQuote == "" {
		return nil, 0
	}
	slog.DebugContext(ctx, "Proof of Cloud check starting", "provider", provName)
	start := time.Now()
	poc := attestation.NewPoCClientWithSigningKey(attestation.PoCPeers, attestation.PoCQuorum, s.attestClient, s.pocSigningKey)
	result := poc.CheckQuote(ctx, raw.IntelQuote)
	dur := time.Since(start)
	slog.DebugContext(ctx, "Proof of Cloud check complete", "provider", provName, "elapsed", dur,
		"registered", result != nil && result.Registered)
	return result, dur
}

// supplyChainResult holds the outputs of compose binding, sigstore, and rekor
// verification. Zero value is safe to use (nil slices/maps/pointers).
type supplyChainResult struct {
	Compose      *attestation.ComposeBindingResult
	Sigstore     []attestation.SigstoreResult
	ImageRepos   []string
	DigestToRepo map[string]string
	Rekor        []attestation.RekorProvenance
}

// verifySupplyChain runs compose binding, sigstore digest, and rekor provenance checks.
func (s *Server) verifySupplyChain(
	ctx context.Context,
	raw *attestation.RawAttestation,
	tdxResult *attestation.TDXVerifyResult,
) (supplyChainResult, time.Duration) {
	if raw.AppCompose == "" || tdxResult == nil || tdxResult.ParseErr != nil {
		return supplyChainResult{}, 0
	}
	start := time.Now()
	sc := supplyChainResult{
		Compose: &attestation.ComposeBindingResult{Checked: true},
	}
	sc.Compose.Err = attestation.VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)

	if sc.Compose.Err == nil {
		cd := attestation.ExtractComposeDigests(raw.AppCompose)
		sc.ImageRepos = cd.Repos
		sc.DigestToRepo = cd.DigestToRepo
		if len(cd.Digests) > 0 && !s.cfg.Offline {
			sc.Sigstore = s.rekorClient.CheckSigstoreDigests(ctx, cd.Digests)
		}
	}

	if len(sc.Sigstore) > 0 && !s.cfg.Offline {
		for _, sr := range sc.Sigstore {
			if sr.OK {
				sc.Rekor = append(sc.Rekor, s.rekorClient.FetchRekorProvenance(ctx, sr.Digest))
			}
		}
	}

	return sc, time.Since(start)
}

// handleChatCompletions is the core proxy handler for POST /v1/chat/completions.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())
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
		slog.InfoContext(ctx, "request complete",
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
		s.handlePinnedChat(ctx, w, r, prov, upstreamModel, body, req)
		return
	}

	ar, failStatus := s.attestAndCache(ctx, w, prov, upstreamModel, ms)
	attestDur = ar.AttestDur
	if failStatus != "" {
		status = failStatus
		return
	}
	report := ar.Report

	ur, err := s.doUpstreamRoundtrip(ctx, prov, body, upstreamModel, ar.E2EEActive, ar.Raw, req.Stream)
	e2eeDur = ur.E2EEDur
	upstreamDur = ur.UpstreamDur
	if err != nil {
		status = "upstream_failed"
		code := http.StatusBadGateway
		if he := (*httpError)(nil); errors.As(err, &he) {
			status = he.status
			code = he.code
		}
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		slog.ErrorContext(ctx, "upstream roundtrip failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, "upstream request failed", code)
		return
	}
	resp := ur.Resp
	session := ur.Session
	meta := ur.Meta
	defer ur.Cancel()
	if session != nil {
		defer session.Zero()
	}
	if meta != nil && meta.Session != nil {
		defer meta.Session.Zero()
	}

	upstreamRelayStart := time.Now()
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

	// E2EE forces stream=true upstream (Venice/NearCloud) or uses /e2e/invoke
	// (Chutes), so the response is always SSE. When the client requested
	// non-streaming, reassemble the decrypted SSE chunks into a single JSON response.
	//
	// Fail closed: if Chutes E2EE metadata was populated (meta != nil) but
	// the session is missing, something went wrong during key encapsulation.
	// Forwarding the ciphertext response as plaintext would leak confidential
	// data, so we abort.
	if meta != nil && meta.Session == nil {
		status = "e2ee_session_missing"
		s.stats.errors.Add(1)
		if ms != nil {
			ms.errors.Add(1)
		}
		slog.ErrorContext(ctx, "e2ee session missing; aborting response", "status", status)
		http.Error(w, "e2ee session not established", http.StatusInternalServerError)
		return
	}
	ss := relayResponse(ctx, w, resp.Body, session, meta, req.Stream)
	recordTokPerSec(ms, ss)
	upstreamDur += time.Since(upstreamRelayStart)

	// After a successful E2EE roundtrip, promote the cached report's
	// e2ee_usable factor from Skip to Pass so that subsequent report
	// fetches reflect the live test result.
	//
	// TODO(e2ee_usable): This mutates a shared *VerificationReport pointer
	// returned by cache.Get, which can race with concurrent requests reading
	// the same report (e.g. /v1/tee/report or parallel chat requests).
	// The report should be deep-copied before mutation, or the e2ee_usable
	// lifecycle should be separated from the report factor system entirely.
	// See docs/plans/e2ee_usable_refactoring.md.
	if ar.E2EEActive {
		report.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.cache.Put(prov.Name, upstreamModel, report)
	}

	status = "ok"
}

// handlePinnedChat handles chat completions for connection-pinned providers.
// Attestation and chat happen on the same TLS connection via PinnedHandler.
func (s *Server) handlePinnedChat(
	ctx context.Context,
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
			slog.ErrorContext(ctx, "E2EE required but tdx_reportdata_binding not passed; refusing request",
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
		slog.ErrorContext(ctx, "pinned chat failed", "provider", prov.Name, "model", upstreamModel, "err", err)
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
	// E2EE providers must always have a report to verify REPORTDATA binding.
	// Without one (e.g. attestation cache expired while SPKI cache is live),
	// we cannot verify the signing key is bound to the TDX quote.
	if prov.E2EE && report == nil {
		s.negCache.Record(prov.Name, upstreamModel)
		slog.ErrorContext(ctx, "E2EE required but no attestation report available",
			"provider", prov.Name, "model", upstreamModel)
		http.Error(w, "E2EE required but no attestation report available; refusing request", http.StatusBadGateway)
		return
	}
	if !s.enforceReport(ctx, w, report, prov, upstreamModel) {
		s.negCache.Record(prov.Name, upstreamModel)
		return
	}
	// E2EE providers require REPORTDATA binding even on first request (SPKI
	// miss). Without it a MITM can substitute the enclave public key and
	// E2EE degrades to plaintext.
	if prov.E2EE && !report.ReportDataBindingPassed() {
		s.negCache.Record(prov.Name, upstreamModel)
		slog.ErrorContext(ctx, "E2EE required but tdx_reportdata_binding not passed; refusing request",
			"provider", prov.Name, "model", upstreamModel)
		http.Error(w, "E2EE required but REPORTDATA binding not verified; refusing plaintext", http.StatusBadGateway)
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

	ms := s.stats.getModelStats(prov.Name, upstreamModel)
	session := pinnedResp.Session
	if session != nil {
		s.stats.e2ee.Add(1)
		defer session.Zero()
	} else {
		s.stats.plaintext.Add(1)
	}
	ss := relayResponse(ctx, w, pinnedResp.Body, session, nil, req.Stream)
	recordTokPerSec(ms, ss)

	// After a successful E2EE roundtrip on the pinned path,
	// promote e2ee_usable from Skip to Pass in the cached report.
	//
	// TODO(e2ee_usable): Same cache mutation race as the non-pinned
	// path — see the comment there and
	// docs/plans/e2ee_usable_refactoring.md.
	if session != nil && report != nil {
		report.MarkE2EEUsable("E2EE roundtrip succeeded via pinned connection")
		s.cache.Put(prov.Name, upstreamModel, report)
	}
}

// attestResult holds the outcome of attestAndCache on success.
type attestResult struct {
	Report     *attestation.VerificationReport
	Raw        *attestation.RawAttestation
	E2EEActive bool
	AttestDur  time.Duration
}

// attestAndCache checks the attestation cache, fetches and verifies on miss,
// enforces the report, caches the signing key, and determines E2EE status.
// On failure it writes the HTTP error response, increments error stats, and
// returns a non-empty status string. On success it returns (result, "").
func (s *Server) attestAndCache(
	ctx context.Context,
	w http.ResponseWriter,
	prov *provider.Provider,
	upstreamModel string,
	ms *modelStats,
) (result *attestResult, failStatus string) {
	attestStart := time.Now()
	var raw *attestation.RawAttestation
	report, cached := s.cache.Get(prov.Name, upstreamModel)
	if cached {
		s.stats.cacheHits.Add(1)
	} else {
		s.stats.cacheMisses.Add(1)
		report, raw = s.fetchAndVerify(ctx, prov, upstreamModel)
		if report == nil {
			s.stats.errors.Add(1)
			ms.errors.Add(1)
			http.Error(w, "attestation fetch failed; see server logs", http.StatusBadGateway)
			return &attestResult{AttestDur: time.Since(attestStart)}, "attest_failed"
		}
		s.cache.Put(prov.Name, upstreamModel, report)
	}

	if !s.enforceReport(ctx, w, report, prov, upstreamModel) {
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		return &attestResult{AttestDur: time.Since(attestStart)}, "blocked"
	}

	// Only cache the signing key after attestation passes. Caching before
	// the Blocked() check would allow a key from a failed attestation to
	// be reused for E2EE on a subsequent cache-hit request.
	if raw != nil && raw.SigningKey != "" {
		if prev, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); ok && subtle.ConstantTimeCompare([]byte(prev), []byte(raw.SigningKey)) == 0 {
			slog.WarnContext(ctx, "signing key rotated (VM restart?)", "provider", prov.Name, "model", upstreamModel)
		}
		s.signingKeyCache.Put(prov.Name, upstreamModel, raw.SigningKey)
	}

	e2eeActive := prov.E2EE && report.ReportDataBindingPassed()
	if e2eeActive {
		s.stats.e2ee.Add(1)
	} else {
		s.stats.plaintext.Add(1)
	}

	return &attestResult{
		Report:     report,
		Raw:        raw,
		E2EEActive: e2eeActive,
		AttestDur:  time.Since(attestStart),
	}, ""
}

// enforceReport checks whether a verification report is blocked. If --force is
// set, logs a warning and returns true (proceed). Otherwise writes a 502 JSON
// response and returns false (request handled). Returns true for nil reports.
func (s *Server) enforceReport(ctx context.Context, w http.ResponseWriter,
	report *attestation.VerificationReport, prov *provider.Provider, model string,
) bool {
	if report == nil || !report.Blocked() {
		return true
	}
	if s.cfg.Force {
		slog.WarnContext(ctx, "--force: bypassing blocked attestation",
			"provider", prov.Name, "model", model,
			"e2ee_will_activate", report.ReportDataBindingPassed())
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	if err := json.NewEncoder(w).Encode(report); err != nil {
		slog.ErrorContext(ctx, "encode response", "error", err)
	}
	return false
}

// relayResponse dispatches the upstream response to the correct relay function
// based on E2EE session type (Chutes meta, Venice/NearCloud session, or
// plaintext) and streaming mode.
func relayResponse(ctx context.Context, w http.ResponseWriter, body io.Reader,
	session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool,
) e2ee.StreamStats {
	switch {
	case meta != nil && meta.Session != nil && stream:
		return e2ee.RelayStreamChutes(ctx, w, body, meta.Session)
	case meta != nil && meta.Session != nil:
		e2ee.RelayNonStreamChutes(ctx, w, body, meta.Session)
		return e2ee.StreamStats{}
	case session != nil && stream:
		return e2ee.RelayStream(ctx, w, body, session)
	case session != nil:
		return e2ee.RelayReassembledNonStream(ctx, w, body, session)
	case stream:
		return e2ee.RelayStream(ctx, w, body, nil)
	default:
		e2ee.RelayNonStream(ctx, w, body, nil)
		return e2ee.StreamStats{}
	}
}

// httpError wraps an error with an HTTP status code for doUpstreamRoundtrip.
type httpError struct {
	code   int
	status string // metric status, e.g. "e2ee_failed", "upstream_failed"
	err    error
}

func (e *httpError) Error() string { return e.err.Error() }
func (e *httpError) Unwrap() error { return e.err }

// upstreamResult holds the outcome of doUpstreamRoundtrip. Always returned
// (even on error) so callers can extract partial timing for metrics.
type upstreamResult struct {
	Resp        *http.Response
	Session     e2ee.Decryptor
	Meta        *e2ee.ChutesE2EE
	Cancel      context.CancelFunc
	E2EEDur     time.Duration
	UpstreamDur time.Duration
}

// doUpstreamRoundtrip builds the upstream body, sends it, and handles Chutes
// retry/failover. On error it cleans up all resources (crypto material, response
// bodies, contexts) and returns the error. On success the caller owns cleanup.
func (s *Server) doUpstreamRoundtrip(
	ctx context.Context,
	prov *provider.Provider,
	body []byte,
	upstreamModel string,
	e2eeActive bool,
	raw *attestation.RawAttestation,
	stream bool,
) (*upstreamResult, error) {
	upstreamURL := prov.BaseURL + prov.ChatPath
	upstreamTimeout := upstreamStreamTimeout
	if !stream {
		upstreamTimeout = upstreamNonStreamTimeout
	}

	chutesRetry := e2eeActive && prov.E2EEMaterialFetcher != nil && prov.SkipSigningKeyCache
	maxAttempts := 1
	if chutesRetry {
		maxAttempts = chutesMaxAttempts
	}

	var (
		session     e2ee.Decryptor
		meta        *e2ee.ChutesE2EE
		resp        *http.Response
		cancel      context.CancelFunc
		err         error
		e2eeDur     time.Duration
		upstreamDur time.Duration
	)

	for attempt := range maxAttempts {
		// On retry, force buildUpstreamBody to use the nonce pool (different
		// instance) instead of the raw attestation from the initial fetch.
		freshRaw := raw
		if attempt > 0 {
			freshRaw = nil
		}

		e2eeStart := time.Now()
		ub, buildErr := s.buildUpstreamBody(ctx, body, upstreamModel, e2eeActive, prov, freshRaw)
		e2eeDur += time.Since(e2eeStart)

		if buildErr != nil {
			err = buildErr
			if attempt < maxAttempts-1 && !errors.Is(err, context.Canceled) {
				slog.WarnContext(ctx, "chutes: E2EE body build failed, retrying",
					"provider", prov.Name, "model", upstreamModel, "attempt", attempt+1, "err", err)
				continue
			}
			return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur},
				&httpError{http.StatusInternalServerError, "e2ee_failed", fmt.Errorf("build upstream body: %w", err)}
		}

		session = ub.Session
		meta = ub.Meta

		var attemptCtx context.Context
		attemptCtx, cancel = context.WithTimeout(ctx, upstreamTimeout)

		upstreamReq, reqErr := http.NewRequestWithContext(attemptCtx, http.MethodPost, upstreamURL, bytes.NewReader(ub.Body))
		if reqErr != nil {
			cancel()
			zeroE2EESessions(session, meta)
			return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur},
				&httpError{http.StatusInternalServerError, "e2ee_failed", fmt.Errorf("build upstream request: %w", reqErr)}
		}
		upstreamReq.Header.Set("Content-Type", "application/json")

		if prepErr := prepareUpstreamHeaders(upstreamReq, prov, session, meta, stream); prepErr != nil {
			cancel()
			zeroE2EESessions(session, meta)
			return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur},
				&httpError{http.StatusInternalServerError, "e2ee_failed", fmt.Errorf("prepare upstream headers: %w", prepErr)}
		}

		upstreamDoStart := time.Now()
		resp, err = s.upstreamClient.Do(upstreamReq)
		upstreamDur += time.Since(upstreamDoStart)

		retryable := chutesRetryableError(err, resp)

		// Mark the instance as failed so the nonce pool deprioritises it
		// on subsequent requests, even on the final attempt.
		if retryable && ub.InstanceID != "" && prov.E2EEMaterialFetcher != nil {
			prov.E2EEMaterialFetcher.MarkFailed(ub.ChuteID, ub.InstanceID)
		}

		if attempt < maxAttempts-1 && retryable {
			cancel()
			if ub.InstanceID != "" {
				slog.WarnContext(ctx, "chutes: upstream attempt failed, trying different instance",
					"provider", prov.Name, "model", upstreamModel,
					"instance_id", ub.InstanceID, "attempt", attempt+1,
					"err", err, "status", respStatusCode(resp))
			}
			zeroE2EESessions(session, meta)
			if resp != nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
				resp.Body.Close()
				resp = nil
			}
			continue
		}
		break
	}

	if err != nil {
		if cancel != nil {
			cancel()
		}
		zeroE2EESessions(session, meta)
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
			resp.Body.Close()
		}
		return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur},
			&httpError{http.StatusBadGateway, "upstream_failed", fmt.Errorf("upstream request: %w", err)}
	}

	return &upstreamResult{
		Resp:        resp,
		Session:     session,
		Meta:        meta,
		Cancel:      cancel,
		E2EEDur:     e2eeDur,
		UpstreamDur: upstreamDur,
	}, nil
}

// buildUpstreamBody constructs the body to forward upstream. If e2eeActive is
// true it delegates encryption to the provider's Encryptor.
//
// When freshRaw is non-nil (cache miss path), its signing key is reused — the
// REPORTDATA binding was already verified by fetchAndVerify. When freshRaw is
// nil (cache hit), a fresh attestation is fetched and re-verified.
func (s *Server) buildUpstreamBody(
	ctx context.Context,
	rawBody []byte,
	upstreamModel string,
	e2eeActive bool,
	prov *provider.Provider,
	freshRaw *attestation.RawAttestation,
) (*upstreamBody, error) {
	if !e2eeActive {
		if prov.E2EE {
			return nil, fmt.Errorf("E2EE required for %s but tdx_reportdata_binding not passed; refusing plaintext", prov.Name)
		}
		return &upstreamBody{Body: rawBody}, nil
	}

	raw := freshRaw
	if raw == nil {
		// Cache hit path: try the signing key cache before re-fetching attestation.
		// Some providers (e.g. Chutes) need fresh instance/nonce data per request.

		// Fast path: providers with a nonce pool (Chutes) can get E2EE
		// material without full re-attestation. The pool provides a fresh
		// instance ID, ML-KEM pubkey, and single-use nonce from cached
		// /e2e/instances data. Full attestation (evidence + TDX verify)
		// was already done in fetchAndVerify and is cached in the report.
		//
		// Only consume from the nonce pool if we already have a cached
		// signing key. This avoids wasting nonces when the signing key
		// cache is cold (fresh attestation is needed anyway). The pool
		// key must match the attested key via constant-time comparison
		// to keep ML-KEM bound to a verified TDX quote.
		if prov.E2EEMaterialFetcher != nil {
			if cachedKey, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); !ok {
				slog.DebugContext(ctx, "E2EE key exchange: no cached signing key; skipping nonce pool",
					"provider", prov.Name, "model", upstreamModel,
				)
				// Fall through to fresh attestation below.
			} else {
				mat, err := prov.E2EEMaterialFetcher.FetchE2EEMaterial(ctx, upstreamModel)
				switch {
				case err != nil:
					slog.ErrorContext(ctx, "E2EE key exchange: failed to fetch nonce pool material; falling back to fresh attestation",
						"provider", prov.Name, "model", upstreamModel,
					)
					// Fall through to fresh attestation below (raw remains nil).
				case subtle.ConstantTimeCompare([]byte(cachedKey), []byte(mat.E2EPubKey)) != 1:
					slog.DebugContext(ctx, "E2EE key exchange: nonce pool key mismatch; invalidating pool",
						"provider", prov.Name, "model", upstreamModel,
						"instance_id", mat.InstanceID,
					)
					prov.E2EEMaterialFetcher.Invalidate(mat.ChuteID)
					// Fall through to fresh attestation below.
				default:
					slog.DebugContext(ctx, "E2EE key exchange: using nonce pool",
						"provider", prov.Name, "model", upstreamModel,
						"instance_id", mat.InstanceID,
					)
					raw = &attestation.RawAttestation{
						SigningKey: mat.E2EPubKey,
						InstanceID: mat.InstanceID,
						E2ENonce:   mat.E2ENonce,
						ChuteID:    mat.ChuteID,
					}
				}
			}
		} else if !prov.SkipSigningKeyCache {
			if cachedKey, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); ok {
				slog.DebugContext(ctx, "E2EE key exchange: using cached signing key", "provider", prov.Name, "model", upstreamModel)
				raw = &attestation.RawAttestation{SigningKey: cachedKey}
			}
		}
		if raw == nil {
			// Signing key not cached: fetch fresh attestation and re-verify.
			slog.DebugContext(ctx, "E2EE key exchange: fetching fresh attestation (cache hit path)", "provider", prov.Name, "model", upstreamModel)
			nonce := attestation.NewNonce()
			var err error
			raw, err = prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
			if err != nil {
				return nil, fmt.Errorf("fetch signing key: %w", err)
			}
			if raw.IntelQuote == "" {
				return nil, errors.New("fresh attestation missing TDX quote; cannot verify signing key binding")
			}
			// offline=true: only REPORTDATA binding is needed here, not full
			// online verification (Intel PCS collateral). The primary
			// fetchAndVerify() path already did online verification for
			// the cached report.
			tdxResult := attestation.VerifyTDXQuote(ctx, raw.IntelQuote, nonce, true)
			if tdxResult.ParseErr != nil {
				return nil, fmt.Errorf("fresh TDX quote parse failed: %w", tdxResult.ParseErr)
			}
			if prov.ReportDataVerifier != nil {
				_, err := prov.ReportDataVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
				if err != nil {
					return nil, fmt.Errorf("fresh signing key REPORTDATA binding failed: %w", err)
				}
			}
			s.signingKeyCache.Put(prov.Name, upstreamModel, raw.SigningKey)
		}
	} else {
		slog.DebugContext(ctx, "E2EE key exchange: reusing attestation from verification (cache miss path)", "provider", prov.Name, "model", upstreamModel)
	}

	if raw.SigningKey == "" {
		return nil, errors.New("attestation response missing signing_key")
	}

	encrypted, session, meta, err := prov.Encryptor.EncryptRequest(rawBody, raw)
	if err != nil {
		return nil, err
	}
	return &upstreamBody{
		Body:       encrypted,
		Session:    session,
		Meta:       meta,
		ChuteID:    raw.ChuteID,
		InstanceID: raw.InstanceID,
	}, nil
}

// prepareUpstreamHeaders injects auth and E2EE headers into the upstream request.
// It builds protocol-specific headers from the Decryptor via type switch, then
// delegates to the provider's Preparer. When no Preparer is configured, it sets
// only the Authorization header.
func prepareUpstreamHeaders(req *http.Request, prov *provider.Provider, session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool) error {
	if prov.Preparer == nil {
		if prov.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+prov.APIKey)
		}
		return nil
	}

	// nil session: plaintext or Chutes (Chutes headers are in meta, not session).
	var e2eeHeaders http.Header
	switch s := session.(type) {
	case *e2ee.VeniceSession:
		e2eeHeaders = make(http.Header)
		e2eeHeaders.Set("X-Venice-Tee-Client-Pub-Key", s.ClientPubKeyHex())
		e2eeHeaders.Set("X-Venice-Tee-Model-Pub-Key", s.ModelKeyHex())
		e2eeHeaders.Set("X-Venice-Tee-Signing-Algo", "ecdsa")
	case *e2ee.NearCloudSession:
		e2eeHeaders = make(http.Header)
		e2eeHeaders.Set("X-Signing-Algo", "ed25519")
		e2eeHeaders.Set("X-Client-Pub-Key", s.ClientEd25519PubHex())
		e2eeHeaders.Set("X-Encryption-Version", "2")
	}
	return prov.Preparer.PrepareRequest(req, e2eeHeaders, meta, stream)
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
	ctx, cancel := context.WithTimeout(reqid.WithID(r.Context(), reqid.New()), modelsTimeout)
	defer cancel()

	all := make([]json.RawMessage, 0)
	for _, p := range s.providers {
		if p.ModelLister == nil {
			continue
		}
		models, err := p.ModelLister.ListModels(ctx)
		if err != nil {
			slog.WarnContext(ctx, "model listing failed", "provider", p.Name, "err", err)
			continue
		}
		all = append(all, models...)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(modelsListResponse{Object: "list", Data: all}); err != nil {
		slog.ErrorContext(ctx, "encoding models response", "err", err)
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

// dashboardData is the JSON-serializable snapshot of all dashboard stats.
// Used by both the initial page render and the SSE /events endpoint.
type dashboardData struct {
	ListenAddr string               `json:"listen_addr"`
	Uptime     string               `json:"uptime"`
	Provider   dashboardProvider    `json:"provider"`
	Requests   dashboardRequests    `json:"requests"`
	Cache      dashboardCache       `json:"cache"`
	Models     map[string]dashModel `json:"models"`
}

type dashboardProvider struct {
	Name     string `json:"name"`
	Upstream string `json:"upstream"`
	E2EE     string `json:"e2ee"`
}

type dashboardRequests struct {
	Total     int64 `json:"total"`
	Streaming int64 `json:"streaming"`
	NonStream int64 `json:"non_stream"`
	E2EE      int64 `json:"e2ee"`
	Plaintext int64 `json:"plaintext"`
	Errors    int64 `json:"errors"`
}

type dashboardCache struct {
	Entries  int    `json:"entries"`
	Negative int    `json:"negative"`
	HitRate  string `json:"hit_rate"`
	Hits     int64  `json:"hits"`
	Misses   int64  `json:"misses"`
}

type dashModel struct {
	Requests    int64  `json:"requests"`
	Errors      int64  `json:"errors"`
	VerifyMs    string `json:"verify_ms"`
	TokPerSec   string `json:"tok_per_sec"`
	LastRequest string `json:"last_request"`
}

func (s *Server) buildDashboardData() dashboardData {
	var provName, baseURL, e2eeStatus string
	for name, p := range s.providers {
		provName = name
		baseURL = p.BaseURL
		if p.E2EE {
			e2eeStatus = "enabled"
		} else {
			e2eeStatus = "disabled"
		}
	}

	hits := s.stats.cacheHits.Load()
	misses := s.stats.cacheMisses.Load()
	var hitRate string
	if total := hits + misses; total > 0 {
		hitRate = fmt.Sprintf("%.0f%%", float64(hits)/float64(total)*100)
	} else {
		hitRate = "—"
	}

	models := make(map[string]dashModel)
	s.stats.modelsMu.RLock()
	for k, m := range s.stats.models {
		var verifyStr string
		if ms := m.lastVerifyMs.Load(); ms > 0 {
			verifyStr = fmt.Sprintf("%dms", ms)
		} else {
			verifyStr = "—"
		}
		var tokStr string
		if dur := m.lastTokDurMs.Load(); dur > 0 {
			tps := float64(m.lastTokCount.Load()) / (float64(dur) / 1000)
			tokStr = fmt.Sprintf("%.1f", tps)
		} else {
			tokStr = "—"
		}
		var agoStr string
		if lastReq := m.lastRequestAt.Load(); lastReq > 0 {
			agoStr = time.Since(time.Unix(lastReq, 0)).Truncate(time.Second).String() + " ago"
		} else {
			agoStr = "—"
		}
		models[k] = dashModel{
			Requests:    m.requests.Load(),
			Errors:      m.errors.Load(),
			VerifyMs:    verifyStr,
			TokPerSec:   tokStr,
			LastRequest: agoStr,
		}
	}
	s.stats.modelsMu.RUnlock()

	return dashboardData{
		ListenAddr: s.cfg.ListenAddr,
		Uptime:     time.Since(s.stats.startTime).Truncate(time.Second).String(),
		Provider: dashboardProvider{
			Name:     provName,
			Upstream: baseURL,
			E2EE:     e2eeStatus,
		},
		Requests: dashboardRequests{
			Total:     s.stats.requests.Load(),
			Streaming: s.stats.streaming.Load(),
			NonStream: s.stats.nonStream.Load(),
			E2EE:      s.stats.e2ee.Load(),
			Plaintext: s.stats.plaintext.Load(),
			Errors:    s.stats.errors.Load(),
		},
		Cache: dashboardCache{
			Entries:  s.cache.Len(),
			Negative: s.negCache.Len(),
			HitRate:  hitRate,
			Hits:     hits,
			Misses:   misses,
		},
		Models: models,
	}
}

// maxSSEConns is the maximum number of concurrent SSE /events connections.
const maxSSEConns = 10

// handleEvents streams dashboard stats as Server-Sent Events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.sseConns.Add(1) > maxSSEConns {
		s.sseConns.Add(-1)
		http.Error(w, "too many SSE connections", http.StatusServiceUnavailable)
		return
	}
	defer s.sseConns.Add(-1)

	ctx := r.Context()
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	send := func(ctx context.Context) bool {
		b, err := json.Marshal(s.buildDashboardData())
		if err != nil {
			slog.ErrorContext(ctx, "marshal dashboard data", "err", err)
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return true
		}
		flusher.Flush()
		return false
	}

	if send(ctx) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if send(ctx) {
				return
			}
		}
	}
}

// handleIndex serves a live stats dashboard at /.
// Initial data is embedded as JSON so the page renders immediately.
// An EventSource connection to /events takes over for live updates.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	initial, err := json.Marshal(s.buildDashboardData())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>teep</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif;
    max-width: 760px; margin: 0 auto; padding: 40px 24px;
    background: #0d1117; color: #c9d1d9; line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  h1 {
    font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, monospace;
    font-size: 1.5em; font-weight: 600; color: #e6edf3; letter-spacing: -0.02em;
  }
  .subtitle { color: #8b949e; font-size: 0.9em; margin-top: 0.25em; }
  h2 {
    font-size: 0.75em; font-weight: 600; color: #8b949e;
    text-transform: uppercase; letter-spacing: 0.08em;
    margin-top: 2em; margin-bottom: 0.5em;
  }
  section {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px 20px;
  }
  code {
    font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, monospace;
    background: #21262d; padding: 2px 6px; border-radius: 4px;
    font-size: 0.85em; color: #58a6ff;
  }
  table { border-collapse: collapse; width: 100%%; }
  td, th {
    text-align: left; padding: 6px 16px 6px 0;
    font-variant-numeric: tabular-nums;
  }
  th { color: #8b949e; font-weight: 400; font-size: 0.9em; }
  td { color: #e6edf3; }
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0; }
  .model-table th {
    border-bottom: 1px solid #30363d; padding-bottom: 8px;
    font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .model-table td {
    border-bottom: 1px solid #21262d; padding: 8px 16px 8px 0;
    font-family: ui-monospace, 'SF Mono', 'Cascadia Code', Menlo, monospace;
    font-size: 0.85em;
  }
  .model-table td:first-child {
    font-family: -apple-system, system-ui, 'Segoe UI', sans-serif; font-size: 0.9em;
  }
  .model-table tr:last-child td { border-bottom: none; }
  .footer {
    color: #484f58; font-size: 0.8em;
    margin-top: 2em; padding-top: 1em; border-top: 1px solid #21262d;
  }
  .footer code { background: transparent; padding: 0; }
  .text-green { color: #3fb950; }
  .text-red { color: #f85149; }
</style>
</head>
<body>
<h1>teep</h1>
<p class="subtitle">TEE attestation proxy on <code id="listen-addr"></code> &mdash; up <span id="uptime"></span></p>

<h2>Provider</h2>
<section>
<table>
  <tr><th>Name</th><td id="prov-name"></td></tr>
  <tr><th>Upstream</th><td id="prov-upstream"></td></tr>
  <tr><th>E2EE</th><td id="prov-e2ee"></td></tr>
</table>
</section>

<h2>Requests</h2>
<section>
<div class="stat-grid">
<table>
  <tr><th>Total</th><td id="req-total"></td></tr>
  <tr><th>Streaming</th><td id="req-streaming"></td></tr>
  <tr><th>Non-stream</th><td id="req-nonstream"></td></tr>
</table>
<table>
  <tr><th>E2EE</th><td id="req-e2ee"></td></tr>
  <tr><th>Plaintext</th><td id="req-plaintext"></td></tr>
  <tr><th>Errors</th><td id="req-errors"></td></tr>
</table>
</div>
</section>

<h2>Attestation Cache</h2>
<section>
<table>
  <tr><th>Entries</th><td id="cache-entries"></td></tr>
  <tr><th>Negative</th><td id="cache-negative"></td></tr>
  <tr><th>Hit rate</th><td id="cache-hitrate"></td></tr>
</table>
</section>

<h2>Models</h2>
<section>
<table class="model-table">
  <tr><th>Model</th><th>Requests</th><th>Errors</th><th>Verify</th><th>Tok/s</th><th>Last request</th></tr>
  <tbody id="model-rows"></tbody>
</table>
</section>

<h2>Endpoints</h2>
<section>
<table>
  <tr><td><code>POST /v1/chat/completions</code></td><td>Proxy with TEE attestation</td></tr>
  <tr><td><code>GET /v1/models</code></td><td>List models</td></tr>
  <tr><td><code>GET /v1/tee/report</code></td><td>Cached attestation report</td></tr>
</table>
</section>

<p class="footer" id="footer"></p>

<script>
function esc(s) {
  var d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function render(d) {
  document.getElementById("listen-addr").textContent = d.listen_addr;
  document.getElementById("uptime").textContent = d.uptime;
  document.getElementById("prov-name").textContent = d.provider.name;
  document.getElementById("prov-upstream").textContent = d.provider.upstream;
  var e2ee = document.getElementById("prov-e2ee");
  e2ee.textContent = d.provider.e2ee;
  e2ee.className = d.provider.e2ee === "enabled" ? "text-green" : "text-red";
  document.getElementById("req-total").textContent = d.requests.total;
  document.getElementById("req-streaming").textContent = d.requests.streaming;
  document.getElementById("req-nonstream").textContent = d.requests.non_stream;
  document.getElementById("req-e2ee").textContent = d.requests.e2ee;
  document.getElementById("req-plaintext").textContent = d.requests.plaintext;
  var errors = document.getElementById("req-errors");
  errors.textContent = d.requests.errors;
  errors.className = d.requests.errors > 0 ? "text-red" : "";
  document.getElementById("cache-entries").textContent = d.cache.entries;
  document.getElementById("cache-negative").textContent = d.cache.negative;
  document.getElementById("cache-hitrate").textContent =
    d.cache.hit_rate + " (" + d.cache.hits + " hit, " + d.cache.misses + " miss)";
  var tbody = document.getElementById("model-rows");
  tbody.innerHTML = "";
  for (var k in d.models) {
    var m = d.models[k];
    var tr = document.createElement("tr");
    var errClass = m.errors > 0 ? " class=\"text-red\"" : "";
    tr.innerHTML = "<td>" + esc(k) + "</td><td>" + m.requests + "</td><td" +
      errClass + ">" + m.errors + "</td><td>" + esc(m.verify_ms) + "</td><td>" +
      esc(m.tok_per_sec) + "</td><td>" + esc(m.last_request) + "</td>";
    tbody.appendChild(tr);
  }
  document.getElementById("footer").innerHTML =
    "Live via SSE. Point any OpenAI-compatible client at <code>http://" + esc(d.listen_addr) + "/v1</code>";
}

render(%s);

var es = new EventSource("/events");
es.onmessage = function(e) { render(JSON.parse(e.data)); };
es.onerror = function() { setTimeout(function() { location.reload(); }, 5000); };
</script>
</body>
</html>
`, initial)
}

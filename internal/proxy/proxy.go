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
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
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

	// HTTP transport counters (reported by countingTransport callbacks).
	httpRequests atomic.Int64
	httpErrors   atomic.Int64

	modelsMu sync.RWMutex
	models   map[string]*modelStats
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

// extractMultipartField reads a single text field from multipart/form-data
// body bytes without consuming an http.Request body. Returns the field value
// or an error if the content-type is not multipart or the field is absent.
func extractMultipartField(contentType string, body []byte, fieldName string) (string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return "", fmt.Errorf("not multipart content-type: %s", contentType)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", errors.New("missing boundary in content-type")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		p, err := mr.NextPart()
		if err != nil {
			return "", err
		}
		if p.FormName() == fieldName {
			val, err := io.ReadAll(io.LimitReader(p, 1024))
			if err != nil {
				return "", err
			}
			return string(val), nil
		}
	}
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
// Content is json.RawMessage because it may be a string (text) or an array
// (multimodal / vision-language). The proxy never inspects message content.
type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// providerModelKey is used as the key in the e2eeFailed sync.Map.
type providerModelKey struct {
	provider string
	model    string
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
	e2eeFailed      sync.Map     // cacheKey → true; tracks provider+model pairs with E2EE decryption failures
	stats           stats
}

// New builds a Server from cfg. Providers are wired with their Attester and
// Preparer implementations based on provider name.
func New(cfg *config.Config) (*Server, error) {
	spkiCache := attestation.NewSPKICache()

	attestClient := tlsct.NewHTTPClientWithTransport(config.AttestationTimeout, &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, !cfg.Offline)

	s := &Server{
		cfg:             cfg,
		providers:       make(map[string]*provider.Provider, len(cfg.Providers)),
		cache:           attestation.NewCache(attestationCacheTTL),
		negCache:        attestation.NewNegativeCache(negativeCacheTTL),
		signingKeyCache: attestation.NewSigningKeyCache(signingKeyCacheTTL),
		spkiCache:       spkiCache,
		mux:             http.NewServeMux(),
		attestClient:    attestClient,
		stats:           stats{startTime: time.Now(), models: make(map[string]*modelStats)},
	}

	onReq := func() { s.stats.httpRequests.Add(1) }
	onErr := func() { s.stats.httpErrors.Add(1) }

	attestClient.Transport = tlsct.WrapCounting(
		tlsct.WrapLogging(attestClient.Transport),
		onReq, onErr)

	upstreamClient := tlsct.NewHTTPClientWithTransport(0, &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, !cfg.Offline)
	upstreamClient.Transport = tlsct.WrapCounting(
		tlsct.WrapLogging(upstreamClient.Transport),
		onReq, onErr)
	s.upstreamClient = upstreamClient

	s.rekorClient = attestation.NewRekorClient(attestClient)

	// Unconditionally set — the proxy always routes PCS fetches through
	// the attestation client for logging and observability.
	// Tests override this directly; they don't call proxy.New.
	attestation.TDXCollateralGetter = attestation.NewCollateralGetter(s.attestClient)

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
	s.mux.HandleFunc("POST /v1/embeddings", s.handleEmbeddings)
	s.mux.HandleFunc("POST /v1/audio/transcriptions", s.handleAudioTranscriptions)
	s.mux.HandleFunc("POST /v1/images/generations", s.handleImagesGenerations)
	s.mux.HandleFunc("POST /v1/rerank", s.handleRerank)
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
		p.EmbeddingsPath = "/v1/embeddings"
		p.AudioPath = "/v1/audio/transcriptions"
		p.ImagesPath = "/v1/images/generations"
		p.RerankPath = "/v1/rerank"
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
		// nearcloud non-chat E2EE is NOT verified: EncryptChatMessagesNearCloud
		// only encrypts the messages array. Embeddings (input), audio, and images
		// (prompt) would be sent in plaintext through a channel the user believes
		// is E2EE. Non-chat paths are not wired until the E2EE protocol is
		// verified to cover those content fields.
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
		p.EmbeddingsPath = "/embeddings"
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
		p.EmbeddingsPath = "/v1/embeddings"
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
		result := attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce)
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
		result := attestation.VerifyNVIDIAGPUDirect(ctx, raw.GPUEvidence, serverNonce)
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

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20) // 50 MiB max
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

	// A prior E2EE failure marks the provider+model pair as failed and also
	// invalidates the cached attestation. Recovery requires a confirmed fresh
	// attestation (cache miss), indicated by ar.Raw != nil.
	if ar.E2EEActive {
		if ok := s.clearE2EEFailureIfFresh(ctx, w, prov, upstreamModel, ar, ms); !ok {
			status = "e2ee_recovery_pending"
			return
		}
	}

	// Chutes E2EE requests can retry the full upstream+relay cycle when an
	// instance fails post-relay (decryption error). The specific instance is
	// marked failed and the next attempt uses a fresh instance from the
	// nonce pool with a new encryption handshake. Non-Chutes paths execute
	// exactly once; post-relay decryption failure marks the provider+model
	// pair as globally failed (fail-closed).
	rr := s.relayWithRetry(ctx, w, prov, upstreamModel, body, ar, ms, req.Stream, prov.ChatPath)
	e2eeDur += rr.e2eeDur
	upstreamDur += rr.upstreamDur
	if rr.status != "" {
		status = rr.status
		return
	}

	// After a successful E2EE roundtrip, promote the cached report's
	// e2ee_usable factor from Skip to Pass so that subsequent report
	// fetches reflect the live test result. Clone before mutating to
	// avoid racing with concurrent readers of the shared cache pointer.
	if ar.E2EEActive {
		cloned := report.Clone()
		cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.cache.Put(prov.Name, upstreamModel, cloned)
	}

	status = "ok"
}

// relayResult holds the outcome of relayWithRetry.
type relayResult struct {
	status      string        // non-empty on terminal failure
	e2eeDur     time.Duration // accumulated E2EE key-exchange time
	upstreamDur time.Duration // accumulated upstream + relay time
}

// relayWithRetry performs the upstream roundtrip and E2EE relay, retrying on
// Chutes instance-level decryption failures. For non-Chutes providers the
// loop executes exactly once.
func (s *Server) relayWithRetry(
	ctx context.Context,
	w http.ResponseWriter,
	prov *provider.Provider,
	upstreamModel string,
	body []byte,
	ar *attestResult,
	ms *modelStats,
	stream bool,
	endpointPath string,
) relayResult {
	chutesE2EE := isChutesE2EE(prov, ar.E2EEActive)
	maxRelayAttempts := 1
	if chutesE2EE {
		maxRelayAttempts = chutesMaxAttempts
	}

	ri, riWriter := newResponseInterceptor(w)
	var ss e2ee.StreamStats
	var relayErr error
	var lastChuteID string // track for post-loop nonce pool invalidation
	var result relayResult

	for relayAttempt := range maxRelayAttempts {
		// On retry, clear raw so doUpstreamRoundtrip uses the nonce pool
		// (different instance) instead of the initial attestation.
		attemptRaw := ar.Raw
		if relayAttempt > 0 {
			attemptRaw = nil
		}

		ur, err := s.doUpstreamRoundtrip(ctx, prov, body, upstreamModel, ar.E2EEActive, attemptRaw, stream, endpointPath)
		result.e2eeDur += ur.E2EEDur
		result.upstreamDur += ur.UpstreamDur
		if err != nil {
			statusStr, code, msg := classifyUpstreamError(err)
			result.status = statusStr
			// For Chutes, upstream failures (transport) are already retried
			// inside doUpstreamRoundtrip. If we get here, all transport
			// retries are exhausted. Continue to the next relay attempt
			// only if we haven't written headers yet.
			if relayAttempt < maxRelayAttempts-1 && !ri.headerSent {
				slog.WarnContext(ctx, "chutes: upstream failed, trying relay attempt with new instance",
					"provider", prov.Name, "model", upstreamModel, "relay_attempt", relayAttempt+1, "err", err)
				continue
			}
			s.stats.errors.Add(1)
			ms.errors.Add(1)
			slog.ErrorContext(ctx, "upstream roundtrip failed", "provider", prov.Name, "model", upstreamModel, "err", err)
			if !ri.headerSent {
				http.Error(w, msg, code)
				return result
			}
			return result
		}
		resp := ur.Resp
		session := ur.Session
		meta := ur.Meta
		if meta != nil && meta.ChuteID != "" {
			lastChuteID = meta.ChuteID
		}

		// cleanupAttempt drains and closes the response body and zeros crypto.
		cleanupAttempt := func() {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
			resp.Body.Close()
			ur.Cancel()
			zeroE2EESessions(session, meta)
		}

		if resp.StatusCode != http.StatusOK {
			// Non-200 upstream: for Chutes, this may be instance-level.
			// doUpstreamRoundtrip already handles retryable HTTP codes, so
			// reaching here means the code is not retryable. Forward as-is.
			if !ri.headerSent {
				result.status = fmt.Sprintf("upstream_%d", resp.StatusCode)
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, io.LimitReader(resp.Body, 10<<20))
			}
			cleanupAttempt()
			return result
		}

		// Fail closed: if Chutes E2EE metadata was populated (meta != nil)
		// but the session is missing, something went wrong during key
		// encapsulation. Forwarding ciphertext as plaintext would leak data.
		if meta != nil && meta.Session == nil {
			cleanupAttempt()
			if relayAttempt < maxRelayAttempts-1 && !ri.headerSent {
				slog.WarnContext(ctx, "chutes: e2ee session missing, trying new instance",
					"provider", prov.Name, "model", upstreamModel, "relay_attempt", relayAttempt+1)
				continue
			}
			result.status = "e2ee_session_missing"
			s.stats.errors.Add(1)
			if ms != nil {
				ms.errors.Add(1)
			}
			slog.ErrorContext(ctx, "e2ee session missing; aborting response", "status", result.status)
			if !ri.headerSent {
				http.Error(w, "e2ee session not established", http.StatusInternalServerError)
				return result
			}
			return result
		}

		upstreamRelayStart := time.Now()
		ss, relayErr = relayResponse(ctx, riWriter, resp.Body, session, meta, stream)
		result.upstreamDur += time.Since(upstreamRelayStart)
		recordTokPerSec(ms, ss)

		// Always drain body and clean up crypto material from this attempt.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		ur.Cancel()
		if session != nil {
			session.Zero()
		}
		if meta != nil && meta.Session != nil {
			meta.Session.Zero()
		}

		if relayErr == nil {
			// Relay succeeded.
			break
		}

		// Relay returned a decryption error.
		if !errors.Is(relayErr, e2ee.ErrDecryptionFailed) {
			break // Non-decryption error; don't retry.
		}

		if chutesE2EE && ur.Meta != nil {
			// Mark the specific Chutes instance as failed so the nonce pool
			// deprioritises it on subsequent requests.
			if ur.Meta.InstanceID != "" && prov.E2EEMaterialFetcher != nil {
				prov.E2EEMaterialFetcher.MarkFailed(ur.Meta.ChuteID, ur.Meta.InstanceID)
				slog.WarnContext(ctx, "chutes: instance E2EE decryption failed, marked unusable",
					"provider", prov.Name, "model", upstreamModel,
					"instance_id", ur.Meta.InstanceID, "chute_id", ur.Meta.ChuteID,
					"relay_attempt", relayAttempt+1, "err", relayErr)
			}
		}

		// Can only retry if we haven't written response headers to the client.
		if relayAttempt < maxRelayAttempts-1 && !ri.headerSent {
			slog.WarnContext(ctx, "chutes: relay decryption failed before headers, retrying with new instance",
				"provider", prov.Name, "model", upstreamModel, "relay_attempt", relayAttempt+1)
			continue
		}
		break
	}

	result.status = s.classifyRelayOutcome(ctx, relayErr, ar.E2EEActive, prov, upstreamModel, ms, chutesE2EE, lastChuteID)
	// Chutes relay functions do not write HTTP error responses for pre-header
	// decryption failures (allowing the retry loop to attempt new instances).
	// Write the error response here after all retries are exhausted.
	if result.status != "" && !ri.headerSent {
		if errors.Is(relayErr, e2ee.ErrDecryptionFailed) {
			http.Error(riWriter, "response decryption failed", http.StatusBadGateway)
		} else {
			http.Error(riWriter, "relay failed", http.StatusBadGateway)
		}
	}
	return result
}

// classifyRelayOutcome handles post-loop relay errors, returning the status
// string (empty on success).
func (s *Server) classifyRelayOutcome(
	ctx context.Context,
	relayErr error,
	e2eeActive bool,
	prov *provider.Provider,
	upstreamModel string,
	ms *modelStats,
	chutesE2EE bool,
	lastChuteID string,
) string {
	if relayErr == nil {
		return ""
	}
	// Post-relay enforcement: handle decryption failures that could not be retried.
	if errors.Is(relayErr, e2ee.ErrDecryptionFailed) && e2eeActive {
		return s.handleE2EEDecryptionFailure(ctx, prov, upstreamModel, ms, chutesE2EE, lastChuteID, relayErr)
	}
	// Non-decryption relay errors (e.g. streaming unsupported, empty
	// upstream, read failures): the error response has already been written
	// to the client. Set status so the caller does not promote e2ee_usable.
	s.stats.errors.Add(1)
	ms.errors.Add(1)
	slog.ErrorContext(ctx, "relay failed", "provider", prov.Name, "model", upstreamModel, "err", relayErr)
	return "relay_failed"
}

// handleE2EEDecryptionFailure records an unretriable E2EE decryption failure,
// invalidates caches, and returns the status string for request logging.
func (s *Server) handleE2EEDecryptionFailure(
	ctx context.Context,
	prov *provider.Provider,
	upstreamModel string,
	ms *modelStats,
	chutesE2EE bool,
	lastChuteID string,
	relayErr error,
) string {
	s.stats.errors.Add(1)
	ms.errors.Add(1)

	if chutesE2EE {
		// For Chutes, per-instance failures are already handled via
		// MarkFailed. Invalidate the nonce pool for this chute so the
		// next request fetches fresh instances.
		if prov.E2EEMaterialFetcher != nil && lastChuteID != "" {
			prov.E2EEMaterialFetcher.Invalidate(lastChuteID)
		}
	} else {
		// Non-Chutes: mark the provider+model pair as globally failed.
		// This is a stronger signal — possible MITM or server-side E2EE
		// breakage. Block all subsequent requests until re-attestation.
		s.e2eeFailed.Store(providerModelKey{prov.Name, upstreamModel}, true)
	}

	// Demote e2ee_usable in the cached report so the report endpoint
	// reflects the failure. The cache entry is about to be deleted, but
	// a concurrent reader may still see it briefly. Keep the report detail
	// sanitized: relayErr may wrap lower-level decrypt errors that include
	// upstream content, which must never be exposed via the report endpoint.
	if cachedReport, ok := s.cache.Get(prov.Name, upstreamModel); ok {
		cloned := cachedReport.Clone()
		cloned.MarkE2EEFailed("E2EE decryption failed (see server logs, req=" + reqid.FromContext(ctx) + ")")
		s.cache.Put(prov.Name, upstreamModel, cloned)
	}

	// Invalidate caches to force full re-attestation on the next request.
	s.cache.Delete(prov.Name, upstreamModel)
	s.signingKeyCache.Delete(prov.Name, upstreamModel)

	slog.ErrorContext(ctx, "E2EE decryption failed; caches invalidated",
		"provider", prov.Name, "model", upstreamModel, "err", relayErr)
	return "e2ee_decrypt_failed"
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

	// Clear stale E2EE failure markers only after a confirmed fresh pinned
	// attestation (pinnedResp.Report != nil). On an SPKI cache hit the pinned
	// handler skips attestation: fail closed and force re-attestation.
	if prov.E2EE {
		key := providerModelKey{prov.Name, upstreamModel}
		if _, failed := s.e2eeFailed.Load(key); failed {
			if pinnedResp.Report != nil {
				s.e2eeFailed.Delete(key)
				slog.InfoContext(ctx, "Cleared prior E2EE failure after successful fresh pinned attestation",
					"provider", prov.Name, "model", upstreamModel)
			} else {
				s.cache.Delete(prov.Name, upstreamModel)
				s.signingKeyCache.Delete(prov.Name, upstreamModel)
				slog.ErrorContext(ctx, "E2EE previously failed; cached pinned attestation insufficient for recovery",
					"provider", prov.Name, "model", upstreamModel)
				s.stats.errors.Add(1)
				http.Error(w, "E2EE previously failed; re-attestation required", http.StatusServiceUnavailable)
				return
			}
		}
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
	ss, relayErr := relayResponse(ctx, w, pinnedResp.Body, session, nil, req.Stream)
	recordTokPerSec(ms, ss)

	s.handlePinnedPostRelay(ctx, prov, upstreamModel, report, session, ms, relayErr)
}

// handlePinnedPostRelay handles E2EE enforcement and cache updates after a
// pinned relay completes. Extracted from handlePinnedChat for complexity.
func (s *Server) handlePinnedPostRelay(
	ctx context.Context,
	prov *provider.Provider,
	upstreamModel string,
	report *attestation.VerificationReport,
	session e2ee.Decryptor,
	ms *modelStats,
	relayErr error,
) {
	// Post-relay enforcement for pinned E2EE paths.
	if relayErr != nil && errors.Is(relayErr, e2ee.ErrDecryptionFailed) && session != nil {
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		s.e2eeFailed.Store(providerModelKey{prov.Name, upstreamModel}, true)

		// Demote e2ee_usable in the cached report so the report endpoint
		// reflects the failure before the cache entry is deleted. Keep detail
		// sanitized: relayErr may include upstream content.
		if cachedReport, ok := s.cache.Get(prov.Name, upstreamModel); ok {
			cloned := cachedReport.Clone()
			cloned.MarkE2EEFailed("pinned E2EE decryption failed (see server logs, req=" + reqid.FromContext(ctx) + ")")
			s.cache.Put(prov.Name, upstreamModel, cloned)
		}

		s.cache.Delete(prov.Name, upstreamModel)
		s.signingKeyCache.Delete(prov.Name, upstreamModel)
		slog.ErrorContext(ctx, "pinned E2EE decryption failed; caches invalidated",
			"provider", prov.Name, "model", upstreamModel, "err", relayErr)
		return
	}

	// Non-decryption relay errors: response already written to client.
	if relayErr != nil {
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		slog.ErrorContext(ctx, "pinned relay failed", "provider", prov.Name, "model", upstreamModel, "err", relayErr)
		return
	}

	// After a successful E2EE roundtrip on the pinned path,
	// promote e2ee_usable from Skip to Pass in the cached report.
	// Clone before mutating to avoid racing with concurrent readers.
	if session != nil && report != nil {
		cloned := report.Clone()
		cloned.MarkE2EEUsable("E2EE roundtrip succeeded via pinned connection")
		s.cache.Put(prov.Name, upstreamModel, cloned)
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
// plaintext) and streaming mode. Returns StreamStats and any decryption error.
func relayResponse(ctx context.Context, w http.ResponseWriter, body io.Reader,
	session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool,
) (e2ee.StreamStats, error) {
	switch {
	case meta != nil && meta.Session != nil && stream:
		return e2ee.RelayStreamChutes(ctx, w, body, meta.Session)
	case meta != nil && meta.Session != nil:
		return e2ee.RelayNonStreamChutes(ctx, w, body, meta.Session)
	case session != nil && stream:
		return e2ee.RelayStream(ctx, w, body, session)
	case session != nil:
		return e2ee.RelayReassembledNonStream(ctx, w, body, session)
	case stream:
		return e2ee.RelayStream(ctx, w, body, nil)
	default:
		return e2ee.RelayNonStream(ctx, w, body, nil)
	}
}

// responseInterceptor wraps an http.ResponseWriter to detect whether headers
// have been flushed to the client. Used by the Chutes E2EE retry loop to
// determine if a failed streaming relay can be retried.
//
// It only satisfies http.Flusher when the underlying ResponseWriter does,
// so relay code's `w.(http.Flusher)` check correctly reflects the real
// writer's capability.
type responseInterceptor struct {
	http.ResponseWriter
	headerSent bool
}

func (ri *responseInterceptor) WriteHeader(code int) {
	ri.headerSent = true
	ri.ResponseWriter.WriteHeader(code)
}

func (ri *responseInterceptor) Write(b []byte) (int, error) {
	ri.headerSent = true
	return ri.ResponseWriter.Write(b)
}

// responseInterceptorFlusher extends responseInterceptor with Flush support.
// Returned by newResponseInterceptor when the underlying writer is flushable.
type responseInterceptorFlusher struct {
	*responseInterceptor
	flusher http.Flusher
}

func (rif *responseInterceptorFlusher) Flush() {
	rif.flusher.Flush()
}

// newResponseInterceptor wraps w in a responseInterceptor. The returned writer
// satisfies http.Flusher only if w does.
func newResponseInterceptor(w http.ResponseWriter) (*responseInterceptor, http.ResponseWriter) {
	ri := &responseInterceptor{ResponseWriter: w}
	if f, ok := w.(http.Flusher); ok {
		return ri, &responseInterceptorFlusher{responseInterceptor: ri, flusher: f}
	}
	return ri, ri
}

// isChutesE2EE returns true if the request uses Chutes E2EE (has a nonce pool
// for instance failover).
func isChutesE2EE(prov *provider.Provider, e2eeActive bool) bool {
	return e2eeActive && prov.E2EEMaterialFetcher != nil && prov.SkipSigningKeyCache
}

// classifyUpstreamError returns a status string, HTTP code, and user-facing
// message for an error from doUpstreamRoundtrip.
func classifyUpstreamError(err error) (status string, code int, msg string) {
	status = "upstream_failed"
	code = http.StatusBadGateway
	msg = "upstream request failed"
	if he := (*httpError)(nil); errors.As(err, &he) {
		status = he.status
		code = he.code
		if he.status == "e2ee_failed" {
			msg = "failed to prepare encrypted request"
		}
	}
	return
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
	endpointPath string,
) (*upstreamResult, error) {
	upstreamURL := prov.BaseURL + endpointPath
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

		if prepErr := prepareUpstreamHeaders(upstreamReq, prov, session, meta, stream, endpointPath); prepErr != nil {
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
func prepareUpstreamHeaders(req *http.Request, prov *provider.Provider, session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool, endpointPath string) error {
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
	return prov.Preparer.PrepareRequest(req, e2eeHeaders, meta, stream, endpointPath)
}

// --------------------------------------------------------------------------
// Non-chat endpoint handlers
// --------------------------------------------------------------------------

// embeddingsRequest is a minimal parse of an OpenAI embeddings request.
type embeddingsRequest struct {
	Model string `json:"model"`
}

// handleEmbeddings handles POST /v1/embeddings. The flow mirrors
// handleChatCompletions but uses prov.EmbeddingsPath and is non-streaming.
func (s *Server) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())
	requestStart := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var req embeddingsRequest
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
	if prov.EmbeddingsPath == "" {
		http.Error(w, fmt.Sprintf("provider %q does not support embeddings", prov.Name), http.StatusBadRequest)
		return
	}

	var attestDur, e2eeDur, upstreamDur time.Duration
	var status string
	defer func() {
		slog.InfoContext(ctx, "request complete",
			"endpoint", "embeddings",
			"provider", prov.Name,
			"model", upstreamModel,
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
	s.stats.nonStream.Add(1)

	if s.negCache.IsBlocked(prov.Name, upstreamModel) {
		status = "neg_cached"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		http.Error(w, fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel), http.StatusServiceUnavailable)
		return
	}

	if prov.PinnedHandler != nil {
		status = "pinned"
		s.handlePinnedNonChat(ctx, w, r, prov, upstreamModel, body, prov.EmbeddingsPath)
		return
	}

	ar, failStatus := s.attestAndCache(ctx, w, prov, upstreamModel, ms)
	attestDur = ar.AttestDur
	if failStatus != "" {
		status = failStatus
		return
	}
	report := ar.Report

	if ar.E2EEActive {
		if ok := s.clearE2EEFailureIfFresh(ctx, w, prov, upstreamModel, ar, ms); !ok {
			status = "e2ee_recovery_pending"
			return
		}
	}

	rr := s.relayWithRetry(ctx, w, prov, upstreamModel, body, ar, ms, false, prov.EmbeddingsPath)
	e2eeDur += rr.e2eeDur
	upstreamDur += rr.upstreamDur
	if rr.status != "" {
		status = rr.status
		return
	}

	if ar.E2EEActive {
		cloned := report.Clone()
		cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.cache.Put(prov.Name, upstreamModel, cloned)
	}
	status = "ok"
}

// imagesRequest is a minimal parse of an OpenAI image generation request.
type imagesRequest struct {
	Model string `json:"model"`
}

// handleImagesGenerations handles POST /v1/images/generations. Non-streaming JSON relay.
func (s *Server) handleImagesGenerations(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())
	requestStart := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var req imagesRequest
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
	if prov.ImagesPath == "" {
		http.Error(w, fmt.Sprintf("provider %q does not support image generation", prov.Name), http.StatusBadRequest)
		return
	}

	var attestDur, e2eeDur, upstreamDur time.Duration
	var status string
	defer func() {
		slog.InfoContext(ctx, "request complete",
			"endpoint", "images",
			"provider", prov.Name,
			"model", upstreamModel,
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
	s.stats.nonStream.Add(1)

	if s.negCache.IsBlocked(prov.Name, upstreamModel) {
		status = "neg_cached"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		http.Error(w, fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel), http.StatusServiceUnavailable)
		return
	}

	if prov.PinnedHandler != nil {
		status = "pinned"
		s.handlePinnedNonChat(ctx, w, r, prov, upstreamModel, body, prov.ImagesPath)
		return
	}

	ar, failStatus := s.attestAndCache(ctx, w, prov, upstreamModel, ms)
	attestDur = ar.AttestDur
	if failStatus != "" {
		status = failStatus
		return
	}
	report := ar.Report

	if ar.E2EEActive {
		if ok := s.clearE2EEFailureIfFresh(ctx, w, prov, upstreamModel, ar, ms); !ok {
			status = "e2ee_recovery_pending"
			return
		}
	}

	rr := s.relayWithRetry(ctx, w, prov, upstreamModel, body, ar, ms, false, prov.ImagesPath)
	e2eeDur += rr.e2eeDur
	upstreamDur += rr.upstreamDur
	if rr.status != "" {
		status = rr.status
		return
	}

	if ar.E2EEActive {
		cloned := report.Clone()
		cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.cache.Put(prov.Name, upstreamModel, cloned)
	}
	status = "ok"
}

// rerankRequest is a minimal parse of a rerank request.
type rerankRequest struct {
	Model string `json:"model"`
}

// handleRerank handles POST /v1/rerank. Non-streaming JSON relay.
func (s *Server) handleRerank(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())
	requestStart := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	var req rerankRequest
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
	if prov.RerankPath == "" {
		http.Error(w, fmt.Sprintf("provider %q does not support reranking", prov.Name), http.StatusBadRequest)
		return
	}

	var attestDur, e2eeDur, upstreamDur time.Duration
	var status string
	defer func() {
		slog.InfoContext(ctx, "request complete",
			"endpoint", "rerank",
			"provider", prov.Name,
			"model", upstreamModel,
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
	s.stats.nonStream.Add(1)

	if s.negCache.IsBlocked(prov.Name, upstreamModel) {
		status = "neg_cached"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		http.Error(w, fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel), http.StatusServiceUnavailable)
		return
	}

	if prov.PinnedHandler != nil {
		status = "pinned"
		s.handlePinnedNonChat(ctx, w, r, prov, upstreamModel, body, prov.RerankPath)
		return
	}

	ar, failStatus := s.attestAndCache(ctx, w, prov, upstreamModel, ms)
	attestDur = ar.AttestDur
	if failStatus != "" {
		status = failStatus
		return
	}
	report := ar.Report

	if ar.E2EEActive {
		if ok := s.clearE2EEFailureIfFresh(ctx, w, prov, upstreamModel, ar, ms); !ok {
			status = "e2ee_recovery_pending"
			return
		}
	}

	rr := s.relayWithRetry(ctx, w, prov, upstreamModel, body, ar, ms, false, prov.RerankPath)
	e2eeDur += rr.e2eeDur
	upstreamDur += rr.upstreamDur
	if rr.status != "" {
		status = rr.status
		return
	}

	if ar.E2EEActive {
		cloned := report.Clone()
		cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.cache.Put(prov.Name, upstreamModel, cloned)
	}
	status = "ok"
}

// handleAudioTranscriptions handles POST /v1/audio/transcriptions.
// Body is multipart/form-data (audio file + model field).
func (s *Server) handleAudioTranscriptions(w http.ResponseWriter, r *http.Request) {
	ctx := reqid.WithID(r.Context(), reqid.New())
	requestStart := time.Now()

	// Read full body first so we can forward it verbatim later.
	// FormValue would consume r.Body via ParseMultipartForm.
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Extract model from the multipart form data without consuming the
	// original body. Parse from the saved bytes.
	modelName, err := extractMultipartField(r.Header.Get("Content-Type"), body, "model")
	if err != nil || modelName == "" {
		http.Error(w, `"model" form field is required`, http.StatusBadRequest)
		return
	}

	prov, upstreamModel, ok := s.resolveModel(modelName)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown model %q", modelName), http.StatusBadRequest)
		return
	}
	if prov.AudioPath == "" {
		http.Error(w, fmt.Sprintf("provider %q does not support audio transcription", prov.Name), http.StatusBadRequest)
		return
	}

	// Multipart E2EE guard (fail-closed): Non-pinned E2EE providers
	// (Chutes, nearcloud) require body encryption, which doesn't support
	// multipart. Fail closed to prevent silently sending plaintext.
	if prov.E2EE && prov.PinnedHandler == nil {
		http.Error(w, "audio transcription requires TLS-level E2EE (pinned provider)", http.StatusBadRequest)
		return
	}

	var attestDur, upstreamDur time.Duration
	var status string
	defer func() {
		slog.InfoContext(ctx, "request complete",
			"endpoint", "audio",
			"provider", prov.Name,
			"model", upstreamModel,
			"status", status,
			"attest", fmtDur(attestDur),
			"upstream", fmtDur(upstreamDur),
			"total", fmtDur(time.Since(requestStart)),
		)
	}()

	s.stats.requests.Add(1)
	ms := s.stats.getModelStats(prov.Name, upstreamModel)
	ms.requests.Add(1)
	ms.lastRequestAt.Store(time.Now().Unix())
	s.stats.nonStream.Add(1)

	if s.negCache.IsBlocked(prov.Name, upstreamModel) {
		status = "neg_cached"
		s.stats.errors.Add(1)
		ms.errors.Add(1)
		http.Error(w, fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel), http.StatusServiceUnavailable)
		return
	}

	if prov.PinnedHandler != nil {
		status = "pinned"
		// Forward raw multipart body to pinned handler.
		s.handlePinnedNonChat(ctx, w, r, prov, upstreamModel, body, prov.AudioPath)
		return
	}

	// Non-pinned path: attestAndCache + relay. E2EE guard above ensures
	// this path is only reached for non-E2EE providers.
	ar, failStatus := s.attestAndCache(ctx, w, prov, upstreamModel, ms)
	attestDur = ar.AttestDur
	if failStatus != "" {
		status = failStatus
		return
	}

	rr := s.relayWithRetry(ctx, w, prov, upstreamModel, body, ar, ms, false, prov.AudioPath)
	upstreamDur += rr.upstreamDur
	if rr.status != "" {
		status = rr.status
		return
	}
	status = "ok"
}

// handlePinnedNonChat handles non-chat requests for connection-pinned providers.
// It mirrors handlePinnedChat but uses the given endpointPath and is always
// non-streaming with no E2EE session decryption (E2EE is TLS-level for pinned).
func (s *Server) handlePinnedNonChat(
	ctx context.Context,
	w http.ResponseWriter, r *http.Request,
	prov *provider.Provider, upstreamModel string,
	body []byte, endpointPath string,
) {
	headers := make(http.Header)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		headers.Set("Content-Type", ct)
	} else {
		headers.Set("Content-Type", "application/json")
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		headers.Set("Authorization", auth)
	}

	pinnedReq := provider.PinnedRequest{
		Method:  http.MethodPost,
		Path:    endpointPath,
		Headers: headers,
		Body:    body,
		Model:   upstreamModel,
		E2EE:    prov.E2EE,
	}
	if prov.E2EE {
		if cachedKey, ok := s.signingKeyCache.Get(prov.Name, upstreamModel); ok {
			pinnedReq.SigningKey = cachedKey
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	pinnedResp, err := prov.PinnedHandler.HandlePinned(reqCtx, &pinnedReq)
	if err != nil {
		s.negCache.Record(prov.Name, upstreamModel)
		slog.ErrorContext(ctx, "pinned request failed", "provider", prov.Name, "model", upstreamModel, "path", endpointPath, "err", err)
		http.Error(w, fmt.Sprintf("pinned connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer pinnedResp.Body.Close()

	report := pinnedResp.Report
	if report != nil {
		s.cache.Put(prov.Name, upstreamModel, report)
	} else if cached, ok := s.cache.Get(prov.Name, upstreamModel); ok {
		report = cached
	}
	if !s.enforceReport(ctx, w, report, prov, upstreamModel) {
		s.negCache.Record(prov.Name, upstreamModel)
		return
	}
	if pinnedResp.SigningKey != "" {
		s.signingKeyCache.Put(prov.Name, upstreamModel, pinnedResp.SigningKey)
	}

	for key, vals := range pinnedResp.Header {
		switch key {
		case "Transfer-Encoding", "Content-Encoding", "Content-Length", "Connection":
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	w.WriteHeader(pinnedResp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(pinnedResp.Body, 50<<20))
}

// clearE2EEFailureIfFresh clears a prior E2EE failure if the attestation
// result has fresh attestation (ar.Raw != nil). Otherwise it fails closed,
// invalidates caches, and writes an HTTP error. Returns true if the caller
// should proceed.
func (s *Server) clearE2EEFailureIfFresh(
	ctx context.Context,
	w http.ResponseWriter,
	prov *provider.Provider,
	upstreamModel string,
	ar *attestResult,
	ms *modelStats,
) bool {
	key := providerModelKey{prov.Name, upstreamModel}
	_, failed := s.e2eeFailed.Load(key)
	if !failed {
		return true
	}
	if ar.Raw != nil {
		s.e2eeFailed.Delete(key)
		slog.InfoContext(ctx, "Cleared prior E2EE failure after successful re-attestation",
			"provider", prov.Name, "model", upstreamModel)
		return true
	}
	s.cache.Delete(prov.Name, upstreamModel)
	s.signingKeyCache.Delete(prov.Name, upstreamModel)
	slog.ErrorContext(ctx, "E2EE previously failed; cached attestation insufficient for recovery",
		"provider", prov.Name, "model", upstreamModel)
	s.stats.errors.Add(1)
	ms.errors.Add(1)
	http.Error(w, "E2EE previously failed; re-attestation required", http.StatusServiceUnavailable)
	return false
}

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

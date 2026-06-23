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
//  6. If E2EE and tee_reportdata_binding Pass: encrypt messages, set headers.
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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

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
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/provider/venice"
	"github.com/13rac1/teep/internal/reqid"
	"github.com/13rac1/teep/internal/tlsct"
	"github.com/google/go-tdx-guest/verify/trust"
)

const (
	// attestationCacheTTL is how long a VerificationReport is considered fresh.
	// Uses the shared AttestationCacheTTL so all attestation caches expire together.
	attestationCacheTTL = attestation.AttestationCacheTTL

	// negativeCacheTTL is how long a failed attestation blocks retries.
	negativeCacheTTL = 30 * time.Second

	// signingKeyCacheTTL is how long a REPORTDATA-verified signing key is
	// reused for E2EE without re-fetching attestation. Uses the shared
	// AttestationCacheTTL so all attestation caches expire together.
	signingKeyCacheTTL = attestation.AttestationCacheTTL

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

	lastRequestAt atomic.Int64 // unix nanos of the most recent request; 0 = never
	lastSuccessAt atomic.Int64 // unix nanos of the most recent successful response; 0 = never

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
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("field %q not found in multipart body", fieldName)
			}
			return "", err
		}
		if p.FormName() == fieldName {
			const maxFieldSize = 1024
			val, err := io.ReadAll(io.LimitReader(p, maxFieldSize+1))
			if err != nil {
				_ = p.Close()
				return "", err
			}
			if err := p.Close(); err != nil {
				return "", err
			}
			if len(val) > maxFieldSize {
				return "", fmt.Errorf("field %q exceeds %d bytes", fieldName, maxFieldSize)
			}
			return string(val), nil
		}
		if err := p.Close(); err != nil {
			return "", err
		}
	}
}

// rewriteModelInBody replaces the model field in the request body with
// upstreamModel (the provider-stripped model name). For JSON bodies the
// "model" JSON field is rewritten. For multipart bodies (audio transcription)
// the "model" form field is replaced while preserving all other parts and the
// original boundary.
func rewriteModelInBody(contentType string, body []byte, epContentType, upstreamModel string) ([]byte, error) {
	if epContentType == "application/json" {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, newRequestNormalizationError(fmt.Errorf("unmarshal request body: %w", err))
		}
		id, err := json.Marshal(upstreamModel)
		if err != nil {
			return nil, fmt.Errorf("marshal upstream model: %w", err)
		}
		m["model"] = id
		return json.Marshal(m)
	}
	// Audio multipart/form-data: rebuild with model field replaced.
	return rewriteMultipartModel(contentType, body, upstreamModel)
}

type requestNormalizationError struct {
	statusCode int
	err        error
}

func newRequestNormalizationError(err error) error {
	return requestNormalizationError{statusCode: http.StatusBadRequest, err: err}
}

func (e requestNormalizationError) Error() string {
	return e.err.Error()
}

func (e requestNormalizationError) Unwrap() error {
	return e.err
}

func normalizationStatusCode(err error) int {
	var normalizeErr requestNormalizationError
	if errors.As(err, &normalizeErr) {
		return normalizeErr.statusCode
	}
	return http.StatusInternalServerError
}

// rewriteMultipartModel rebuilds a multipart/form-data body, replacing the
// value of the "model" form field with upstreamModel. All other parts and the
// original boundary are preserved.
func rewriteMultipartModel(contentType string, body []byte, upstreamModel string) ([]byte, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, newRequestNormalizationError(fmt.Errorf("parse content-type: %w", err))
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, newRequestNormalizationError(errors.New("missing boundary in content-type"))
	}

	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var out bytes.Buffer
	mw := multipart.NewWriter(&out)
	if err := mw.SetBoundary(boundary); err != nil {
		return nil, newRequestNormalizationError(fmt.Errorf("set boundary: %w", err))
	}
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, newRequestNormalizationError(fmt.Errorf("read multipart: %w", err))
		}
		pw, err := mw.CreatePart(p.Header)
		if err != nil {
			_ = p.Close()
			return nil, newRequestNormalizationError(fmt.Errorf("create part: %w", err))
		}
		if p.FormName() == "model" {
			_, err = pw.Write([]byte(upstreamModel))
		} else {
			_, err = io.Copy(pw, p)
		}
		_ = p.Close()
		if err != nil {
			return nil, newRequestNormalizationError(fmt.Errorf("write part: %w", err))
		}
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}
	return out.Bytes(), nil
}

// chutesRetryableError returns true if the upstream error or response status
// indicates a Chutes instance-level failure that warrants failover to a
// different instance. Returns false for client-induced cancellations
// (context.Canceled) so we don't burn retries after the caller is gone.
//
// Note: 429 (Too Many Requests) is explicitly NOT retried. Chutes rate
// limits are account-level, not instance-level, so retrying with a
// different instance amplifies the rate limit and burns nonces uselessly.
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
	case http.StatusInternalServerError,
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
	BodyReader io.Reader // EHBP streaming encrypted body (used instead of Body when set)
	Session    e2ee.Decryptor
	Meta       *e2ee.ChutesE2EE
	EHBP       *e2ee.EHBPSession
	ChuteID    string // For MarkFailed (from raw attestation, not meta)
	InstanceID string // For MarkFailed (from raw attestation, not meta)
}

// zeroE2EE zeroes crypto material from all E2EE session types.
func zeroE2EE(session e2ee.Decryptor, meta *e2ee.ChutesE2EE, ehbp *e2ee.EHBPSession) {
	if session != nil {
		session.Zero()
	}
	if meta != nil && meta.Session != nil {
		meta.Session.Zero()
	}
	if ehbp != nil {
		ehbp.Zero()
	}
}

// chatRequest is a minimal parse of an OpenAI chat completions request.
// Only fields the proxy needs to inspect or rewrite are decoded here.
type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Stream         bool          `json:"stream"`
	PromptCacheKey string        `json:"prompt_cache_key,omitempty"`
}

// extractPromptCacheKey extracts the prompt_cache_key field from a JSON body.
// Returns empty string if the field is absent or the body is not valid JSON.
func extractPromptCacheKey(body []byte) string {
	var v struct {
		PromptCacheKey string `json:"prompt_cache_key"`
	}
	_ = json.Unmarshal(body, &v) // best-effort; ignore errors
	return v.PromptCacheKey
}

// cacheModelCtxKey is the context key for the per-backend cache model name.
// When set, cache operations use this value instead of the upstream model
// name, preventing cache key collisions between enclaves with different
// TLS keys. See [Provider.CacheKeySuffix].
type cacheModelCtxKey struct{}

// withCacheModel stores the per-backend cache model name in the context.
func withCacheModel(ctx context.Context, model string) context.Context {
	return context.WithValue(ctx, cacheModelCtxKey{}, model)
}

// cacheModelFor returns the cache model name from the context, or falls back
// to the given model if not set. Used for attestation report cache, signing
// key cache, negative cache, and e2ee failure tracker keying.
func cacheModelFor(ctx context.Context, model string) string {
	if cm, _ := ctx.Value(cacheModelCtxKey{}).(string); cm != "" {
		return cm
	}
	return model
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
	nvidiaVerifier  *attestation.NVIDIAVerifier
	mux             *http.ServeMux
	attestClient    *http.Client            // for attestation fetches
	collateral      trust.HTTPSGetter       // for Intel PCS collateral fetches
	verifyQuote     attestation.TDXVerifier // constructed from cfg.Offline + collateral
	sevVerifier     attestation.SEVVerifier // constructed from cfg.Offline + AMD KDS getter
	upstreamClient  *http.Client            // for chat completions forwards
	sseConns        atomic.Int64            // active SSE /events connections
	e2eeFailed      sync.Map                // cacheKey → true; tracks provider+model pairs with E2EE decryption failures
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
	attestClient.Transport = tlsct.NewTLS12FallbackTransport(attestClient.Transport, attestation.AMDKDSHost)

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
	s.nvidiaVerifier = attestation.DefaultNVIDIAVerifier()
	s.collateral = attestation.NewCollateralGetter(s.attestClient)
	s.verifyQuote = attestation.NewTDXVerifier(cfg.Offline, s.collateral)
	s.sevVerifier = attestation.NewSEVVerifier(cfg.Offline, attestation.NewSEVCertGetter(s.attestClient))

	for name, cp := range cfg.Providers {
		if cp == nil {
			return nil, fmt.Errorf("provider %q: config is nil", name)
		}
		if strings.Contains(name, ":") {
			return nil, fmt.Errorf("provider map key %q must not contain ':'", name)
		}
		if cp.Name == "" {
			return nil, fmt.Errorf("provider %q has empty name", name)
		}
		if strings.Contains(cp.Name, ":") {
			return nil, fmt.Errorf("provider %q has invalid name %q: must not contain ':'", name, cp.Name)
		}
		if cp.Name != name {
			return nil, fmt.Errorf("provider map key %q does not match provider name %q", name, cp.Name)
		}
		mDefaults, gwDefaults := defaults.MeasurementDefaults(name)
		mergedPolicy := config.MergedMeasurementPolicy(name, cfg, mDefaults)
		mergedGWPolicy := config.MergedGatewayMeasurementPolicy(name, cfg, gwDefaults)
		p, err := fromConfig(cp, spkiCache, cfg.Offline, config.MergedAllowFail(name, cfg, cfg.Offline), mergedPolicy, mergedGWPolicy, s.rekorClient, s.nvidiaVerifier, s.collateral)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}
		s.providers[name] = p
		slog.Info("registered provider", "provider", name, "base_url", cp.BaseURL, "api_key", config.RedactKey(cp.APIKey), "e2ee", cp.E2EE)
	}

	if len(s.providers) == 0 {
		return nil, errors.New("no providers configured")
	}

	// Monitoring endpoints (/, /events, /metrics) are unauthenticated.
	// Access control relies on the proxy binding to loopback (127.0.0.1) by default;
	// config.Load warns when ListenAddr is non-loopback.
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /events", s.handleEvents)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("POST /v1/chat/completions", s.handleEndpoint(&chatEndpoint))
	s.mux.HandleFunc("POST /v1/embeddings", s.handleEndpoint(&embeddingsEndpoint))
	s.mux.HandleFunc("POST /v1/audio/transcriptions", s.handleEndpoint(&audioEndpoint))
	s.mux.HandleFunc("POST /v1/images/generations", s.handleEndpoint(&imagesEndpoint))
	s.mux.HandleFunc("POST /v1/rerank", s.handleEndpoint(&rerankEndpoint))
	s.mux.HandleFunc("POST /v1/score", s.handleEndpoint(&scoreEndpoint))
	s.mux.HandleFunc("POST /v1/responses", s.handleEndpoint(&responsesEndpoint))
	s.mux.HandleFunc("POST /v1/audio/speech", s.handleEndpoint(&speechEndpoint))
	s.mux.HandleFunc("GET /v1/models", s.handleModels)
	s.mux.HandleFunc("GET /v1/tee/report", s.handleReport)

	return s, nil
}

// ListenAndServe starts the proxy HTTP server on the configured listen address.
// It blocks until ctx is cancelled (e.g. via signal.NotifyContext), then
// initiates a graceful shutdown with a 5-second deadline to drain in-flight
// requests (which zeros any active E2EE sessions via their defers).
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.cfg.MaxConns <= 0 {
		return fmt.Errorf("max_conns must be positive, got %d", s.cfg.MaxConns)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	ln = &monitoredListener{
		Listener: netutil.LimitListener(ln, s.cfg.MaxConns),
		maxConns: s.cfg.MaxConns,
	}

	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("teep proxy listening", "addr", s.cfg.ListenAddr, "max_conns", s.cfg.MaxConns)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

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

// monitoredListener wraps netutil.LimitListener to log a rate-throttled warning
// when the connection limit is reached. The active counter tracks open connections
// so the check before each Accept is best-effort (racy but sufficient for logging).
type monitoredListener struct {
	net.Listener
	maxConns int
	active   atomic.Int64
	lastWarn atomic.Int64
}

func (m *monitoredListener) Accept() (net.Conn, error) {
	if m.active.Load() >= int64(m.maxConns) {
		now := time.Now().Unix()
		if last := m.lastWarn.Load(); now-last >= 60 && m.lastWarn.CompareAndSwap(last, now) {
			slog.Warn("connection limit reached; new connections are queuing",
				"max_conns", m.maxConns)
		}
	}
	c, err := m.Listener.Accept()
	if err != nil {
		return nil, err
	}
	m.active.Add(1)
	return &monitoredConn{Conn: c, active: &m.active}, nil
}

// monitoredConn decrements the active connection counter exactly once on Close.
type monitoredConn struct {
	net.Conn
	once   sync.Once
	active *atomic.Int64
}

func (c *monitoredConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.active.Add(-1) })
	return err
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
	nvidiaVerifier *attestation.NVIDIAVerifier,
	getter trust.HTTPSGetter,
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
		p.ScorePath = "/v1/score"
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
			nvidiaVerifier,
			getter,
		)
		p.SPKIDomainForModel = func(ctx context.Context, model string) (string, bool) {
			d, err := resolver.Resolve(ctx, model)
			if err != nil {
				return "", false
			}
			return d, true
		}
		p.ModelLister = provider.NewOwnedByModelLister(
			"https://"+nearcloud.GatewayHost(), cp.APIKey,
			config.NewAttestationClient(offline), "nearai",
		)
	case "nearcloud":
		p.ChatPath = "/v1/chat/completions"
		p.ImagesPath = "/v1/images/generations"
		p.EmbeddingsPath = "/v1/embeddings"
		p.RerankPath = "/v1/rerank"
		p.ScorePath = "/v1/score"
		p.Encryptor = neardirect.NewE2EE()
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
			nvidiaVerifier,
			getter,
		)
		p.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) {
			return nearcloud.GatewayHost(), true
		}
		p.ModelLister = provider.NewOwnedByModelLister(
			"https://"+nearcloud.GatewayHost(), cp.APIKey,
			config.NewAttestationClient(offline), "nearai",
		)
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
		u, err := url.Parse(cp.BaseURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("phalacloud base_url %q is invalid: must be an absolute URL", cp.BaseURL)
		}
		if path := strings.TrimSuffix(u.EscapedPath(), "/"); path != "" {
			base := *u
			base.Path = ""
			base.RawPath = ""
			base.RawQuery = ""
			base.Fragment = ""
			return nil, fmt.Errorf("phalacloud base_url %q must not include a path suffix; use %q", cp.BaseURL, base.String())
		}
		p.ChatPath = "/v1/chat/completions"
		p.EmbeddingsPath = "/v1/embeddings"
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
		p.Preparer = chutesProvider.NewPreparer(cp.APIKey, cp.BaseURL)
		p.ReportDataVerifier = chutesProvider.ReportDataVerifier{}
		p.SupplyChainPolicy = nil // cosign+IMA model, no docker-compose
		p.ModelLister = chutesProvider.NewModelLister(chutesProvider.DefaultModelsBaseURL, cp.APIKey, config.NewAttestationClient(offline))
		p.E2EEMaterialFetcher = chutesProvider.NewNoncePool(
			cp.BaseURL, cp.APIKey, attester.Resolver(), config.NewAttestationClient(offline),
		)
	case "tinfoil_v3_cloud":
		p.ChatPath = "/v1/chat/completions"
		p.EmbeddingsPath = "/v1/embeddings"
		p.AudioPath = "/v1/audio/transcriptions"
		p.ResponsesPath = "/v1/responses"
		p.SpeechPath = "/v1/audio/speech"
		p.UsesTLSBinding = true
		p.Attester = tinfoil.NewAttester(cp.BaseURL, cp.APIKey, offline)
		p.Preparer = tinfoil.NewPreparer(cp.APIKey)
		p.Encryptor = tinfoil.NewE2EE()
		p.ReportDataVerifier = tinfoil.ReportDataVerifier{}
		p.SupplyChainPolicy = nil // Sigstore-based, not compose-based
		p.SigstoreRepoForModel = func(_ string) string {
			return "tinfoilsh/confidential-model-router"
		}
		p.ModelLister = provider.NewModelLister(cp.BaseURL, cp.APIKey, config.NewAttestationClient(offline))
		p.SPKIDomainForModel = func(_ context.Context, _ string) (string, bool) {
			return "inference.tinfoil.sh", true
		}
	case "tinfoil_v3_direct":
		resolver := tinfoil.NewDirectResolver(cp.APIKey, offline)
		p.BaseURL = tinfoil.DefaultBaseURL // fallback for model discovery
		p.ChatPath = "/v1/chat/completions"
		p.EmbeddingsPath = "/v1/embeddings"
		p.AudioPath = "/v1/audio/transcriptions"
		p.ResponsesPath = "/v1/responses"
		p.SpeechPath = "/v1/audio/speech"
		p.UsesTLSBinding = true
		p.Attester = tinfoil.NewDirectAttester(resolver, cp.APIKey, offline)
		p.Preparer = tinfoil.NewPreparer(cp.APIKey)
		p.Encryptor = tinfoil.NewE2EE()
		p.ReportDataVerifier = tinfoil.ReportDataVerifier{}
		p.SupplyChainPolicy = nil // Sigstore-based, not compose-based
		p.SigstoreRepoForModel = func(model string) string {
			m, err := resolver.ResolveMapping(context.Background(), model)
			if err != nil || m.Repo == "" {
				return tinfoil.RepoForModel(model)
			}
			return m.Repo
		}
		p.BaseURLForModel = func(ctx context.Context, model string) (string, error) {
			m, err := resolver.ResolveMapping(ctx, model)
			if err != nil {
				return "", fmt.Errorf("tinfoil direct: resolve model %q: %w", model, err)
			}
			promptCacheKey := tinfoil.PromptCacheKeyFromContext(ctx)
			domain := m.SelectDomain(promptCacheKey)
			return "https://" + domain, nil
		}
		p.ModelLister = provider.NewModelLister(tinfoil.DefaultBaseURL, cp.APIKey, config.NewAttestationClient(offline))
		p.SPKIDomainForModel = func(ctx context.Context, model string) (string, bool) {
			m, err := resolver.ResolveMapping(ctx, model)
			if err != nil {
				slog.WarnContext(ctx, "tinfoil direct: SPKI domain resolution failed",
					"model", model, "err", err)
				return "", false
			}
			promptCacheKey := tinfoil.PromptCacheKeyFromContext(ctx)
			return m.SelectDomain(promptCacheKey), true
		}
		p.CacheKeySuffix = func(ctx context.Context, model string) string {
			m, err := resolver.ResolveMapping(ctx, model)
			if err != nil {
				return ""
			}
			promptCacheKey := tinfoil.PromptCacheKeyFromContext(ctx)
			return m.SelectDomain(promptCacheKey)
		}
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, neardirect, nearcloud, nanogpt, phalacloud, chutes, tinfoil_v3_cloud, tinfoil_v3_direct)", cp.Name)
	}

	// Invariant: any provider with a PinnedHandler must have SPKIDomainForModel
	// so the proxy can evict SPKI entries when the attestation cache expires.
	// This check prevents future providers from silently omitting the resolver.
	if p.PinnedHandler != nil && p.SPKIDomainForModel == nil {
		return nil, fmt.Errorf("provider %q has PinnedHandler but no SPKIDomainForModel; SPKI eviction would fail", cp.Name)
	}

	return p, nil
}

// resolveModel parses a client model string of the form "provider:model" and
// returns the matching provider and upstream model name. Both the provider
// prefix and the model segment must be non-empty. Unknown provider names and
// missing separators are rejected (returns false).
func (s *Server) resolveModel(clientModel string) (*provider.Provider, string, bool) {
	provName, upstreamModel, ok := strings.Cut(clientModel, ":")
	if !ok || provName == "" || upstreamModel == "" {
		return nil, "", false
	}
	p, found := s.providers[provName]
	if !found {
		return nil, "", false
	}
	return p, upstreamModel, true
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
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		return nil, nil
	}

	totalStart := time.Now()
	nonce := attestation.NewNonce()

	slog.DebugContext(ctx, "attestation fetch starting", "provider", prov.Name, "model", upstreamModel)
	fetchStart := time.Now()
	raw, err := prov.Attester.FetchAttestation(ctx, upstreamModel, nonce)
	if err != nil {
		slog.ErrorContext(ctx, "attestation fetch failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		return nil, nil
	}
	fetchDur := time.Since(fetchStart)
	slog.DebugContext(ctx, "attestation fetch complete", "provider", prov.Name, "elapsed", fetchDur)

	tdxResult, tdxDur := s.verifyTDX(ctx, raw, nonce, prov)
	sevResult, sevDur := s.verifySEV(ctx, raw, nonce, prov)
	nvidiaResult, nvidiaDur := verifyNVIDIA(ctx, raw, nonce, prov.Name)
	nrasResult, nrasDur := s.verifyNVIDIAOnline(ctx, raw, prov.Name)
	pocResult, pocDur := s.verifyPoC(ctx, raw, prov.Name)
	sc, composeDur := s.verifySupplyChain(ctx, raw, tdxResult)
	tinfoilSC, tinfoilSCDur := s.verifyTinfoilSupplyChain(ctx, raw, tdxResult, sevResult, prov, upstreamModel)

	totalDur := time.Since(totalStart)
	slog.InfoContext(ctx, "verification complete",
		"provider", prov.Name,
		"model", upstreamModel,
		"total", fmtDur(totalDur),
		"fetch", fmtDur(fetchDur),
		"tdx", fmtDur(tdxDur),
		"sev", fmtDur(sevDur),
		"nvidia", fmtDur(nvidiaDur),
		"nras", fmtDur(nrasDur),
		"poc", fmtDur(pocDur),
		"compose", fmtDur(composeDur),
		"tinfoil_sc", fmtDur(tinfoilSCDur),
	)

	ms := s.stats.getModelStats(prov.Name, upstreamModel)
	ms.lastVerifyMs.Store(totalDur.Milliseconds())

	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:               prov.Name,
		Model:                  upstreamModel,
		Raw:                    raw,
		Nonce:                  nonce,
		AllowFail:              config.MergedAllowFail(prov.Name, s.cfg, s.cfg.Offline),
		Policy:                 prov.MeasurementPolicy,
		GatewayPolicy:          prov.GatewayMeasurementPolicy,
		SupplyChainPolicy:      prov.SupplyChainPolicy,
		ImageRepos:             sc.ImageRepos,
		DigestToRepo:           sc.DigestToRepo,
		TDX:                    tdxResult,
		SEV:                    sevResult,
		Nvidia:                 nvidiaResult,
		NvidiaNRAS:             nrasResult,
		PoC:                    pocResult,
		Compose:                sc.Compose,
		Sigstore:               sc.Sigstore,
		Rekor:                  sc.Rekor,
		TinfoilSC:              tinfoilSC,
		E2EEConfigured:         prov.E2EE,
		Inapplicable:           inapplicableForProvider(prov.Name),
		ProviderUsesTLSBinding: prov.UsesTLSBinding,
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
	result := s.verifyQuote(ctx, raw.IntelQuote)
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

// verifySEV runs SEV-SNP report verification and REPORTDATA binding.
func (s *Server) verifySEV(
	ctx context.Context,
	raw *attestation.RawAttestation,
	nonce attestation.Nonce,
	prov *provider.Provider,
) (*attestation.SEVVerifyResult, time.Duration) {
	if len(raw.SEVReportBytes) == 0 {
		return nil, 0
	}
	slog.DebugContext(ctx, "SEV-SNP verification starting", "provider", prov.Name)
	start := time.Now()
	result := s.sevVerifier(ctx, raw.SEVReportBytes)
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
	slog.DebugContext(ctx, "SEV-SNP verification complete", "provider", prov.Name, "elapsed", dur)
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
		serverNonce, err := attestation.ParseNonce(raw.GPUVerificationNonce())
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
		result := s.nvidiaVerifier.VerifyNRAS(ctx, raw.NvidiaPayload, s.attestClient)
		dur := time.Since(start)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete", "provider", provName, "elapsed", dur)
		return result, dur
	}
	if len(raw.GPUEvidence) > 0 {
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting (synthesized EAT)", "provider", provName)
		eatJSON := attestation.GPUEvidenceToEAT(raw.GPUEvidence, raw.Nonce)
		start := time.Now()
		result := s.nvidiaVerifier.VerifyNRAS(ctx, eatJSON, s.attestClient)
		dur := time.Since(start)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete (synthesized EAT)", "provider", provName, "elapsed", dur)
		return result, dur
	}
	return nil, 0
}

func inapplicableForProvider(provName string) attestation.InapplicableFactors {
	switch provName {
	case "venice", "neardirect", "nearcloud", "nanogpt", "phalacloud":
		return attestation.DefaultInapplicableFactors()
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		return tinfoil.InapplicableFactors()
	case "chutes":
		return chutesProvider.InapplicableFactors()
	default:
		return attestation.DefaultInapplicableFactors()
	}
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
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, s.attestClient)
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
		if tdxResult != nil && tdxResult.ParseErr != nil {
			slog.WarnContext(ctx, "supply chain verification skipped: TDX quote parse failed",
				"parse_err", tdxResult.ParseErr)
		} else {
			slog.DebugContext(ctx, "supply chain verification skipped",
				"has_compose", raw.AppCompose != "",
				"has_tdx", tdxResult != nil)
		}
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
		var okDigests []string
		for _, sr := range sc.Sigstore {
			if sr.OK {
				okDigests = append(okDigests, sr.Digest)
			}
		}
		sc.Rekor = s.rekorClient.FetchRekorProvenances(ctx, okDigests)
	}

	return sc, time.Since(start)
}

// verifyTinfoilSupplyChain performs Tinfoil-specific Sigstore supply chain
// verification and code/hardware measurement comparison. Returns nil for
// non-Tinfoil providers.
func (s *Server) verifyTinfoilSupplyChain(
	ctx context.Context,
	raw *attestation.RawAttestation,
	tdxResult *attestation.TDXVerifyResult,
	sevResult *attestation.SEVVerifyResult,
	prov *provider.Provider,
	upstreamModel string,
) (*attestation.TinfoilSupplyChainResult, time.Duration) {
	if raw.BackendFormat != attestation.FormatTinfoil || prov.SigstoreRepoForModel == nil {
		return nil, 0
	}
	sigstoreRepo := prov.SigstoreRepoForModel(upstreamModel)
	if sigstoreRepo == "" {
		return nil, 0
	}
	start := time.Now()
	result := &attestation.TinfoilSupplyChainResult{}

	// Check GPU hash bound from REPORTDATA verification detail.
	bindingDetail := ""
	if tdxResult != nil {
		bindingDetail = tdxResult.ReportDataBindingDetail
	} else if sevResult != nil {
		bindingDetail = sevResult.ReportDataBindingDetail
	}
	result.GPUHashBound = strings.Contains(bindingDetail, "gpu_bound=true")
	result.NVSwitchHashBound = strings.Contains(bindingDetail, "nvswitch_bound=true")
	result.NVSwitchExpected = strings.Contains(bindingDetail, "nvswitch_bound=")

	// TDX policy checks.
	if tdxResult != nil && tdxResult.ParseErr == nil {
		pol := tinfoil.CheckTDXPolicy(tdxResult, prov.MeasurementPolicy.MRSeamAllow)
		result.TDXPolicyErr = pol.Err()
		if result.TDXPolicyErr == nil {
			result.TDXPolicyDetail = "Tinfoil TDX policy: TD_ATTRIBUTES, XFAM, MR_SEAM, MR registers, RTMR3, TEE_TCB_SVN all pass"
		} else {
			result.TDXPolicyDetail = fmt.Sprintf("Tinfoil TDX policy checks failed: %v", result.TDXPolicyErr)
		}
	}

	// Sigstore DSSE bundle verification.
	sv := tinfoil.NewSigstoreVerifier(config.NewAttestationClient(s.cfg.Offline))
	predicateBytes, predicateType, err := sv.FetchAndVerify(ctx, sigstoreRepo)
	if err != nil {
		result.SigstoreErr = err
		slog.WarnContext(ctx, "Tinfoil Sigstore verification failed",
			"repo", sigstoreRepo, "err", err)
		return result, time.Since(start)
	}
	result.SigstoreVerified = true
	result.SigstoreDetail = fmt.Sprintf("Sigstore DSSE verified for %s (predicate: %s)", sigstoreRepo, predicateType)

	// Parse code measurements from the verified predicate.
	if predicateType != tinfoil.PredicateMultiPlatform {
		result.CodeMatchErr = fmt.Errorf("unexpected predicate type %q, want %q", predicateType, tinfoil.PredicateMultiPlatform)
		return result, time.Since(start)
	}
	codeMeasurements, err := tinfoil.ParseMultiPlatformPredicate(predicateBytes)
	if err != nil {
		result.CodeMatchErr = fmt.Errorf("parse multi-platform predicate: %w", err)
		return result, time.Since(start)
	}

	// Build enclave measurements and compare.
	switch {
	case tdxResult != nil && tdxResult.ParseErr == nil:
		enclave := tinfoil.EnclaveMeasurementsFromTDX(tdxResult)
		if err := tinfoil.CompareMultiPlatformTDX(codeMeasurements, enclave); err != nil {
			result.CodeMatchErr = err
		} else {
			result.CodeMatch = true
			result.CodeMatchDetail = fmt.Sprintf("TDX code measurements match Sigstore predicate (RTMR1=%s..., RTMR2=%s...)",
				truncTo(codeMeasurements.RTMR1, 16), truncTo(codeMeasurements.RTMR2, 16))
		}

		// Hardware measurement match (TDX only).
		hwPredBytes, hwPredType, hwErr := sv.FetchAndVerify(ctx, "tinfoilsh/hardware-measurements")
		switch {
		case hwErr != nil:
			result.HWMatchErr = fmt.Errorf("fetch hardware measurements: %w", hwErr)
		case hwPredType != tinfoil.PredicateHardwareMeasurements:
			result.HWMatchErr = fmt.Errorf("unexpected hardware predicate type %q", hwPredType)
		default:
			entries, parseErr := tinfoil.ParseHardwareMeasurements(hwPredBytes)
			if parseErr != nil {
				result.HWMatchErr = fmt.Errorf("parse hardware measurements: %w", parseErr)
			} else if matchID, matchErr := tinfoil.MatchHardwareMeasurements(entries, enclave); matchErr != nil {
				result.HWMatchErr = matchErr
			} else {
				result.HWMatch = matchID
			}
		}

	case sevResult != nil && sevResult.ParseErr == nil:
		enclave := tinfoil.EnclaveMeasurementsFromSEV(sevResult)
		if err := tinfoil.CompareMultiPlatformSEVSNP(codeMeasurements, enclave); err != nil {
			result.CodeMatchErr = err
		} else {
			result.CodeMatch = true
			result.CodeMatchDetail = fmt.Sprintf("SEV-SNP code measurement matches Sigstore predicate (%s...)",
				truncTo(codeMeasurements.SNPMeasurement, 16))
		}

	default:
		result.CodeMatchErr = errors.New("no parseable TDX or SEV-SNP result for code measurement comparison")
	}

	return result, time.Since(start)
}

// truncTo returns the first n characters of s, or s itself if shorter.
func truncTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// --------------------------------------------------------------------------
// Endpoint handler factory
// --------------------------------------------------------------------------

// endpointConfig configures a proxy endpoint handler via the handleEndpoint factory.
type endpointConfig struct {
	// name is the endpoint name for logging (e.g. "chat", "embeddings").
	name string

	// endpointType is the canonical proxy route kind (EndpointChat, EndpointEmbeddings, etc.).
	// This canonicalizes endpoint identification across E2EE relay code.
	endpointType e2ee.EndpointType

	// endpointPath returns the upstream API path for this endpoint type from
	// the given provider. Returns "" if the provider doesn't support this endpoint.
	endpointPath func(*provider.Provider) string

	// unsupported is the human-readable description of this endpoint type,
	// used in error messages when the provider doesn't support it.
	// Empty string means the path is always required (chat).
	unsupported string

	// parseRequest extracts the model name and streaming flag from the request
	// body. For JSON endpoints, this unmarshals and reads the model field.
	// For multipart (audio), this extracts the model from form data.
	parseRequest func(r *http.Request, body []byte) (model string, stream bool, err error)

	// contentType is the default Content-Type for upstream requests.
	// If empty, the original request's Content-Type is preserved.
	contentType string

	// preRouteGuard is an optional check run after model resolution but before
	// routing. Returns an error message and true to block the request.
	// Nil means no guard.
	preRouteGuard func(prov *provider.Provider) (errMsg string, block bool)

	// canStream indicates whether this endpoint type supports SSE streaming.
	// When true, the pinned path uses handlePinnedChat (which supports
	// streaming + E2EE session decryption); otherwise handlePinnedNonChat.
	canStream bool
}

// parseChatRequest extracts model and stream flag from a chat completions JSON body.
func parseChatRequest(_ *http.Request, body []byte) (model string, stream bool, err error) {
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "", false, errors.New("invalid JSON body")
	}
	return req.Model, req.Stream, nil
}

// parseJSONModelRequest extracts only the model field from a JSON body.
// Used for embeddings, images, rerank, and score endpoints that don't support streaming.
func parseJSONModelRequest(_ *http.Request, body []byte) (model string, stream bool, err error) {
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", false, errors.New("invalid JSON body")
	}
	return req.Model, false, nil
}

// parseAudioModelRequest extracts the model field from a multipart/form-data body.
func parseAudioModelRequest(r *http.Request, body []byte) (model string, stream bool, err error) {
	model, err = extractMultipartField(r.Header.Get("Content-Type"), body, "model")
	if err != nil {
		return "", false, fmt.Errorf("extracting model from multipart body: %w", err)
	}
	if model == "" {
		return "", false, errors.New(`"model" form field is empty`)
	}
	return model, false, nil
}

// Endpoint configurations for each proxy route.
var (
	chatEndpoint = endpointConfig{
		name:         "chat",
		endpointType: e2ee.EndpointChat,
		endpointPath: func(p *provider.Provider) string { return p.ChatPath },
		parseRequest: parseChatRequest,
		contentType:  "application/json",
		canStream:    true,
	}
	embeddingsEndpoint = endpointConfig{
		name:         "embeddings",
		endpointType: e2ee.EndpointEmbeddings,
		endpointPath: func(p *provider.Provider) string { return p.EmbeddingsPath },
		unsupported:  "embeddings",
		parseRequest: parseJSONModelRequest,
		contentType:  "application/json",
	}
	imagesEndpoint = endpointConfig{
		name:         "images",
		endpointType: e2ee.EndpointImages,
		endpointPath: func(p *provider.Provider) string { return p.ImagesPath },
		unsupported:  "image generation",
		parseRequest: parseJSONModelRequest,
		contentType:  "application/json",
	}
	rerankEndpoint = endpointConfig{
		name:         "rerank",
		endpointType: e2ee.EndpointRerank,
		endpointPath: func(p *provider.Provider) string { return p.RerankPath },
		unsupported:  "reranking",
		parseRequest: parseJSONModelRequest,
		contentType:  "application/json",
	}
	scoreEndpoint = endpointConfig{
		name:         "score",
		endpointType: e2ee.EndpointScore,
		endpointPath: func(p *provider.Provider) string { return p.ScorePath },
		unsupported:  "score",
		parseRequest: parseJSONModelRequest,
		contentType:  "application/json",
	}
	audioEndpoint = endpointConfig{
		name:         "audio",
		endpointType: e2ee.EndpointAudio,
		endpointPath: func(p *provider.Provider) string { return p.AudioPath },
		unsupported:  "audio transcription",
		parseRequest: parseAudioModelRequest,
		preRouteGuard: func(prov *provider.Provider) (string, bool) {
			// Non-pinned E2EE providers (Chutes, nearcloud) require body encryption,
			// which doesn't support multipart. Fail closed to prevent silently
			// sending plaintext.
			if prov.E2EE && prov.PinnedHandler == nil {
				return "audio transcription requires TLS-level E2EE (pinned provider)", true
			}
			return "", false
		},
	}
	responsesEndpoint = endpointConfig{
		name:         "responses",
		endpointType: e2ee.EndpointResponses,
		endpointPath: func(p *provider.Provider) string { return p.ResponsesPath },
		unsupported:  "responses",
		parseRequest: parseChatRequest,
		contentType:  "application/json",
		canStream:    true,
	}
	speechEndpoint = endpointConfig{
		name:         "speech",
		endpointType: e2ee.EndpointSpeech,
		endpointPath: func(p *provider.Provider) string { return p.SpeechPath },
		unsupported:  "text-to-speech",
		parseRequest: parseJSONModelRequest,
		contentType:  "application/json",
	}
)

// handleEndpoint returns an http.HandlerFunc that handles requests for the
// given endpoint configuration. The returned handler performs:
// body reading → model parsing → provider resolution → attestation → E2EE → relay.
func (s *Server) handleEndpoint(ep *endpointConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := reqid.WithID(r.Context(), reqid.New())
		requestStart := time.Now()

		r.Body = http.MaxBytesReader(w, r.Body, 50<<20) // 50 MiB max
		defer r.Body.Close()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusBadRequest)
			return
		}

		model, stream, err := ep.parseRequest(r, body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if model == "" {
			http.Error(w, `"model" field is required`, http.StatusBadRequest)
			return
		}

		prov, upstreamModel, ok := s.resolveModel(model)
		if !ok {
			http.Error(w, fmt.Sprintf("unknown model %q: use provider:model format (e.g. venice:qwen3-5b)", model), http.StatusBadRequest)
			return
		}

		// Extract prompt_cache_key for cache-aware backend selection.
		// When present, the resolver uses hash-based sticky routing to
		// select a backend enclave domain, maximizing vLLM APC hit rates.
		promptCacheKey := extractPromptCacheKey(body)
		ctx = tinfoil.WithPromptCacheKey(ctx, promptCacheKey)

		// Compute per-backend cache model key to prevent attestation cache
		// collisions between enclaves with different TLS keys. When
		// CacheKeySuffix returns a domain, all cache operations for this
		// request use "model@domain" instead of just "model".
		if prov.CacheKeySuffix != nil {
			if suffix := prov.CacheKeySuffix(ctx, upstreamModel); suffix != "" {
				ctx = withCacheModel(ctx, upstreamModel+"@"+suffix)
			}
		}

		body, err = rewriteModelInBody(r.Header.Get("Content-Type"), body, ep.contentType, upstreamModel)
		if err != nil {
			slog.ErrorContext(ctx, "rewrite model in body", "provider", prov.Name, "model", upstreamModel, "err", err)
			http.Error(w, "failed to normalize request body", normalizationStatusCode(err))
			return
		}

		endpointPath := ep.endpointPath(prov)
		if endpointPath == "" {
			if ep.unsupported != "" {
				http.Error(w, fmt.Sprintf("provider %q does not support %s", prov.Name, ep.unsupported), http.StatusBadRequest)
			} else {
				http.Error(w, fmt.Sprintf("provider %q has no path configured for %s", prov.Name, ep.name), http.StatusInternalServerError)
			}
			return
		}

		if ep.preRouteGuard != nil {
			if errMsg, block := ep.preRouteGuard(prov); block {
				http.Error(w, errMsg, http.StatusBadRequest)
				return
			}
		}

		var attestDur, e2eeDur, upstreamDur time.Duration
		var status string
		defer func() {
			slog.InfoContext(ctx, "request complete",
				"endpoint", ep.name,
				"provider", prov.Name,
				"model", upstreamModel,
				"stream", stream,
				"status", status,
				"attest", fmtDur(attestDur),
				"e2ee", fmtDur(e2eeDur),
				"upstream", fmtDur(upstreamDur),
				"total", fmtDur(time.Since(requestStart)),
			)
		}()

		s.stats.requests.Add(1)
		s.stats.lastRequestAt.Store(requestStart.UnixNano())
		ms := s.stats.getModelStats(prov.Name, upstreamModel)
		ms.requests.Add(1)
		ms.lastRequestAt.Store(requestStart.Unix())
		if stream {
			s.stats.streaming.Add(1)
		} else {
			s.stats.nonStream.Add(1)
		}

		if s.negCache.IsBlocked(prov.Name, cacheModelFor(ctx, upstreamModel)) {
			status = "neg_cached"
			s.stats.errors.Add(1)
			ms.errors.Add(1)
			http.Error(w,
				fmt.Sprintf("attestation recently failed for %s/%s; try again later", prov.Name, upstreamModel),
				http.StatusServiceUnavailable)
			return
		}

		// Connection-pinned providers (NEAR AI) handle attestation on a
		// single TLS connection. No separate attestation cache or E2EE needed.
		if prov.PinnedHandler != nil {
			status = "pinned"
			if ep.canStream {
				s.handlePinnedChat(ctx, w, r, prov, upstreamModel, body, stream, endpointPath, ep.endpointType, ep.contentType)
			} else {
				s.handlePinnedNonChat(ctx, w, r, prov, upstreamModel, body, endpointPath, ep.endpointType)
			}
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

		ct := ep.contentType
		if ct == "" {
			ct = r.Header.Get("Content-Type")
		}
		rr := s.relayWithRetry(ctx, w, prov, upstreamModel, body, ar, ms, stream, endpointPath, ep.endpointType, ct)
		e2eeDur += rr.e2eeDur
		upstreamDur += rr.upstreamDur
		if rr.status != "" {
			status = rr.status
			return
		}

		if ar.E2EEActive {
			cloned := report.Clone()
			cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
			s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), cloned)
		}
		s.stats.lastSuccessAt.Store(time.Now().UnixNano())
		status = "ok"
	}
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
// The endpoint parameter identifies the proxy route kind (for E2EE relay).
// The endpointPath parameter is the actual upstream provider path.
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
	endpoint e2ee.EndpointType,
	contentType string,
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

		ur, err := s.doUpstreamRoundtrip(ctx, prov, body, upstreamModel, ar.E2EEActive, attemptRaw, stream, endpointPath, contentType, endpoint)
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
		ehbp := ur.EHBP
		if meta != nil && meta.ChuteID != "" {
			lastChuteID = meta.ChuteID
		}

		// cleanupAttempt drains and closes the response body and zeros crypto.
		cleanupAttempt := func() {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
			resp.Body.Close()
			ur.Cancel()
			zeroE2EE(session, meta, ehbp)
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

		// EHBP response unwrapping: decrypt the full response body before
		// relay so standard relay functions see plaintext SSE/JSON.
		if ehbp != nil {
			status, ok := s.unwrapEHBPResponse(ctx, resp, ehbp, prov.Name, upstreamModel, ri, riWriter)
			if !ok {
				cleanupAttempt()
				ehbpErr := fmt.Errorf("EHBP: %s", status)
				result.status = s.handleE2EEDecryptionFailure(ctx, prov, upstreamModel, ms, false, "", ehbpErr)
				return result
			}
			ehbp.Zero()
			ehbp = nil
			session = nil
			meta = nil
		}

		upstreamRelayStart := time.Now()
		ss, relayErr = relayResponse(ctx, riWriter, resp.Body, session, meta, stream, endpoint)
		result.upstreamDur += time.Since(upstreamRelayStart)
		recordTokPerSec(ms, ss)

		// Always drain body and clean up crypto material from this attempt.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		ur.Cancel()
		zeroE2EE(session, meta, ehbp)

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
		s.e2eeFailed.Store(providerModelKey{prov.Name, cacheModelFor(ctx, upstreamModel)}, true)
	}

	// Demote e2ee_usable in the cached report so the report endpoint
	// reflects the failure. The cache entry is about to be deleted, but
	// a concurrent reader may still see it briefly. Keep the report detail
	// sanitized: relayErr may wrap lower-level decrypt errors that include
	// upstream content, which must never be exposed via the report endpoint.
	if cachedReport, ok := s.cache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
		cloned := cachedReport.Clone()
		cloned.MarkE2EEFailed("E2EE decryption failed (see server logs, req=" + reqid.FromContext(ctx) + ")")
		s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), cloned)
	}

	// Invalidate caches to force full re-attestation on the next request.
	s.cache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
	s.signingKeyCache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))

	slog.ErrorContext(ctx, "E2EE decryption failed; caches invalidated",
		"provider", prov.Name, "model", upstreamModel, "err", relayErr)
	return "e2ee_decrypt_failed"
}

// pinnedPreDispatchE2EE checks REPORTDATA binding on cached attestation
// before making a pinned request. Returns false if the request must be aborted.
//
// When the attestation report cache is empty but the SPKI cache may still hold
// a live entry, the SPKI domain is evicted so the pinned handler performs full
// re-attestation on this connection instead of returning a nil report.
func (s *Server) pinnedPreDispatchE2EE(ctx context.Context, w http.ResponseWriter, prov *provider.Provider, upstreamModel string) bool {
	if !prov.E2EE {
		return true
	}
	if cached, ok := s.cache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
		if !cached.ReportDataBindingPassed() {
			slog.ErrorContext(ctx, "E2EE required but tee_reportdata_binding not passed; refusing request",
				"provider", prov.Name, "model", upstreamModel)
			http.Error(w, "E2EE required but REPORTDATA binding not verified; refusing plaintext", http.StatusBadGateway)
			return false
		}
	} else if prov.PinnedHandler != nil {
		// Attestation report cache miss (expired or never populated) on a
		// pinned provider. Evict the SPKI domain so the pinned handler
		// treats this as an SPKI miss, forcing fresh attestation.
		//
		// Use SPKIDomainForModel to resolve the correct SPKI cache key.
		// If unavailable, fail closed — an unresolvable domain means we
		// cannot guarantee the stale SPKI entry will be evicted, risking
		// a nil report on the next pinned request.
		if prov.SPKIDomainForModel == nil {
			slog.ErrorContext(ctx, "E2EE pinned provider has no SPKIDomainForModel; cannot evict SPKI cache; refusing request",
				"provider", prov.Name, "model", upstreamModel)
			http.Error(w, "E2EE pinned provider configuration error", http.StatusInternalServerError)
			return false
		}
		domain, ok := prov.SPKIDomainForModel(ctx, upstreamModel)
		if !ok || domain == "" {
			slog.ErrorContext(ctx, "E2EE pinned provider could not resolve SPKI domain; refusing request",
				"provider", prov.Name, "model", upstreamModel)
			http.Error(w, "E2EE SPKI domain resolution failed", http.StatusInternalServerError)
			return false
		}
		s.spkiCache.DeleteDomain(domain)
		slog.InfoContext(ctx, "evicted SPKI cache to force re-attestation (attestation report expired)",
			"provider", prov.Name, "model", upstreamModel, "domain", domain)
	}
	return true
}

// pinnedPostDispatchE2EE enforces E2EE requirements after receiving a pinned
// response: nil-report check, REPORTDATA binding check, and e2eeFailed map
// recovery. Returns false if the request must be aborted.
func (s *Server) pinnedPostDispatchE2EE(
	ctx context.Context, w http.ResponseWriter,
	prov *provider.Provider, upstreamModel string,
	report *attestation.VerificationReport,
	freshReport bool,
) bool {
	if !prov.E2EE {
		return true
	}
	// E2EE providers must always have a report to verify REPORTDATA binding.
	// Without one (e.g. attestation cache expired while SPKI cache is live),
	// we cannot verify the signing key is bound to the TDX quote.
	if report == nil {
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		slog.ErrorContext(ctx, "E2EE required but no attestation report available",
			"provider", prov.Name, "model", upstreamModel)
		http.Error(w, "E2EE required but no attestation report available; refusing request", http.StatusBadGateway)
		return false
	}
	// E2EE providers require REPORTDATA binding even on first request (SPKI
	// miss). Without it a MITM can substitute the enclave public key and
	// E2EE degrades to plaintext.
	if !report.ReportDataBindingPassed() {
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		slog.ErrorContext(ctx, "E2EE required but tee_reportdata_binding not passed; refusing request",
			"provider", prov.Name, "model", upstreamModel)
		http.Error(w, "E2EE required but REPORTDATA binding not verified; refusing plaintext", http.StatusBadGateway)
		return false
	}
	// Clear stale E2EE failure markers only after a confirmed fresh pinned
	// attestation (freshReport=true). On an SPKI cache hit the pinned
	// handler skips attestation: fail closed and force re-attestation.
	key := providerModelKey{prov.Name, cacheModelFor(ctx, upstreamModel)}
	if _, failed := s.e2eeFailed.Load(key); failed {
		if freshReport {
			s.e2eeFailed.Delete(key)
			slog.InfoContext(ctx, "Cleared prior E2EE failure after successful fresh pinned attestation",
				"provider", prov.Name, "model", upstreamModel)
		} else {
			s.cache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
			s.signingKeyCache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
			slog.ErrorContext(ctx, "E2EE previously failed; cached pinned attestation insufficient for recovery",
				"provider", prov.Name, "model", upstreamModel)
			s.stats.errors.Add(1)
			http.Error(w, "E2EE previously failed; re-attestation required", http.StatusServiceUnavailable)
			return false
		}
	}
	return true
}

// handlePinnedChat handles streaming-capable requests for connection-pinned
// providers. Attestation and chat happen on the same TLS connection via
// PinnedHandler. Also used for non-chat streaming endpoints if added later.
func (s *Server) handlePinnedChat(
	ctx context.Context,
	w http.ResponseWriter, r *http.Request,
	prov *provider.Provider, upstreamModel string,
	body []byte, stream bool, endpointPath string, endpoint e2ee.EndpointType, contentType string,
) {
	// Build forwarded headers.
	headers := make(http.Header)
	ct := contentType
	if ct == "" {
		ct = r.Header.Get("Content-Type")
	}
	if ct == "" {
		ct = "application/json"
	}
	headers.Set("Content-Type", ct)
	// Forward Authorization from client if present.
	if auth := r.Header.Get("Authorization"); auth != "" {
		headers.Set("Authorization", auth)
	}

	if !s.pinnedPreDispatchE2EE(ctx, w, prov, upstreamModel) {
		return
	}

	pinnedReq := provider.PinnedRequest{
		Method:   http.MethodPost,
		Path:     endpointPath,
		Headers:  headers,
		Body:     body,
		Model:    upstreamModel,
		E2EE:     prov.E2EE,
		Endpoint: endpoint,
	}
	// Supply the cached signing key for E2EE on SPKI cache hits.
	if prov.E2EE {
		if cachedKey, ok := s.signingKeyCache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
			pinnedReq.SigningKey = cachedKey
		}
	}

	var cancel context.CancelFunc
	if stream {
		ctx, cancel = context.WithTimeout(ctx, 30*time.Minute)
	} else {
		ctx, cancel = context.WithTimeout(ctx, 120*time.Second)
	}
	defer cancel()

	pinnedResp, err := prov.PinnedHandler.HandlePinned(ctx, &pinnedReq)
	if err != nil {
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		slog.ErrorContext(ctx, "pinned chat failed", "provider", prov.Name, "model", upstreamModel, "err", err)
		http.Error(w, fmt.Sprintf("pinned connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer pinnedResp.Body.Close()

	// Use the report from this request (SPKI miss) or cached report (SPKI hit)
	// to enforce fail-closed policy before forwarding any upstream response.
	report := pinnedResp.Report
	if report != nil {
		s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), report)
	} else if cached, ok := s.cache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
		report = cached
	}
	if !s.enforceReport(ctx, w, report, prov, upstreamModel) {
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		return
	}
	if !s.pinnedPostDispatchE2EE(ctx, w, prov, upstreamModel, report, pinnedResp.Report != nil) {
		return
	}
	if pinnedResp.SigningKey != "" {
		s.signingKeyCache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), pinnedResp.SigningKey)
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
	ss, relayErr := relayResponse(ctx, w, pinnedResp.Body, session, nil, stream, endpoint)
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
		s.e2eeFailed.Store(providerModelKey{prov.Name, cacheModelFor(ctx, upstreamModel)}, true)

		// Demote e2ee_usable in the cached report so the report endpoint
		// reflects the failure before the cache entry is deleted. Keep detail
		// sanitized: relayErr may include upstream content.
		if cachedReport, ok := s.cache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
			cloned := cachedReport.Clone()
			cloned.MarkE2EEFailed("pinned E2EE decryption failed (see server logs, req=" + reqid.FromContext(ctx) + ")")
			s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), cloned)
		}

		s.cache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
		s.signingKeyCache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
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
		s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), cloned)
	}
	s.stats.lastSuccessAt.Store(time.Now().UnixNano())
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
	report, cached := s.cache.Get(prov.Name, cacheModelFor(ctx, upstreamModel))
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
		s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), report)
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
		if prev, ok := s.signingKeyCache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok && subtle.ConstantTimeCompare([]byte(prev), []byte(raw.SigningKey)) == 0 {
			slog.WarnContext(ctx, "signing key rotated (VM restart?)", "provider", prov.Name, "model", upstreamModel)
		}
		s.signingKeyCache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), raw.SigningKey)
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
// The endpoint parameter identifies the proxy route kind.
func relayResponse(ctx context.Context, w http.ResponseWriter, body io.Reader,
	session e2ee.Decryptor, meta *e2ee.ChutesE2EE, stream bool, endpoint e2ee.EndpointType,
) (e2ee.StreamStats, error) {
	switch {
	case meta != nil && meta.Session != nil && stream:
		return e2ee.RelayStreamChutes(ctx, w, body, meta.Session)
	case meta != nil && meta.Session != nil:
		return e2ee.RelayNonStreamChutes(ctx, w, body, meta.Session)
	case session != nil && stream:
		return e2ee.RelayStream(ctx, w, body, session, endpoint)
	case session != nil:
		return e2ee.RelayReassembledNonStream(ctx, w, body, session, endpoint)
	case stream:
		return e2ee.RelayStream(ctx, w, body, nil, endpoint)
	default:
		return e2ee.RelayNonStreamForEndpoint(ctx, w, body, nil, endpoint)
	}
}

// unwrapEHBPResponse decrypts an EHBP-encrypted response body in place,
// replacing resp.Body with a plaintext reader. Returns a status string and
// false on failure; the caller must clean up and return. On success returns
// ("", true) and resp.Body is ready for standard relay.
func (s *Server) unwrapEHBPResponse(
	ctx context.Context,
	resp *http.Response,
	ehbp *e2ee.EHBPSession,
	provName, upstreamModel string,
	ri *responseInterceptor,
	riWriter http.ResponseWriter,
) (string, bool) {
	nonceHex := resp.Header.Get("Ehbp-Response-Nonce")
	if nonceHex == "" {
		slog.ErrorContext(ctx, "EHBP response missing Ehbp-Response-Nonce header",
			"provider", provName, "model", upstreamModel)
		if !ri.headerSent {
			ri.WriteHeader(http.StatusBadGateway)
			_, _ = riWriter.Write([]byte("EHBP response missing Ehbp-Response-Nonce header\n"))
		}
		return "ehbp_missing_nonce", false
	}
	if len(nonceHex) != 64 {
		slog.ErrorContext(ctx, "EHBP response nonce wrong length",
			"provider", provName, "model", upstreamModel, "len", len(nonceHex))
		if !ri.headerSent {
			ri.WriteHeader(http.StatusBadGateway)
			_, _ = riWriter.Write([]byte("EHBP response nonce invalid\n"))
		}
		return "ehbp_invalid_nonce", false
	}
	decryptedBody, err := ehbp.DecryptResponse(resp.Body, nonceHex)
	if err != nil {
		slog.ErrorContext(ctx, "EHBP response decryption failed",
			"provider", provName, "model", upstreamModel, "err", err)
		if !ri.headerSent {
			ri.WriteHeader(http.StatusBadGateway)
			_, _ = riWriter.Write([]byte("EHBP response decryption failed\n"))
		}
		return "ehbp_decrypt_failed", false
	}
	resp.Body = decryptedBody
	return "", true
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
	EHBP        *e2ee.EHBPSession
	Cancel      context.CancelFunc
	E2EEDur     time.Duration
	UpstreamDur time.Duration
}

// setUpstreamConnectionHeaders sets Connection and EHBP headers on the
// upstream request. For TLS-binding providers, Connection: close is set
// when a fresh attestation was fetched (cache miss) to prevent TLS
// connection reuse across attestation boundaries. On cache hits, the
// connection is reusable — the per-response SPKI verification in
// verifyUpstreamTLSBinding ensures the connection remains bound to the
// attested enclave.
func setUpstreamConnectionHeaders(req *http.Request, prov *provider.Provider, raw *attestation.RawAttestation, ehbp *e2ee.EHBPSession) {
	if prov.UsesTLSBinding && raw != nil {
		req.Header.Set("Connection", "close")
	}
	if ehbp != nil {
		req.Header.Set("Ehbp-Encapsulated-Key", ehbp.EncapKeyHex())
		req.ContentLength = -1 // force chunked transfer encoding
	}
}

// verifyUpstreamTLSBinding checks that the live upstream TLS peer SPKI
// matches the attested tls_key_fp from the attestation report. This
// prevents MITM attacks between teep and the enclave after attestation
// completes. The attestation fetch already verifies the peer SPKI, but
// the upstream inference connection must also be bound to the same
// attested identity.
//
// On mismatch, invalidates all caches to force re-attestation on the next
// request. Returns an *httpError on failure, nil on success.
func (s *Server) verifyUpstreamTLSBinding(
	ctx context.Context,
	prov *provider.Provider,
	upstreamModel string,
	resp *http.Response,
	raw *attestation.RawAttestation,
) *httpError {
	peerSPKI := tlsct.PeerSPKI(resp.TLS)
	if peerSPKI == "" {
		return &httpError{http.StatusBadGateway, "tls_binding_failed",
			errors.New("upstream TLS binding failed: no TLS peer state on upstream connection")}
	}
	if subtle.ConstantTimeCompare([]byte(peerSPKI), []byte(raw.TinfoilTLSKeyFP)) != 1 {
		slog.ErrorContext(ctx, "upstream TLS SPKI mismatch: live peer does not match attested fingerprint",
			"provider", prov.Name, "model", upstreamModel,
			"live_spki", provider.Truncate(peerSPKI, 16),
			"attested_spki", provider.Truncate(raw.TinfoilTLSKeyFP, 16))
		// Invalidate caches to force re-attestation on next request.
		s.cache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
		s.signingKeyCache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
		if prov.SPKIDomainForModel != nil {
			if domain, ok := prov.SPKIDomainForModel(ctx, upstreamModel); ok && domain != "" {
				s.spkiCache.DeleteDomain(domain)
			}
		}
		return &httpError{http.StatusBadGateway, "tls_binding_failed",
			errors.New("upstream TLS SPKI mismatch: live peer fingerprint does not match attested tls_key_fp")}
	}
	return nil
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
	contentType string,
	endpoint e2ee.EndpointType,
) (*upstreamResult, error) {
	baseURL := prov.BaseURL
	if prov.BaseURLForModel != nil {
		resolved, err := prov.BaseURLForModel(ctx, upstreamModel)
		if err != nil {
			return &upstreamResult{}, &httpError{http.StatusBadGateway, "model_resolution_failed",
				fmt.Errorf("resolve upstream URL for model %q: %w", upstreamModel, err)}
		}
		baseURL = resolved
	}
	upstreamURL := baseURL + endpointPath
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
		ehbp        *e2ee.EHBPSession
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
		ub, buildErr := s.buildUpstreamBody(ctx, body, upstreamModel, e2eeActive, prov, freshRaw, endpoint)
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
		ehbp = ub.EHBP

		var attemptCtx context.Context
		attemptCtx, cancel = context.WithTimeout(ctx, upstreamTimeout)

		var reqBody io.Reader
		if ub.BodyReader != nil {
			reqBody = ub.BodyReader
		} else {
			reqBody = bytes.NewReader(ub.Body)
		}
		upstreamReq, reqErr := http.NewRequestWithContext(attemptCtx, http.MethodPost, upstreamURL, reqBody)
		if reqErr != nil {
			cancel()
			zeroE2EE(session, meta, ehbp)
			return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur},
				&httpError{http.StatusInternalServerError, "e2ee_failed", fmt.Errorf("build upstream request: %w", reqErr)}
		}
		upstreamReq.Header.Set("Content-Type", contentType)
		provider.SetUserAgent(upstreamReq)
		setUpstreamConnectionHeaders(upstreamReq, prov, raw, ehbp)

		if prepErr := prepareUpstreamHeaders(upstreamReq, prov, session, meta, stream, endpointPath); prepErr != nil {
			cancel()
			zeroE2EE(session, meta, ehbp)
			return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur},
				&httpError{http.StatusInternalServerError, "e2ee_failed", fmt.Errorf("prepare upstream headers: %w", prepErr)}
		}

		upstreamDoStart := time.Now()
		resp, err = s.upstreamClient.Do(upstreamReq)
		upstreamDur += time.Since(upstreamDoStart)

		// TLS-fingerprint binding: for providers that use TLS binding
		// (e.g. Tinfoil), verify the live upstream TLS peer SPKI matches
		// the attested tls_key_fp from the attestation report.
		if err == nil && resp != nil && prov.UsesTLSBinding && raw != nil && raw.TinfoilTLSKeyFP != "" {
			if spkiErr := s.verifyUpstreamTLSBinding(ctx, prov, upstreamModel, resp, raw); spkiErr != nil {
				cancel()
				zeroE2EE(session, meta, ehbp)
				resp.Body.Close()
				return &upstreamResult{E2EEDur: e2eeDur, UpstreamDur: upstreamDur}, spkiErr
			}
		}

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
			zeroE2EE(session, meta, ehbp)
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
		zeroE2EE(session, meta, ehbp)
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
		EHBP:        ehbp,
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
	endpoint e2ee.EndpointType,
) (*upstreamBody, error) {
	if !e2eeActive {
		if prov.E2EE {
			return nil, fmt.Errorf("E2EE required for %s but tee_reportdata_binding not passed; refusing plaintext", prov.Name)
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
			if cachedKey, ok := s.signingKeyCache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); !ok {
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
			if cachedKey, ok := s.signingKeyCache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
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
			// Only REPORTDATA binding is needed here, not full online
			// verification. The primary fetchAndVerify() path already
			// did online verification for the cached report.
			switch {
			case raw.IntelQuote != "":
				tdxResult := attestation.VerifyTDXQuoteOffline(ctx, raw.IntelQuote)
				if tdxResult.ParseErr != nil {
					return nil, fmt.Errorf("fresh TDX quote parse failed: %w", tdxResult.ParseErr)
				}
				if prov.ReportDataVerifier != nil {
					_, err := prov.ReportDataVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
					if err != nil {
						return nil, fmt.Errorf("fresh signing key REPORTDATA binding failed: %w", err)
					}
				}
			case len(raw.SEVReportBytes) > 0:
				sevResult := attestation.VerifySEVReportOffline(ctx, raw.SEVReportBytes)
				if sevResult.ParseErr != nil {
					return nil, fmt.Errorf("fresh SEV-SNP report parse failed: %w", sevResult.ParseErr)
				}
				if prov.ReportDataVerifier != nil {
					_, err := prov.ReportDataVerifier.VerifyReportData(sevResult.ReportData, raw, nonce)
					if err != nil {
						return nil, fmt.Errorf("fresh signing key REPORTDATA binding failed: %w", err)
					}
				}
			default:
				return nil, errors.New("fresh attestation has no TEE evidence; cannot verify signing key binding")
			}
			s.signingKeyCache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), raw.SigningKey)
		}
	} else {
		slog.DebugContext(ctx, "E2EE key exchange: reusing attestation from verification (cache miss path)", "provider", prov.Name, "model", upstreamModel)
	}

	if raw.SigningKey == "" {
		return nil, errors.New("attestation response missing signing_key")
	}

	result, err := prov.Encryptor.EncryptRequest(rawBody, raw, endpoint)
	if err != nil {
		return nil, err
	}
	return &upstreamBody{
		Body:       result.Body,
		BodyReader: result.BodyReader,
		Session:    result.Session,
		Meta:       result.Chutes,
		EHBP:       result.EHBP,
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

// handlePinnedNonChat handles non-chat requests for connection-pinned providers.
// It mirrors handlePinnedChat but uses the given endpointPath and is always
// non-streaming. When the upstream returns an E2EE session (e.g. images with
// encrypted b64_json), the response is decrypted via RelayNonStream.
func (s *Server) handlePinnedNonChat(
	ctx context.Context,
	w http.ResponseWriter, r *http.Request,
	prov *provider.Provider, upstreamModel string,
	body []byte, endpointPath string, endpoint e2ee.EndpointType,
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

	if !s.pinnedPreDispatchE2EE(ctx, w, prov, upstreamModel) {
		return
	}

	pinnedReq := provider.PinnedRequest{
		Method:   http.MethodPost,
		Path:     endpointPath,
		Headers:  headers,
		Body:     body,
		Model:    upstreamModel,
		E2EE:     prov.E2EE,
		Endpoint: endpoint,
	}
	if prov.E2EE {
		if cachedKey, ok := s.signingKeyCache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
			pinnedReq.SigningKey = cachedKey
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	pinnedResp, err := prov.PinnedHandler.HandlePinned(reqCtx, &pinnedReq)
	if err != nil {
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		slog.ErrorContext(ctx, "pinned request failed", "provider", prov.Name, "model", upstreamModel, "path", endpointPath, "err", err)
		http.Error(w, fmt.Sprintf("pinned connection failed: %v", err), http.StatusBadGateway)
		return
	}
	defer pinnedResp.Body.Close()

	report := pinnedResp.Report
	if report != nil {
		s.cache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), report)
	} else if cached, ok := s.cache.Get(prov.Name, cacheModelFor(ctx, upstreamModel)); ok {
		report = cached
	}
	if !s.enforceReport(ctx, w, report, prov, upstreamModel) {
		s.negCache.Record(prov.Name, cacheModelFor(ctx, upstreamModel))
		return
	}
	if !s.pinnedPostDispatchE2EE(ctx, w, prov, upstreamModel, report, pinnedResp.Report != nil) {
		return
	}
	if pinnedResp.SigningKey != "" {
		s.signingKeyCache.Put(prov.Name, cacheModelFor(ctx, upstreamModel), pinnedResp.SigningKey)
	}

	// Copy response headers, excluding hop-by-hop headers that Go's
	// HTTP stack manages (matching handlePinnedChat's filtering).
	for key, vals := range pinnedResp.Header {
		switch key {
		case "Transfer-Encoding", "Content-Encoding", "Content-Length", "Connection":
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}

	// Non-OK: forward error response directly (no E2EE decryption needed).
	if pinnedResp.StatusCode != http.StatusOK {
		if pinnedResp.Session != nil {
			defer pinnedResp.Session.Zero()
		}
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

	// RelayNonStreamForEndpoint reads the full body, decrypts endpoint-specific
	// fields if session is non-nil, and writes to w.
	_, relayErr := e2ee.RelayNonStreamForEndpoint(ctx, w, pinnedResp.Body, session, endpoint)

	s.handlePinnedPostRelay(ctx, prov, upstreamModel, report, session, ms, relayErr)
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
	key := providerModelKey{prov.Name, cacheModelFor(ctx, upstreamModel)}
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
	s.cache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
	s.signingKeyCache.Delete(prov.Name, cacheModelFor(ctx, upstreamModel))
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

// handleModels returns available models from all configured providers in
// deterministic (sorted) provider order. Each model's "id" field is rewritten
// to "provider:upstreamID" so clients can route requests back to the correct
// provider. All other upstream model fields are preserved semantically.
// Partial-success: a provider that fails listing is logged and skipped.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(reqid.WithID(r.Context(), reqid.New()), modelsTimeout)
	defer cancel()

	provNames := make([]string, 0, len(s.providers))
	for name := range s.providers {
		provNames = append(provNames, name)
	}
	slices.Sort(provNames)

	// Fan out model listing to all providers concurrently.
	// Results are collected in provNames order for deterministic output.
	type provResult struct{ models []json.RawMessage }
	results := make([]provResult, len(provNames))
	var wg sync.WaitGroup
	for i, name := range provNames {
		prov := s.providers[name]
		if prov.ModelLister == nil {
			continue
		}
		wg.Add(1)
		go func(i int, name string, prov *provider.Provider) {
			defer wg.Done()
			models, err := prov.ModelLister.ListModels(ctx)
			if err != nil {
				slog.WarnContext(ctx, "model listing failed", "provider", prov.Name, "err", err)
				return
			}
			for _, raw := range models {
				prefixed, err := prefixModelID(name, raw)
				if err != nil {
					slog.WarnContext(ctx, "model ID prefix failed", "provider", name, "err", err)
					continue
				}
				results[i].models = append(results[i].models, prefixed)
			}
		}(i, name, prov)
	}
	wg.Wait()

	totalCap := 0
	for _, r := range results {
		totalCap += len(r.models)
	}
	all := make([]json.RawMessage, 0, totalCap)
	for _, r := range results {
		all = append(all, r.models...)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(modelsListResponse{Object: "list", Data: all}); err != nil {
		slog.ErrorContext(ctx, "encoding models response", "err", err)
	}
}

// prefixModelID rewrites the "id" field of a JSON model object to
// "providerName:originalID", preserving all other fields. Returns an error if
// the object cannot be parsed or the "id" field is missing or not a string.
func prefixModelID(providerName string, raw json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	idRaw, ok := obj["id"]
	if !ok {
		return nil, errors.New("model object missing 'id' field")
	}
	var id string
	if err := json.Unmarshal(idRaw, &id); err != nil {
		return nil, fmt.Errorf("model 'id' is not a string: %w", err)
	}
	prefixed, err := json.Marshal(providerName + ":" + id)
	if err != nil {
		return nil, err
	}
	obj["id"] = prefixed
	return json.Marshal(obj)
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

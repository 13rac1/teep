package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

type authorizedRequest struct {
	provider    *provider.Provider
	route       provider.ResolvedRoute
	key         provider.AuthorizationKey
	body        []byte
	stream      bool
	path        string
	contentType string
	endpoint    e2ee.EndpointType
}

type authorizedOutcome struct {
	report                          *attestation.VerificationReport
	status                          string
	summary                         []any
	trace                           *tlsct.InferenceAttempt
	diagnostics                     []any
	attestDur, e2eeDur, upstreamDur time.Duration
}

type authorizedResponse struct {
	outcome       authorizedOutcome
	authorization *authorization
	upstream      *upstreamResult
	blocked       *attestation.VerificationReport
	retryReason   string
}

func (s *Server) authorizedRoundtrip(ctx context.Context, input *authorizedRequest) (authorizedResponse, error) {
	timeout := upstreamNonStreamTimeout
	if input.stream {
		timeout = upstreamStreamTimeout
	}
	logical, cancel := context.WithTimeout(ctx, timeout)
	deadline, _ := logical.Deadline()
	budget := max(0, time.Until(deadline))
	var attestDur, e2eeDur, upstreamDur time.Duration
	attempts := 0
	lastRetry := ""
	result, err := tlsct.RunInferenceAttempts(logical, func(attemptCtx context.Context) (authorizedResponse, bool, error) {
		attempts++
		result, retry, err := s.authorizedAttempt(attemptCtx, input)
		if retry && attempts < 2 && attemptCtx.Err() == nil {
			lastRetry = result.retryReason
			logAuthorizedRetry(attemptCtx, input, &result, attempts, err)
		}
		attestDur += result.outcome.attestDur
		e2eeDur += result.outcome.e2eeDur
		upstreamDur += result.outcome.upstreamDur
		return result, retry, err
	})
	result.outcome.attestDur, result.outcome.e2eeDur, result.outcome.upstreamDur = attestDur, e2eeDur, upstreamDur
	result.outcome.summary = append(result.outcome.summary, "inference_attempts", attempts, "inference_timeout_budget", budget)
	if lastRetry != "" {
		result.outcome.summary = append(result.outcome.summary, "retry_reason", lastRetry)
	}
	if result.upstream == nil {
		cancel()
	} else {
		attemptCancel := result.upstream.Cancel
		result.upstream.Cancel = func() { attemptCancel(); cancel() }
	}
	return result, err
}

func (s *Server) authorizedAttempt(ctx context.Context, input *authorizedRequest) (result authorizedResponse, retry bool, err error) {
	started := time.Now()
	value, blocked, err := s.loadAuthorization(ctx, input.provider, input.route, input.key)
	result = authorizedResponse{authorization: value, blocked: blocked, outcome: authorizedOutcome{status: "authorization_failed", attestDur: time.Since(started)}}
	if err != nil || blocked != nil {
		return result, false, err
	}
	result.outcome.diagnostics = authorizationIdentityDiagnostics(value)
	result.outcome.status = "upstream_failed"
	attemptCtx, cancel := context.WithCancel(ctx)
	trace := &tlsct.InferenceAttempt{}
	result.outcome.trace = trace
	started = time.Now()
	ur, err := s.prepareAuthorizedRequest(trace.Context(attemptCtx), input, value)
	result.outcome.e2eeDur = time.Since(started)
	if err != nil {
		cancel()
		return result, false, err
	}
	started = time.Now()
	defer func() { result.outcome.upstreamDur = time.Since(started) }()
	ur.Cancel = cancel
	result.upstream = ur
	client, err := s.pinnedClientForIdentity(input.provider.Name, value.identity)
	if err == nil {
		ur.Resp, err = client.Do(ur.Request) //nolint:bodyclose // cleanupAuthorized closes rejected attempts; inferAuthorized owns successful responses.
	}
	if err != nil {
		retry := trace.RetryConnectionFailure(attemptCtx, err)
		if retry {
			result.retryReason = "connection_establishment"
		}
		if tlsct.IsOriginTrustFailure(err) {
			removed := s.authorizations.deleteGeneration(input.key, value.generation)
			result.outcome.diagnostics = authorizationFailureDiagnostics(value, err, removed)
		}
		cleanupAuthorized(ur)
		result.upstream = nil
		return result, retry, err
	}
	trace.ResponseHeadersReceived(ur.Resp.Proto)
	result.outcome.summary = append(result.outcome.summary, "upstream_status_code", ur.Resp.StatusCode)
	if tlsct.IsRedirectStatus(ur.Resp.StatusCode) {
		err = errors.New("upstream returned an unexpected redirect")
	} else if ur.Session != nil || ur.EHBP != nil || (input.provider.Name == "nearcloud" && input.path == "/v1/chat/completions" && ur.Resp.StatusCode == http.StatusMisdirectedRequest) {
		var rejected bool
		rejected, err = provider.KeyRejection(ur.Resp, input.provider.Name, input.path)
		if rejected {
			removed := s.authorizations.deleteGeneration(input.key, value.generation)
			logAuthorizationRejection(ctx, input, value, "model_key_rejected", removed, false)
			result.retryReason = "model_key_rejected"
			if !input.provider.E2EE {
				return result, false, nil
			}
			cleanupAuthorized(ur)
			result.upstream = nil
			return result, input.provider.E2EE, errors.New("upstream rejected the attested model key")
		}
	}
	if err != nil {
		cleanupAuthorized(ur)
		result.upstream = nil
		return result, false, err
	}
	return result, false, nil
}

func (s *Server) prepareAuthorizedRequest(ctx context.Context, input *authorizedRequest, value *authorization) (*upstreamResult, error) {
	req, encrypted, err := provider.PrepareInference(ctx, input.provider, input.route, &provider.InferenceInput{
		Body: input.body, SigningKey: value.signingKey, ModelKey: value.modelKey, Path: input.path, ContentType: input.contentType, Stream: input.stream, Endpoint: input.endpoint,
	})
	if err != nil {
		return nil, err
	}
	return &upstreamResult{Request: req, Session: encrypted.Session, Meta: encrypted.Chutes, EHBP: encrypted.EHBP}, nil
}

func cleanupAuthorized(ur *upstreamResult) {
	if ur.Resp != nil {
		ur.Resp.Body.Close()
	}
	e2ee.ZeroSessions(ur.Session, ur.Meta, ur.EHBP)
	if ur.Cancel != nil {
		ur.Cancel()
	}
}

// inferAuthorized returns the report from the attempt actually used, including
// after retry. It never recovers a report through another discovery lookup.
func (s *Server) inferAuthorized(ctx context.Context, w http.ResponseWriter, input *authorizedRequest) (out authorizedOutcome, err error) {
	result, err := s.authorizedRoundtrip(ctx, input)
	out = result.outcome
	if err != nil {
		return out, err
	}
	if result.blocked != nil {
		s.enforceReport(ctx, w, result.blocked, input.provider, input.key.Model())
		out.report, out.status = result.blocked, "attestation_blocked"
		return out, errors.New("attestation blocked")
	}
	defer cleanupAuthorized(result.upstream)
	if input.provider.E2EE {
		s.stats.e2ee.Add(1)
	} else {
		s.stats.plaintext.Add(1)
	}
	value := result.authorization
	out.report = value.report
	started := time.Now()
	defer func() { out.upstreamDur += time.Since(started) }()
	if err := s.relayAuthorized(result.upstream.Request.Context(), w, input, &result); err != nil { //nolint:contextcheck // The request retains the attempt context derived from ctx with the caller deadline.
		return out, err
	}
	if input.provider.E2EE {
		value.report.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.authorizations.promote(input.key, value.generation, "E2EE roundtrip succeeded via proxy")
	}
	out.status = "ok"
	out.summary = append(out.summary, authorizationIdentityDiagnostics(value)...)
	return out, nil
}

func (s *Server) relayAuthorized(ctx context.Context, w http.ResponseWriter, input *authorizedRequest, result *authorizedResponse) (retErr error) {
	writer, err := newResponseLifetime(ctx, w)
	if err != nil {
		return err
	}
	defer func() {
		if err := writer.check(); err != nil {
			retErr = err
		}
	}()
	w = writer
	ur := result.upstream
	resp := ur.Resp
	copyAuthorizedHeaders(w.Header(), resp.Header)
	var body io.Reader = resp.Body
	invalidate := func(reason string) {
		removed := s.rejectResponseAuthorization(input.key, result.authorization.generation)
		logAuthorizationRejection(ctx, input, result.authorization, reason, removed, removed)
	}
	// EHBP permits plaintext non-success diagnostics. Attested TLS still
	// authenticates the peer; these errors do not establish E2EE success.
	success := resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
	if ur.EHBP != nil && (success || len(resp.Header.Values("Ehbp-Response-Nonce")) != 0) {
		nonce := resp.Header.Get("Ehbp-Response-Nonce")
		if len(resp.Header.Values("Ehbp-Response-Nonce")) != 1 {
			invalidate("response_nonce_count")
			return errors.New("EHBP response must contain one response nonce")
		}
		plain, err := ur.EHBP.DecryptResponse(resp.Body, nonce)
		if err != nil {
			invalidate("response_authentication")
			return errors.New("EHBP response authentication failed")
		}
		defer plain.Close()
		body = plain
	}
	body = responseLifetimeReader{Reader: body, check: writer.check}
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		_, err := io.Copy(w, io.LimitReader(body, 10<<20))
		if errors.Is(err, e2ee.ErrDecryptionFailed) {
			invalidate("response_decryption")
		}
		return errors.Join(fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), err)
	}
	streamStats, err := relayResponse(ctx, w, body, ur.Session, ur.Meta, input.stream, input.endpoint)
	recordTokPerSec(s.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority()), streamStats)
	if errors.Is(err, e2ee.ErrDecryptionFailed) {
		invalidate("response_decryption")
	}
	return err
}

func (s *Server) handleAuthorizedEndpoint(ctx context.Context, w http.ResponseWriter, input *authorizedRequest) authorizedOutcome {
	ri, writer := newResponseInterceptor(w)
	out, err := s.inferAuthorized(ctx, writer, input)
	if err != nil {
		if len(out.diagnostics) == 0 {
			out.diagnostics = []any{"authority", input.key.Authority()}
		}
		warn := classifyAuthorizedFailure(ctx, err, &out)
		if out.trace != nil {
			out.summary = append(out.summary, out.trace.TimingDiagnostics()...)
			connection := out.trace.ConnectionDiagnostics()
			if warn {
				out.diagnostics = append(out.diagnostics, connection...)
			} else {
				out.summary = append(out.summary, connection...)
			}
		} else {
			out.summary = append(out.summary, "failure_phase", "authorization")
		}
		if !warn {
			out.summary = append(out.summary, out.diagnostics...)
		}
		if warn {
			attrs := append([]any{"provider", input.provider.Name, "model", input.key.Model(), "err", err}, out.diagnostics...)
			attrs = append(attrs, out.summary...)
			slog.WarnContext(ctx, "authorized inference failed", attrs...)
		}
		s.stats.errors.Add(1)
		s.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority()).errors.Add(1)
		if !ri.headerSent {
			code := http.StatusBadGateway
			if _, ok := errors.AsType[*verificationOverloadError](err); ok || errors.Is(err, tlsct.ErrConnectionCapacity) {
				code = http.StatusServiceUnavailable
			}
			if errors.Is(err, tlsct.ErrConnectionCapacity) {
				writer.Header().Set("Retry-After", "1")
			}
			if httpErr, ok := errors.AsType[*httpError](err); ok {
				code = httpErr.code
			}
			http.Error(writer, "inference authorization or upstream request failed; see server logs", code)
			return out
		}
	} else {
		s.stats.lastSuccessAt.Store(time.Now().UnixNano())
	}
	return out
}

func copyAuthorizedHeaders(dst, src http.Header) {
	excluded := map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Content-Length": true, "Content-Encoding": true}
	for _, line := range src.Values("Connection") {
		for name := range strings.SplitSeq(line, ",") {
			excluded[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range src {
		if !excluded[http.CanonicalHeaderKey(name)] {
			dst[name] = append([]string(nil), values...)
		}
	}
}

// rejectResponseAuthorization records the cooldown before releasing the store
// lock. No acquisition can observe the removal before the cooldown, and a late
// response from an older generation cannot extend it or affect a replacement.
func (s *Server) rejectResponseAuthorization(key provider.AuthorizationKey, generation authorizationGeneration) bool {
	key = key.EvidenceScope()
	store := s.authorizations
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.entries[key]
	if !ok || record.value.generation != generation {
		return false
	}
	s.negCache.Record(key.ProviderName(), key.SingleflightKey())
	delete(store.entries, key)
	return true
}

// authorizationFailureDiagnostics describes the generation actually used by the
// failed attempt, even when another caller has already published a replacement.
func authorizationFailureDiagnostics(value *authorization, err error, removed bool) []any {
	attrs := append(authorizationIdentityDiagnostics(value), "authorization_removed", removed)
	if mismatch, ok := errors.AsType[*tlsct.SPKIMismatchError](err); ok {
		attrs = append(attrs, "tls_authority", mismatch.Authority, "tls_sni", mismatch.ServerName, "expected_spki", mismatch.Expected, "observed_spki", mismatch.Observed)
	}
	return attrs
}

func logAuthorizationRejection(ctx context.Context, input *authorizedRequest, value *authorization, reason string, removed, cooldown bool) {
	attrs := make([]any, 0, 16)
	attrs = append(attrs, "provider", input.provider.Name, "model", input.key.Model(), "reason", reason, "cooldown_recorded", cooldown)
	attrs = append(attrs, authorizationFailureDiagnostics(value, nil, removed)...)
	slog.WarnContext(ctx, "response authorization rejected", attrs...)
}

func authorizationIdentityDiagnostics(value *authorization) []any {
	return []any{"authority", value.identity.Authority(), "authorization_generation", value.generation, "authorization_published_at", value.publishedAt}
}

func logAuthorizedRetry(ctx context.Context, input *authorizedRequest, result *authorizedResponse, attempt int, err error) {
	attrs := []any{"provider", input.provider.Name, "model", input.key.Model(), "inference_attempt", attempt, "retry_reason", result.retryReason, "err", err}
	attrs = append(attrs, result.outcome.diagnostics...)
	attrs = append(attrs, result.outcome.summary...)
	if result.outcome.trace != nil {
		attrs = append(attrs, result.outcome.trace.TimingDiagnostics()...)
		attrs = append(attrs, result.outcome.trace.ConnectionDiagnostics()...)
	}
	slog.WarnContext(ctx, "authorized inference retry scheduled", attrs...)
}

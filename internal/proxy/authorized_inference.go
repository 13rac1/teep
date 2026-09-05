package proxy

import (
	"bytes"
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
	attestDur, e2eeDur, upstreamDur time.Duration
}

type authorizedResponse struct {
	outcome       authorizedOutcome
	authorization *authorization
	upstream      *upstreamResult
	blocked       *attestation.VerificationReport
}

func (s *Server) authorizedRoundtrip(ctx context.Context, input *authorizedRequest) (authorizedResponse, error) {
	timeout := upstreamNonStreamTimeout
	if input.stream {
		timeout = upstreamStreamTimeout
	}
	logical, cancel := context.WithTimeout(ctx, timeout)
	var attestDur, e2eeDur, upstreamDur time.Duration
	result, err := tlsct.RunInferenceAttempts(logical, func(attemptCtx context.Context) (authorizedResponse, bool, error) {
		result, retry, err := s.authorizedAttempt(attemptCtx, input)
		attestDur += result.outcome.attestDur
		e2eeDur += result.outcome.e2eeDur
		upstreamDur += result.outcome.upstreamDur
		return result, retry, err
	})
	result.outcome.attestDur, result.outcome.e2eeDur, result.outcome.upstreamDur = attestDur, e2eeDur, upstreamDur
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
	result.outcome.status = "upstream_failed"
	attemptCtx, cancel := value.attemptContext(ctx)
	trace := &tlsct.InferenceAttempt{}
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
	client, err := s.pinnedUpstreamClient(input.provider, input.route.BaseURL(), value.identity.Fingerprint())
	if err == nil {
		ur.Resp, err = client.Do(ur.Request) //nolint:bodyclose // cleanupAuthorized closes rejected attempts; inferAuthorized owns successful responses.
	}
	if err != nil {
		retry := trace.RetryConnectionFailure(attemptCtx, err)
		if tlsct.IsTrustFailure(err) {
			s.authorizations.deleteGeneration(input.key, value.generation)
		}
		cleanupAuthorized(ur)
		result.upstream = nil
		return result, retry, err
	}
	if tlsct.IsRedirectStatus(ur.Resp.StatusCode) {
		err = errors.New("upstream returned an unexpected redirect")
	} else if ur.Session != nil || ur.EHBP != nil {
		var rejected bool
		rejected, err = provider.KeyRejection(ur.Resp, input.provider.Name, input.path)
		if rejected {
			s.authorizations.deleteGeneration(input.key, value.generation)
			cleanupAuthorized(ur)
			result.upstream = nil
			return result, true, errors.New("upstream rejected the attested encryption key")
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
	started := time.Now()
	ub, err := s.buildUpstreamBody(ctx, input.body, input.key.Model(), input.provider.E2EE, input.provider, &attestation.RawAttestation{SigningKey: value.signingKey}, input.endpoint)
	if err != nil {
		return nil, err
	}
	ur := &upstreamResult{Session: ub.Session, Meta: ub.Meta, EHBP: ub.EHBP, E2EEDur: time.Since(started)}
	var body io.Reader = bytes.NewReader(ub.Body)
	if ub.BodyReader != nil {
		body = ub.BodyReader
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, input.route.BaseURL()+input.path, body)
	if err == nil {
		req.GetBody = nil
		req.Header.Set("Content-Type", input.contentType)
		provider.SetUserAgent(req)
		setUpstreamConnectionHeaders(req, ub.EHBP)
		err = prepareUpstreamHeaders(req, input.provider, ub.Session, ub.Meta, input.stream, input.path)
	}
	if err != nil {
		zeroE2EE(ub.Session, ub.Meta, ub.EHBP)
		return nil, err
	}
	ur.Request = req
	return ur, nil
}

func cleanupAuthorized(ur *upstreamResult) {
	if ur.Resp != nil {
		ur.Resp.Body.Close()
	}
	zeroE2EE(ur.Session, ur.Meta, ur.EHBP)
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
	if err := s.relayAuthorized(result.upstream.Request.Context(), w, input, result); err != nil { //nolint:contextcheck // The request retains the attempt context derived from ctx with the authenticated deadline.
		return out, err
	}
	if input.provider.E2EE {
		value.report.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.authorizations.promote(input.key, value.generation, "E2EE roundtrip succeeded via proxy")
	}
	out.status = "ok"
	return out, nil
}

func (s *Server) relayAuthorized(ctx context.Context, w http.ResponseWriter, input *authorizedRequest, result authorizedResponse) (retErr error) {
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
	invalidate := func() { s.authorizations.deleteGeneration(input.key, result.authorization.generation) }
	if ur.EHBP != nil {
		nonce := resp.Header.Get("Ehbp-Response-Nonce")
		// A plaintext non-success response does not demonstrate key expiry.
		if nonce != "" || resp.StatusCode == http.StatusOK {
			plain, err := ur.EHBP.DecryptResponse(resp.Body, nonce)
			if err != nil {
				invalidate()
				return errors.New("EHBP response authentication failed")
			}
			defer plain.Close()
			body = plain
		}
	}
	body = responseLifetimeReader{Reader: body, check: writer.check}
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		_, err := io.Copy(w, io.LimitReader(body, 10<<20))
		if errors.Is(err, e2ee.ErrDecryptionFailed) {
			invalidate()
		}
		return fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}
	streamStats, err := relayResponse(ctx, w, body, ur.Session, ur.Meta, input.stream, input.endpoint)
	recordTokPerSec(s.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority()), streamStats)
	if errors.Is(err, e2ee.ErrDecryptionFailed) {
		invalidate()
	}
	return err
}

func (s *Server) handleAuthorizedEndpoint(ctx context.Context, w http.ResponseWriter, input *authorizedRequest) authorizedOutcome {
	ri, writer := newResponseInterceptor(w)
	out, err := s.inferAuthorized(ctx, writer, input)
	if err != nil {
		slog.WarnContext(ctx, "authorized inference failed", "provider", input.provider.Name, "model", input.key.Model(), "err", err)
		s.stats.errors.Add(1)
		s.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority()).errors.Add(1)
		if errors.Is(err, context.Canceled) {
			out.status = "canceled"
		} else if errors.Is(err, context.DeadlineExceeded) {
			out.status = "deadline_exceeded"
		}
		if !ri.headerSent {
			code := http.StatusBadGateway
			if _, ok := errors.AsType[*verificationOverloadError](err); ok {
				code = http.StatusServiceUnavailable
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

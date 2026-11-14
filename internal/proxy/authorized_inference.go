package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/tlsct"
)

type authorizedRequest struct {
	provider *provider.Provider
	route    provider.ResolvedRoute
	key      provider.AuthorizationKey
	body     []byte
	// model is the upstream model that teep resolved and wrote into body
	// (rewriteModelInBody); the receipt check compares it.
	model       string
	stream      bool
	path        string
	contentType string
	endpoint    e2ee.EndpointType
}

type authorizedOutcome struct {
	report                          *attestation.VerificationReport
	status                          string
	summary                         []slog.Attr // Completion summary: INFO for every request, also appended to failure warnings.
	trace                           *tlsct.InferenceAttempt
	diagnostics                     []slog.Attr // Warning-only detail; caller cancellation moves it into summary.
	attestDur, e2eeDur, upstreamDur time.Duration
}

type authorizedResponse struct {
	outcome          authorizedOutcome
	authorization    *authorization
	upstream         *upstreamResult
	blocked          *attestation.VerificationReport
	relayDiagnostics []slog.Attr
	retryReason      string
}

// A Phala Cloud stream that the client leaves after content reached it is
// read to its end for the receipt check, within these bounds from the
// client's end (SEE: tailHold).
const (
	streamDrainTimeout = 2 * time.Minute
	streamDrainBytes   = 16 << 20
)

// drainBounds replaces streamDrainTimeout and streamDrainBytes when set.
type drainBounds struct {
	timeout time.Duration
	bytes   int64
}

func (s *Server) drainTimeout() time.Duration {
	if s.drainBounds.timeout > 0 {
		return s.drainBounds.timeout
	}
	return streamDrainTimeout
}

func (s *Server) drainBytes() int64 {
	if s.drainBounds.bytes > 0 {
		return s.drainBounds.bytes
	}
	return streamDrainBytes
}

// attemptTimeouts are the attempt deadlines for stream and non-stream
// requests.
type attemptTimeouts struct {
	stream, nonStream time.Duration
}

// attemptTimeout returns the attempt timeout for a stream or a non-stream
// request.
func (s *Server) attemptTimeout(stream bool) time.Duration {
	switch {
	case stream && s.attemptTimeouts.stream > 0:
		return s.attemptTimeouts.stream
	case stream:
		return upstreamStreamTimeout
	case s.attemptTimeouts.nonStream > 0:
		return s.attemptTimeouts.nonStream
	default:
		return upstreamNonStreamTimeout
	}
}

func (s *Server) authorizedRoundtrip(ctx context.Context, input *authorizedRequest) (authorizedResponse, error) {
	// The upstream attempt does not run on the client's context: hold
	// stops it when the client's request ends while teep relays, as
	// before, but not during the bounded tail read after a gateway failure
	// (SEE: tailHold).
	//
	// teep's own attempt deadline bounds the relay and the downstream
	// writes (RelayDeadline). The upstream request runs receiptCheckTimeout
	// longer, so that a stream that teep's deadline cut can still be read
	// to its end for the receipt check. A deadline that the caller set
	// bounds both: teep serve sets none on the incoming request. With a
	// caller deadline, logical and the client's context expire on separate
	// timers at the same instant, so an ending at that deadline can be
	// classified as either side's; serve does not reach this.
	//
	// A Phala Cloud stream is read to its end after the client leaves
	// (drainable), so its upstream request also outlives a caller deadline,
	// by the drain bound.
	drainable := input.provider.Name == "phalacloud" && input.stream
	attemptDeadline := time.Now().Add(s.attemptTimeout(input.stream))
	callerBound := false
	if clientDeadline, ok := ctx.Deadline(); ok && clientDeadline.Before(attemptDeadline) {
		attemptDeadline, callerBound = clientDeadline, true
	}
	upstreamDeadline := attemptDeadline.Add(receiptCheckTimeout)
	switch {
	case drainable:
		upstreamDeadline = attemptDeadline.Add(max(receiptCheckTimeout, s.drainTimeout()))
	case callerBound:
		upstreamDeadline = attemptDeadline
	}
	logical, cancel := context.WithDeadline(context.WithoutCancel(ctx), upstreamDeadline)
	hold := newTailHold(ctx, func() {
		// Without a drain, logical has the caller's deadline already and
		// expires with the same error; only a cancellation needs passing
		// on.
		if drainable || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			cancel()
		}
	}, drainTimer(s.drainTimeout(), cancel))
	budget := max(0, time.Until(attemptDeadline))
	var attestDur, e2eeDur, upstreamDur time.Duration
	attempts := 0
	lastRetry := ""
	result, err := tlsct.RunInferenceAttempts(logical, func(attemptCtx context.Context) (authorizedResponse, bool, error) {
		attempts++
		result, retry, err := s.authorizedAttempt(attemptCtx, input)
		if retry && attempts < 2 && attemptCtx.Err() == nil {
			lastRetry = result.retryReason
			s.logAuthorizedRetry(attemptCtx, input, &result, attempts, err)
		}
		attestDur += result.outcome.attestDur
		e2eeDur += result.outcome.e2eeDur
		upstreamDur += result.outcome.upstreamDur
		return result, retry, err
	})
	result.outcome.attestDur, result.outcome.e2eeDur, result.outcome.upstreamDur = attestDur, e2eeDur, upstreamDur
	result.outcome.summary = append(result.outcome.summary, slog.Int("inference_attempts", attempts), slog.Duration("inference_timeout_budget", budget))
	if lastRetry != "" {
		result.outcome.summary = append(result.outcome.summary, slog.String("retry_reason", lastRetry))
	}
	if result.upstream == nil {
		hold.release()
		cancel()
	} else {
		attemptCancel := result.upstream.Cancel
		result.upstream.Cancel = func() { hold.release(); attemptCancel(); cancel() }
		result.upstream.EnterTail = hold.enterTail
		if drainable {
			result.upstream.MarkContent = hold.markContent
			result.upstream.Draining = hold.draining
			result.upstream.ClientEnded = hold.clientEnded
		}
		result.upstream.RelayDeadline = attemptDeadline
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
	result.outcome.summary = append(result.outcome.summary, slog.Int("upstream_status_code", ur.Resp.StatusCode))
	if tlsct.IsRedirectStatus(ur.Resp.StatusCode) {
		err = errors.New("upstream returned an unexpected redirect")
	} else if ur.Session != nil || ur.EHBP != nil || input.provider.Name == "phalacloud" || (input.provider.Name == "nearcloud" && input.path == "/v1/chat/completions" && ur.Resp.StatusCode == http.StatusMisdirectedRequest) {
		var rejected bool
		rejected, err = provider.KeyRejection(ur.Resp, input.provider.Name, input.path)
		if rejected {
			reason := "model_key_rejected"
			if input.provider.Name == "phalacloud" {
				reason = "session_not_accepted"
			}
			removed := s.authorizations.deleteGeneration(input.key, value.generation)
			s.logAuthorizationRejection(ctx, input, value, reason, removed, false)
			result.retryReason = reason
			if !input.provider.E2EE {
				return result, false, nil
			}
			cleanupAuthorized(ur)
			result.upstream = nil
			if input.provider.Name == "phalacloud" {
				return result, true, errors.New("upstream refused the pinned attested sessions")
			}
			return result, true, errors.New("upstream rejected the attested model key")
		}
	}
	if err == nil {
		err = s.refuseUncheckedSuccess(ctx, input, value, ur.Resp.StatusCode)
	}
	if err == nil && ur.Resp.StatusCode == http.StatusOK {
		err = s.checkAuthorizedKeyset(ctx, input, value, ur.Resp.Header)
	}
	if err != nil {
		cleanupAuthorized(ur)
		result.upstream = nil
		return result, false, err
	}
	return result, false, nil
}

// refuseUncheckedSuccess refuses a response with a 2xx status other than 200
// from an E2EE provider or from Phala Cloud. teep decrypts and authenticates
// an E2EE response body, and checks the Phala Cloud keyset digest and
// receipt, only for 200, and a client takes any 2xx for success, so such a
// response would reach the client unchecked. It is refused before anything
// is relayed, and the generation ends with the failure cooldown, as for a
// response that fails authentication.
func (s *Server) refuseUncheckedSuccess(ctx context.Context, input *authorizedRequest, value *authorization, status int) error {
	if !refusesUncheckedSuccess(input.provider, status) {
		return nil
	}
	removed := s.rejectResponseAuthorization(input.key, value.generation)
	s.logAuthorizationRejection(ctx, input, value, "unexpected_success_status", removed, removed)
	return fmt.Errorf("upstream answered HTTP %d; the response must be HTTP 200 to be checked", status)
}

// refusesUncheckedSuccess reports whether teep refuses status from p: a 2xx
// status other than 200 from an E2EE provider or from Phala Cloud, with or
// without E2EE.
func refusesUncheckedSuccess(p *provider.Provider, status int) bool {
	return (p.E2EE || p.Name == "phalacloud") && isUncheckedSuccess(status)
}

// isUncheckedSuccess reports whether status is a 2xx status other than 200.
func isUncheckedSuccess(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices && status != http.StatusOK
}

// checkAuthorizedKeyset checks the X-ACI-Keyset-Digest of a successful
// response against the keyset that the authorization's canonical ACI/1
// report binds; an error response is relayed as on the unpinned path. A
// response without the header, or of another digest, fails before teep
// relays it, and the authorization generation ends. ACI/1 §5.2 lets the
// gateway finish a response in flight under a new keyset, but its receipt
// is signed under keys that teep has not verified. The next send verifies
// again: a member of the same renewal family keeps continuity, another
// family becomes a new authorization (§3.1).
func (s *Server) checkAuthorizedKeyset(ctx context.Context, input *authorizedRequest, value *authorization, header http.Header) error {
	differs, err := attestation.CheckServedKeysetDigest(header, value.report)
	if !differs && err == nil {
		return nil
	}
	removed := s.authorizations.deleteGeneration(input.key, value.generation)
	if err != nil {
		s.logAuthorizationRejection(ctx, input, value, "keyset_digest_missing", removed, false)
		return err
	}
	s.logAuthorizationRejection(ctx, input, value, "keyset_digest_changed", removed, false)
	return errors.New("the response served another keyset digest; its receipt is signed under a keyset that teep has not verified")
}

func (s *Server) prepareAuthorizedRequest(ctx context.Context, input *authorizedRequest, value *authorization) (*upstreamResult, error) {
	req, encrypted, err := provider.PrepareInference(ctx, input.provider, input.route, &provider.InferenceInput{
		Body: input.body, SigningKey: value.signingKey, BackendFormat: value.report.BackendFormat, ACISessionIDs: value.report.ACISessionIDs, ModelKey: value.modelKey, Path: input.path, ContentType: input.contentType, Stream: input.stream, Endpoint: input.endpoint,
	})
	if err != nil {
		return nil, err
	}
	return &upstreamResult{Request: req, Session: encrypted.Session, Meta: encrypted.Chutes, EHBP: encrypted.EHBP, RequestHash: provider.ReceiptRequestHash(encrypted)}, nil
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
	// The relay and the downstream writes stop at teep's attempt deadline
	// and when the client's request ends; the upstream request may run
	// longer (SEE: authorizedRoundtrip).
	relayCtx, cancelRelay := context.WithCancel(result.upstream.Request.Context())
	defer cancelRelay()
	if !result.upstream.RelayDeadline.IsZero() {
		var cancelDeadline context.CancelFunc
		relayCtx, cancelDeadline = context.WithDeadline(relayCtx, result.upstream.RelayDeadline)
		defer cancelDeadline()
	}
	defer context.AfterFunc(ctx, cancelRelay)()
	if err := s.relayAuthorized(ctx, relayCtx, w, input, &result); err != nil {
		out.summary = append(out.summary, result.relayDiagnostics...)
		// A client that ends the request after it has the answer, but
		// before teep reads the end of the upstream stream, does not
		// make the decryption it received less proven.
		if input.provider.E2EE && callerCanceledOnly(ctx, err) && decryptedFields(result.upstream.Session) > 0 {
			value.report.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
			s.authorizations.promote(input.key, value.generation, "E2EE roundtrip succeeded via proxy")
		}
		return out, err
	}
	if input.provider.E2EE && e2eeConfirmed(result.upstream.Session) {
		value.report.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
		s.authorizations.promote(input.key, value.generation, "E2EE roundtrip succeeded via proxy")
	}
	out.status = "ok"
	out.summary = append(out.summary, authorizationIdentityDiagnostics(value)...)
	return out, nil
}

// relayAuthorized relays the response of one attempt. ctx is the attempt
// context, which teep's own stream deadline bounds; clientCtx is the context
// of the client's request, the only signal that the client side ended.
func (s *Server) relayAuthorized(clientCtx, ctx context.Context, w http.ResponseWriter, input *authorizedRequest, result *authorizedResponse) (retErr error) {
	writer, err := newResponseLifetime(ctx, w)
	if err != nil {
		return err
	}
	// ctx learns of the client's end through a goroutine (context.AfterFunc
	// in inferAuthorized); the writer reads the client's context itself, so
	// that no byte goes to a client after its request ended, whichever
	// goroutine runs first.
	relayErr := writer.contextErr
	writer.contextErr = func() error {
		if err := clientCtx.Err(); err != nil {
			return err
		}
		return relayErr()
	}
	defer func() {
		for _, err := range []error{writer.err, writer.contextErr()} {
			if err != nil && !errors.Is(retErr, err) {
				retErr = errors.Join(retErr, err)
			}
		}
	}()
	w = writer
	ur := result.upstream
	writer.onFirstWrite = ur.MarkContent
	resp := ur.Resp
	var body io.Reader = resp.Body
	invalidate := func(reason string) {
		removed := s.rejectResponseAuthorization(input.key, result.authorization.generation)
		s.logAuthorizationRejection(ctx, input, result.authorization, reason, removed, removed)
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
	var receipt *receiptRelay
	if input.key.ProviderName() == "phalacloud" && resp.StatusCode == http.StatusOK {
		// Every successful Phala Cloud response must have a receipt that
		// verifies; a non-stream response is held until it does.
		receipt, err = newReceiptRelay(resp.Header, body)
		if err != nil {
			return s.receiptFailed(ctx, input, result, "receipt_id_invalid", err, true)
		}
		body = receipt.wire
	}
	// The upstream headers go to the client only for a response that
	// passed the checks above; a refused response sends none of them.
	progress := &responseReadProgress{Reader: body}
	body = responseLifetimeReader{Reader: progress, check: writer.check}
	if resp.StatusCode != http.StatusOK {
		copyAuthorizedHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, err := io.Copy(w, io.LimitReader(body, 10<<20))
		if errors.Is(err, e2ee.ErrDecryptionFailed) {
			invalidate("response_decryption")
		}
		result.relayDiagnostics = responseFailureDiagnostics(progress, writer)
		return errors.Join(fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), err)
	}
	started := time.Now()
	// The relay of a 200 response writes a 2xx status only for upstream
	// content; any other status is teep's own error (a stream whose first
	// read fails), which carries none of the upstream headers.
	w = newUpstreamHeaderWriter(w, resp.Header)
	target := w
	var held *heldResponse
	if receipt != nil && !input.stream {
		held = &heldResponse{header: w.Header()}
		target = held
	}
	streamStats, err := relayResponse(ctx, target, body, ur.Session, ur.Meta, input.stream, input.endpoint)
	switch {
	case receipt == nil:
	case err == nil:
		err = s.checkReceipt(ctx, input, result, receipt)
		if err == nil && held != nil {
			err = held.release(w)
		}
	case input.stream && (streamStats.Chunks > 0 || streamStats.Forwarded > 0):
		// The stream failed after content reached the client: the check
		// must still run, or the gateway could skip it.
		s.checkReceiptAfterRelayFailure(clientCtx, input, result, receipt, relayEnding{err: err, downstream: writer.err, upstreamBody: resp.Body, enterTail: ur.EnterTail, draining: ur.Draining, clientEnded: ur.ClientEnded})
	}
	if err != nil || writer.check() != nil {
		if input.stream {
			result.relayDiagnostics = streamFailureDiagnostics(started, streamStats, progress, writer)
		} else {
			result.relayDiagnostics = responseFailureDiagnostics(progress, writer)
		}
	}
	recordTokPerSec(s.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority()), streamStats)
	if errors.Is(err, e2ee.ErrDecryptionFailed) {
		invalidate("response_decryption")
	}
	return err
}

// handleAuthorizedEndpoint writes summary attributes to the INFO completion
// record for every request. Warning-only diagnostics go to the WARN record for
// an independent failure; caller cancellation moves them into summary instead.
func (s *Server) handleAuthorizedEndpoint(ctx context.Context, w http.ResponseWriter, input *authorizedRequest) authorizedOutcome {
	ri, writer := newResponseInterceptor(w)
	out, err := s.inferAuthorized(ctx, writer, input)
	out.summary = append(out.summary, slog.Bool("downstream_headers_committed", ri.headerSent))
	if err != nil {
		out.summary = append(out.summary, slog.Int64("downstream_bytes_written", ri.bytesWritten))
		if len(out.diagnostics) == 0 {
			out.diagnostics = []slog.Attr{slog.String("authority", input.key.Authority())}
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
			out.summary = append(out.summary, slog.String("failure_phase", "authorization"))
		}
		if !warn {
			out.summary = append(out.summary, out.diagnostics...)
		}
		if warn {
			attrs := make([]slog.Attr, 0, 3+len(out.diagnostics)+len(out.summary))
			attrs = append(attrs, slog.String("provider", input.provider.Name), slog.String("model", input.key.Model()), slog.Any("err", err))
			attrs = append(attrs, out.diagnostics...)
			attrs = append(attrs, out.summary...)
			s.authorizations.log().LogAttrs(ctx, slog.LevelWarn, "authorized inference failed", attrs...)
		}
		s.stats.errors.Add(1)
		s.stats.getModelStats(input.key.ProviderName(), input.key.Model()+"@"+input.key.Authority()).errors.Add(1)
		if !ri.headerSent {
			// The upstream headers were copied before the relay; teep's own
			// error response carries none of them.
			clear(writer.Header())
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
func authorizationFailureDiagnostics(value *authorization, err error, removed bool) []slog.Attr {
	attrs := append(authorizationIdentityDiagnostics(value), slog.Bool("authorization_removed", removed))
	if mismatch, ok := errors.AsType[*tlsct.SPKIMismatchError](err); ok {
		attrs = append(attrs, slog.String("tls_authority", mismatch.Authority), slog.String("tls_sni", mismatch.ServerName), slog.String("expected_spki", mismatch.Expected), slog.String("observed_spki", mismatch.Observed))
	}
	return attrs
}

func (s *Server) logAuthorizationRejection(ctx context.Context, input *authorizedRequest, value *authorization, reason string, removed, cooldown bool) {
	attrs := make([]slog.Attr, 0, 8)
	attrs = append(attrs, slog.String("provider", input.provider.Name), slog.String("model", input.key.Model()), slog.String("reason", reason), slog.Bool("cooldown_recorded", cooldown))
	attrs = append(attrs, authorizationFailureDiagnostics(value, nil, removed)...)
	s.authorizations.log().LogAttrs(ctx, slog.LevelWarn, "response authorization rejected", attrs...)
}

func authorizationIdentityDiagnostics(value *authorization) []slog.Attr {
	return []slog.Attr{slog.String("authority", value.identity.Authority()), slog.Uint64("authorization_generation", uint64(value.generation)), slog.Time("authorization_published_at", value.publishedAt)}
}

func (s *Server) logAuthorizedRetry(ctx context.Context, input *authorizedRequest, result *authorizedResponse, attempt int, err error) {
	attrs := []slog.Attr{slog.String("provider", input.provider.Name), slog.String("model", input.key.Model()), slog.Int("inference_attempt", attempt), slog.String("retry_reason", result.retryReason), slog.Any("err", err)}
	attrs = append(attrs, result.outcome.diagnostics...)
	attrs = append(attrs, result.outcome.summary...)
	if result.outcome.trace != nil {
		attrs = append(attrs, result.outcome.trace.TimingDiagnostics()...)
		attrs = append(attrs, result.outcome.trace.ConnectionDiagnostics()...)
	}
	s.authorizations.log().LogAttrs(ctx, slog.LevelWarn, "authorized inference retry scheduled", attrs...)
}

// upstreamHeaderWriter puts the upstream response headers on the client
// response before the relay, so that the relay sets its own headers over
// them and keeps an upstream header that it sets only when absent (the media
// type of a speech response). When the first status written is not a 2xx
// status, the response is teep's own error: the upstream headers that still
// have their upstream values are removed before it is written.
type upstreamHeaderWriter struct {
	http.ResponseWriter
	copied  http.Header
	written bool
}

func newUpstreamHeaderWriter(w http.ResponseWriter, src http.Header) *upstreamHeaderWriter {
	copied := http.Header{}
	copyAuthorizedHeaders(copied, src)
	dst := w.Header()
	for name, values := range copied {
		dst[name] = slices.Clone(values)
	}
	return &upstreamHeaderWriter{ResponseWriter: w, copied: copied}
}

func (w *upstreamHeaderWriter) WriteHeader(code int) {
	if !w.written {
		w.written = true
		if code < http.StatusOK || code >= http.StatusMultipleChoices {
			dst := w.Header()
			for name, values := range w.copied {
				if slices.Equal(dst[name], values) {
					delete(dst, name)
				}
			}
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *upstreamHeaderWriter) Write(p []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// Flush commits the headers as a 200 status when none was written, as the
// writer below would.
func (w *upstreamHeaderWriter) Flush() {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *upstreamHeaderWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

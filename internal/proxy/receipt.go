package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/aci"
)

// receiptCheckTimeout bounds the receipt fetch and check of one response.
// The check runs under a context that the server owns, so a client that
// hangs up does not decide its result.
const receiptCheckTimeout = 30 * time.Second

// receiptRelay hashes the wire bytes of one Phala Cloud response for the
// receipt check (ACI/1 §9.3), and records how reading from upstream ended.
type receiptRelay struct {
	id       string
	wire     *aci.ResponseHash
	upstream *upstreamRead
}

func newReceiptRelay(header http.Header, body io.Reader) (*receiptRelay, error) {
	id, err := aci.ReceiptID(header)
	if err != nil {
		return nil, err
	}
	upstream := &upstreamRead{r: body}
	return &receiptRelay{id: id, wire: aci.NewResponseHash(upstream), upstream: upstream}, nil
}

// upstreamRead records whether the read of the upstream body reached EOF.
type upstreamRead struct {
	r   io.Reader
	eof bool
}

func (u *upstreamRead) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	if errors.Is(err, io.EOF) {
		u.eof = true
	}
	return n, err
}

// relayEnding is how the relay of a stream failed: its error, the error of
// the downstream write or flush (nil when there was none), and the upstream
// body, which teep closes when reading the rest of it takes too long.
type relayEnding struct {
	err          error
	downstream   error
	upstreamBody io.Closer
	// enterTail claims the upstream attempt for the tail read
	// (upstreamResult.EnterTail); nil when the attempt has no hold.
	enterTail func() bool
	// draining reports whether the client left after content, so that
	// teep reads the rest of the stream (upstreamResult.Draining); nil when
	// the attempt is not drained.
	draining func() bool
}

// drainAndCheckReceipt reads the rest of a stream that the client left
// after content reached it, then checks the receipt over the whole
// response. teep did not cancel the upstream request, so the gateway sees a
// complete stream and must publish its receipt. The drain bound, armed
// when the client left, cancels the upstream request when it passes, and
// the read stops at the byte bound. A stream that does not end within
// them, and a receipt that is not served or does not verify, are the
// gateway's failure and end the generation.
func (s *Server) drainAndCheckReceipt(clientCtx context.Context, input *authorizedRequest, result *authorizedResponse, rr *receiptRelay, attrs []slog.Attr) {
	responseHash, err := rr.wire.FinishLimit(s.drainBytes())
	if err != nil {
		responseHash = rr.wire.Received()
	}
	ctx, cancel := serverContext(clientCtx)
	defer cancel()
	if err := s.verifyResponseReceipt(ctx, input, result, rr, responseHash, true, true); err != nil {
		s.authorizations.log().LogAttrs(ctx, slog.LevelError, "the client left, and the receipt check of the rest of the stream failed", attrs...)
	}
}

// endedByClient reports whether the relay failed because the client side
// ended, from positive evidence only: the relay error is the error of the
// downstream write or flush, or the error of the client's own request
// context, which has ended. teep's own deadline for the attempt is not the
// client's, and every other relay error (a reset, a cut, a stream that does
// not parse) is the gateway's.
func endedByClient(clientCtx context.Context, ending relayEnding) bool {
	if ending.downstream != nil && errors.Is(ending.err, ending.downstream) {
		// The downstream write deadline is the attempt deadline, which
		// teep sets: a write that fails on it is the client's only when
		// the client's own context has ended too.
		if errors.Is(ending.downstream, os.ErrDeadlineExceeded) || errors.Is(ending.downstream, context.DeadlineExceeded) {
			return clientCtx.Err() != nil
		}
		return true
	}
	clientErr := clientCtx.Err()
	return clientErr != nil && errors.Is(ending.err, clientErr)
}

// finishWithin reads the rest of the upstream body into the response hash,
// and closes the body when ctx ends first. It returns the hash of every
// byte read, also when the read fails.
func (rr *receiptRelay) finishWithin(ctx context.Context, body io.Closer) [32]byte {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = body.Close()
		case <-done:
		}
	}()
	if sum, err := rr.wire.Finish(); err == nil {
		return sum
	}
	return rr.wire.Received()
}

// serverContext returns a context for the receipt check that the client's
// cancellation does not end, bounded by receiptCheckTimeout.
func serverContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), receiptCheckTimeout)
}

// checkReceipt fetches the receipt of a relayed Phala Cloud response over the
// pinned client and verifies it against the authorization that the request
// used. A receipt whose signature, keyset, response hash, session or
// served_at does not verify ends that authorization generation. For a
// stream, which reached the client before its check, every failure ends the
// generation. For a non-stream response, which teep holds until the check
// passes, a receipt that cannot be fetched or whose statements about the
// request differ from it fails the request and keeps the generation:
// neither is evidence against the attestation that other clients share.
func (s *Server) checkReceipt(ctx context.Context, input *authorizedRequest, result *authorizedResponse, rr *receiptRelay) error {
	ctx, cancel := serverContext(ctx)
	defer cancel()
	// A stream reached the client before its check, so for a stream every
	// failure of the check that the gateway causes ends the generation.
	delivered := input.stream
	responseHash, err := rr.wire.Finish()
	if err != nil {
		return s.receiptFailed(ctx, input, result, "receipt_response_incomplete", err, delivered)
	}
	return s.verifyResponseReceipt(ctx, input, result, rr, responseHash, delivered, false)
}

// checkReceiptAfterRelayFailure handles a stream whose relay failed after
// teep relayed content to the client:
//   - the client side ended it (endedByClient) before the read from
//     upstream reached its end: one client must not end the authorization
//     that every client shares, so the generation stays, and the error log
//     says that content went out without a completed check.
//   - otherwise the failure is the gateway's. teep reads the rest of the
//     upstream body under the server's bounded context, so that a gateway
//     that ended its stream badly but signed what it sent can still verify,
//     and checks the receipt against the hash of every byte read from
//     upstream. Every failure that the gateway causes ends the generation;
//     a stream cut before its end does not verify, also when the network
//     cut it.
//
// The relayed content cannot be recalled.
func (s *Server) checkReceiptAfterRelayFailure(clientCtx context.Context, input *authorizedRequest, result *authorizedResponse, rr *receiptRelay, ending relayEnding) {
	attrs := []slog.Attr{slog.String("provider", input.provider.Name), slog.String("model", input.key.Model()), slog.String("receipt_id", rr.id)}
	logCtx := context.WithoutCancel(clientCtx)
	if ending.draining != nil && ending.draining() {
		s.drainAndCheckReceipt(clientCtx, input, result, rr, attrs)
		return
	}
	clientEnded := !rr.upstream.eof && endedByClient(clientCtx, ending)
	if s.tailClaimHook != nil {
		s.tailClaimHook()
	}
	// The relay failed for a reason that is not the client's. If the
	// client's end abandoned the attempt before teep claimed it for the
	// tail read, the client side ended the response after all.
	if !clientEnded && !rr.upstream.eof && ending.enterTail != nil && !ending.enterTail() {
		clientEnded = true
	}
	if clientEnded {
		s.authorizations.log().LogAttrs(logCtx, slog.LevelError, "content was relayed without a completed receipt check: the client side ended the response", attrs...)
		return
	}
	// The tail read and the receipt fetch each have their own bound, so a
	// tail read that uses its whole bound leaves the fetch its own.
	tailCtx, cancelTail := serverContext(clientCtx)
	responseHash := rr.finishWithin(tailCtx, ending.upstreamBody)
	cancelTail()
	ctx, cancel := serverContext(clientCtx)
	defer cancel()
	if err := s.verifyResponseReceipt(ctx, input, result, rr, responseHash, true, true); err != nil {
		s.authorizations.log().LogAttrs(ctx, slog.LevelError, "content was relayed before the receipt check failed", attrs...)
	}
}

// verifyResponseReceipt fetches the receipt of rr and verifies it with
// responseHash. With delivered (content already reached the client), every
// failure ends the generation. With patient, the receipt GET retries HTTP
// 404 until ctx ends (aci.FetchReceiptUntil).
func (s *Server) verifyResponseReceipt(ctx context.Context, input *authorizedRequest, result *authorizedResponse, rr *receiptRelay, responseHash [32]byte, delivered, patient bool) error {
	value := result.authorization
	// teep resolved the model and wrote it into the body that it sent, so
	// the body is not decoded again here. A request without one is the
	// client's and keeps the generation; serve refuses it before it is
	// sent.
	if input.model == "" {
		return s.receiptFailed(ctx, input, result, "receipt_request_model", errors.New("request has no resolved model"), false)
	}
	client, err := s.pinnedClientForIdentity(input.provider.Name, value.identity)
	if err != nil {
		return s.receiptFailed(ctx, input, result, "receipt_fetch_failed", err, delivered)
	}
	fetch := aci.FetchReceipt
	if patient {
		// After a stream that failed or that the client left, the gateway
		// can delay its receipt until its backend reaches its end.
		fetch = aci.FetchReceiptUntil
	}
	receipt, err := fetch(ctx, client, input.route.BaseURL(), input.provider.APIKey, rr.id)
	if err != nil {
		if errors.Is(err, aci.ErrMalformedReceipt) {
			return s.receiptFailed(ctx, input, result, "receipt_malformed", err, true)
		}
		return s.receiptFailed(ctx, input, result, "receipt_fetch_failed", err, delivered)
	}
	check := &aci.ReceiptCheck{
		Keys: value.report.ACIReceiptKeys, KeysetDigest: value.report.ACIKeysetDigest, NotAfter: value.report.ACIKeysetNotAfter,
		Endpoint: input.path, Method: http.MethodPost, Model: input.model,
		ResponseHash: responseHash, RequestHash: result.upstream.RequestHash, Sessions: value.report.ACIPinnedSessions,
	}
	if err := aci.VerifyReceipt(receipt, check); err != nil {
		if errors.Is(err, aci.ErrReceiptRouteMismatch) {
			// The gateway names the endpoint, method and model of the
			// request it received. For content that already went out,
			// another name ends the generation.
			return s.receiptFailed(ctx, input, result, "receipt_route_mismatch", err, delivered)
		}
		if errors.Is(err, aci.ErrReceiptRequestMismatch) {
			// One client's request must not end the authorization that
			// every client shares; the client chooses its request.
			return s.receiptFailed(ctx, input, result, "receipt_request_mismatch", err, false)
		}
		return s.receiptFailed(ctx, input, result, "receipt_rejected", err, true)
	}
	// The signature covers these members; log them only for a receipt
	// that verified.
	if len(receipt.Unknown) > 0 {
		slog.WarnContext(ctx, "ACI receipt has members that teep does not define; they are not checked",
			"provider", input.provider.Name, "receipt_id", receipt.ID, "members", receipt.Unknown)
	}
	s.authorizations.log().LogAttrs(ctx, slog.LevelDebug, "receipt verified",
		slog.String("provider", input.provider.Name), slog.String("model", input.key.Model()),
		slog.String("receipt_id", receipt.ID), slog.Bool("request_hash_checked", check.RequestHash != nil))
	return nil
}

// receiptFailed logs a failed receipt check at error level and returns its
// error. When invalidate is true, the authorization generation that the
// request used ends.
func (s *Server) receiptFailed(ctx context.Context, input *authorizedRequest, result *authorizedResponse, reason string, err error, invalidate bool) error {
	removed := false
	if invalidate {
		removed = s.authorizations.deleteGeneration(input.key, result.authorization.generation)
	}
	attrs := make([]slog.Attr, 0, 9)
	attrs = append(attrs,
		slog.String("provider", input.provider.Name), slog.String("model", input.key.Model()),
		slog.String("reason", reason), slog.Bool("stream", input.stream), slog.Any("err", err))
	attrs = append(attrs, authorizationFailureDiagnostics(result.authorization, nil, removed)...)
	s.authorizations.log().LogAttrs(ctx, slog.LevelError, "response receipt check failed", attrs...)
	return fmt.Errorf("receipt check: %w", err)
}

// heldResponse keeps a non-stream response until its receipt verifies. It
// shares the header map of the downstream writer, which sends nothing until
// release writes the status. It holds at most e2ee.MaxNonStreamResponseBytes,
// the bound of a reassembled non-stream response; a larger body fails.
type heldResponse struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

// errHeldResponseTooLarge is the failure of a held body over its bound.
var errHeldResponseTooLarge = fmt.Errorf("held non-stream response exceeds %d bytes", e2ee.MaxNonStreamResponseBytes)

func (h *heldResponse) Header() http.Header { return h.header }

func (h *heldResponse) WriteHeader(code int) {
	if h.status == 0 {
		h.status = code
	}
}

func (h *heldResponse) Write(p []byte) (int, error) {
	h.WriteHeader(http.StatusOK)
	if h.overflow || h.body.Len()+len(p) > e2ee.MaxNonStreamResponseBytes {
		h.overflow = true
		return 0, errHeldResponseTooLarge
	}
	return h.body.Write(p)
}

// release writes the held status and body to w. A body over its bound fails
// and writes nothing, also when the relay ignored the Write error.
func (h *heldResponse) release(w http.ResponseWriter) error {
	if h.overflow {
		return errHeldResponseTooLarge
	}
	if h.status == 0 {
		h.status = http.StatusOK
	}
	w.WriteHeader(h.status)
	_, err := w.Write(h.body.Bytes())
	return err
}

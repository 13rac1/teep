package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider/aci"
)

// receiptRelay hashes the wire bytes of one Phala Cloud response for the
// receipt check (ACI/1 §9.3).
type receiptRelay struct {
	id   string
	wire *aci.ResponseHash
}

func newReceiptRelay(header http.Header, body io.Reader) (*receiptRelay, error) {
	id, err := aci.ReceiptID(header)
	if err != nil {
		return nil, err
	}
	return &receiptRelay{id: id, wire: aci.NewResponseHash(body)}, nil
}

// checkReceipt fetches the receipt of a relayed Phala Cloud response over the
// pinned client and verifies it against the authorization that the request
// used. A receipt whose signature, keyset, response hash, session or
// served_at does not verify ends that authorization generation. A receipt
// that cannot be fetched, or whose statements about the request differ from
// it, fails the request and keeps the generation: neither is evidence
// against the attestation that other clients share.
func (s *Server) checkReceipt(ctx context.Context, input *authorizedRequest, result *authorizedResponse, rr *receiptRelay) error {
	value := result.authorization
	responseHash, err := rr.wire.Finish()
	if err != nil {
		return s.receiptFailed(ctx, input, result, "receipt_response_incomplete", err, false)
	}
	var body struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(input.body, &body); err != nil || body.Model == "" {
		return s.receiptFailed(ctx, input, result, "receipt_request_model", errors.New("request body has no string model"), false)
	}
	client, err := s.pinnedClientForIdentity(input.provider.Name, value.identity)
	if err != nil {
		return s.receiptFailed(ctx, input, result, "receipt_fetch_failed", err, false)
	}
	receipt, err := aci.FetchReceipt(ctx, client, input.route.BaseURL(), input.provider.APIKey, rr.id)
	if err != nil {
		if errors.Is(err, aci.ErrMalformedReceipt) {
			return s.receiptFailed(ctx, input, result, "receipt_malformed", err, true)
		}
		return s.receiptFailed(ctx, input, result, "receipt_fetch_failed", err, false)
	}
	check := &aci.ReceiptCheck{
		Keys: value.report.ACIReceiptKeys, KeysetDigest: value.report.ACIKeysetDigest, NotAfter: value.report.ACIKeysetNotAfter,
		Endpoint: input.path, Method: http.MethodPost, Model: body.Model,
		ResponseHash: responseHash, RequestHash: result.upstream.RequestHash, Sessions: value.report.ACIPinnedSessions,
	}
	if err := aci.VerifyReceipt(receipt, check); err != nil {
		if errors.Is(err, aci.ErrReceiptRequestMismatch) {
			// One client's request must not end the authorization that
			// every client shares.
			return s.receiptFailed(ctx, input, result, "receipt_request_mismatch", err, false)
		}
		return s.receiptFailed(ctx, input, result, "receipt_rejected", err, true)
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

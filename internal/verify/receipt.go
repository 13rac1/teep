package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
)

// probeReceipt is the receipt check of one Phala Cloud probe response.
type probeReceipt struct {
	client      *http.Client
	route       provider.ResolvedRoute
	pinned      []attestation.ACIPinnedSession
	requestHash *[32]byte
}

// verifyPhalaProbe checks the E2EE v2 stream of a Phala Cloud probe, then
// fetches its receipt over the pinned client and verifies it (ACI/1 §9.3),
// as teep serve does for every response. A failure of the stream goes to
// e2ee_usable. Once the response is HTTP 200 with the verified keyset digest
// and an event stream, every outcome except a verified receipt fails
// aci_receipt_verified (result.Receipt), whatever happens to the stream: a
// missing or malformed receipt id, a reset, a stream without [DONE], content
// that does not decrypt, and a failed receipt request (a network fault can
// cause that one too; its detail says to run again).
func verifyPhalaProbe(ctx context.Context, opts *Options, raw *attestation.RawAttestation, resp *http.Response, session *e2ee.ACIv2Session, pr *probeReceipt) *attestation.E2EETestResult {
	id, idErr := aci.ReceiptID(resp.Header)
	wire := aci.NewResponseHash(resp.Body)
	resp.Body = struct {
		io.Reader
		io.Closer
	}{wire, resp.Body}
	if err := checkACIv2Response(resp, raw); err != nil {
		// No answer to the request: the receipt factor stays a deferred
		// Skip, and e2ee_usable states the failure.
		return &attestation.E2EETestResult{Attempted: true, Err: err}
	}
	// From here on, every outcome except a verified receipt fails
	// aci_receipt_verified, whatever happens to the stream: the gateway
	// must not be able to choose a failure that skips the check.
	result := readACIv2Stream(resp, session)
	if idErr != nil {
		result.Receipt = &attestation.ACIReceiptResult{Err: idErr}
		return result
	}
	// The receipt covers the whole response the gateway sent. Read what is
	// left of it; when that read fails, check the bytes that arrived, which
	// a stream cut before its end does not match.
	responseHash, err := wire.Finish()
	if err != nil {
		responseHash = wire.Received()
	}
	result.Receipt = verifyProbeReceipt(ctx, opts, raw, id, responseHash, pr)
	return result
}

// verifyProbeReceipt fetches the receipt id and checks it against
// responseHash. Err is set when teep did not obtain a receipt that
// verifies.
func verifyProbeReceipt(ctx context.Context, opts *Options, raw *attestation.RawAttestation, id string, responseHash [32]byte, pr *probeReceipt) *attestation.ACIReceiptResult {
	receipt, err := aci.FetchReceipt(ctx, pr.client, pr.route.BaseURL(), opts.Provider.APIKey, id)
	switch {
	case errors.Is(err, aci.ErrMalformedReceipt) || errors.Is(err, aci.ErrReceiptNotServed):
		return &attestation.ACIReceiptResult{Err: err}
	case err != nil:
		return &attestation.ACIReceiptResult{Err: fmt.Errorf("the receipt request failed: %w; run again", err)}
	}
	check := &aci.ReceiptCheck{
		Keys: raw.ACIReceiptKeys, KeysetDigest: raw.ACIWorkloadKeysetDigest, NotAfter: raw.ACIKeysetNotAfter,
		Endpoint: "/v1/chat/completions", Method: http.MethodPost, Model: opts.ModelName,
		ResponseHash: responseHash, RequestHash: pr.requestHash, Sessions: pr.pinned,
	}
	result := &attestation.ACIReceiptResult{Unknown: receipt.Unknown}
	switch err := aci.VerifyReceipt(receipt, check); {
	case err != nil:
		result.Err = err
	case pr.requestHash == nil:
		result.Detail = "receipt verified, request hash not checked: the request has a value that the gateway can write in another form"
	default:
		result.Detail = "receipt verified, including the request hash"
	}
	// The signature covers these members; log them only for a receipt
	// that verified.
	if result.Err == nil && len(receipt.Unknown) > 0 {
		slog.WarnContext(ctx, "ACI receipt has members that teep does not define; they are not checked",
			"provider", opts.ProviderName, "receipt_id", receipt.ID, "members", receipt.Unknown)
	}
	return result
}

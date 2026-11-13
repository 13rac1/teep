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
// e2ee_usable. Once the stream verified, a missing or malformed receipt id
// and every failure to obtain a verified receipt go to aci_receipt_verified
// (result.Receipt): the gateway under test must not choose a class of
// failure that does not block. That includes a failed receipt request (a
// transport error, a short body, the end of ctx), which a network fault can
// also cause; its detail says to run again.
func verifyPhalaProbe(ctx context.Context, opts *Options, raw *attestation.RawAttestation, resp *http.Response, session *e2ee.ACIv2Session, pr *probeReceipt) *attestation.E2EETestResult {
	id, idErr := aci.ReceiptID(resp.Header)
	wire := aci.NewResponseHash(resp.Body)
	resp.Body = struct {
		io.Reader
		io.Closer
	}{wire, resp.Body}
	result := verifyACIv2StreamResponse(resp, session, raw)
	if result.Err != nil {
		return result
	}
	if idErr != nil {
		result.Receipt = &attestation.ACIReceiptResult{Err: idErr}
		return result
	}
	result.Receipt = verifyProbeReceipt(ctx, opts, raw, id, wire, pr)
	return result
}

// verifyProbeReceipt fetches the receipt id and checks it. Err is set when
// teep did not obtain a receipt that verifies. The verified stream was read
// to its end, so the hash of the response does not fail in practice; if it
// does, the receipt cannot be checked and fails too.
func verifyProbeReceipt(ctx context.Context, opts *Options, raw *attestation.RawAttestation, id string, wire *aci.ResponseHash, pr *probeReceipt) *attestation.ACIReceiptResult {
	responseHash, err := wire.Finish()
	if err != nil {
		return &attestation.ACIReceiptResult{Err: fmt.Errorf("hash the probe response: %w", err)}
	}
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

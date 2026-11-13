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
// as teep serve does for every response. The stream and a failure to fetch
// the receipt go to e2ee_usable; a receipt that is missing, malformed or
// fails the check goes to aci_receipt_verified (result.Receipt).
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
	receipt, err := verifyProbeReceipt(ctx, opts, raw, id, wire, pr)
	if err != nil {
		// The receipt could not be fetched: a transport or HTTP failure of
		// the probe, not a statement of the service.
		result.Err = fmt.Errorf("receipt fetch: %w", err)
		return result
	}
	result.Receipt = receipt
	return result
}

// verifyProbeReceipt fetches the receipt id and checks it. It returns a
// nil result with an error when the response or the receipt could not be
// read, and a result (with Err set when the check fails) otherwise.
func verifyProbeReceipt(ctx context.Context, opts *Options, raw *attestation.RawAttestation, id string, wire *aci.ResponseHash, pr *probeReceipt) (*attestation.ACIReceiptResult, error) {
	responseHash, err := wire.Finish()
	if err != nil {
		return nil, err
	}
	receipt, err := aci.FetchReceipt(ctx, pr.client, pr.route.BaseURL(), opts.Provider.APIKey, id)
	if errors.Is(err, aci.ErrMalformedReceipt) {
		return &attestation.ACIReceiptResult{Err: err}, nil
	}
	if err != nil {
		return nil, err
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
	return result, nil
}

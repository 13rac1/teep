package verify

import (
	"context"
	"fmt"
	"io"
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
// as teep serve does for every response. A probe passes only when the
// receipt verifies.
func verifyPhalaProbe(ctx context.Context, opts *Options, raw *attestation.RawAttestation, resp *http.Response, session *e2ee.ACIv2Session, pr *probeReceipt) *attestation.E2EETestResult {
	id, err := aci.ReceiptID(resp.Header)
	if err != nil {
		return &attestation.E2EETestResult{Attempted: true, Err: fmt.Errorf("receipt: %w", err)}
	}
	wire := aci.NewResponseHash(resp.Body)
	resp.Body = struct {
		io.Reader
		io.Closer
	}{wire, resp.Body}
	result := verifyACIv2StreamResponse(resp, session, raw)
	if result.Err != nil {
		return result
	}
	detail, err := verifyProbeReceipt(ctx, opts, raw, id, wire, pr)
	if err != nil {
		result.Err = fmt.Errorf("receipt: %w", err)
		return result
	}
	result.Detail += detail
	return result
}

func verifyProbeReceipt(ctx context.Context, opts *Options, raw *attestation.RawAttestation, id string, wire *aci.ResponseHash, pr *probeReceipt) (string, error) {
	responseHash, err := wire.Finish()
	if err != nil {
		return "", err
	}
	receipt, err := aci.FetchReceipt(ctx, pr.client, pr.route.BaseURL(), opts.Provider.APIKey, id)
	if err != nil {
		return "", err
	}
	check := &aci.ReceiptCheck{
		Keys: raw.ACIReceiptKeys, KeysetDigest: raw.ACIWorkloadKeysetDigest, NotAfter: raw.ACIKeysetNotAfter,
		Endpoint: "/v1/chat/completions", Method: http.MethodPost, Model: opts.ModelName,
		ResponseHash: responseHash, RequestHash: pr.requestHash, Sessions: pr.pinned,
	}
	if err := aci.VerifyReceipt(receipt, check); err != nil {
		return "", err
	}
	if pr.requestHash == nil {
		return "; receipt verified, request hash not checked: the request has a value that the gateway can write in another form", nil
	}
	return "; receipt verified, including the request hash", nil
}

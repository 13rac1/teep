package attestation

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/tlsct"
	"github.com/google/go-sev-guest/verify/testdata"
	sevtrust "github.com/google/go-sev-guest/verify/trust"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
)

// Reject before a connection can be opened, as the transport budget does.
type collateralCapacityTransport struct{ calls atomic.Int32 }

func (t *collateralCapacityTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, tlsct.ErrConnectionCapacity
}

func TestCollateralCapacityNoRetry(t *testing.T) {
	for _, kind := range []string{"SEV", "TDX"} {
		t.Run(kind, func(t *testing.T) {
			transport := &collateralCapacityTransport{}
			client := &http.Client{Transport: transport}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var err error
			if kind == "SEV" {
				_, err = sevtrust.GetWith(ctx, NewSEVCertGetter(client), "https://kdsintf.amd.com/cert")
			} else {
				_, _, err = tdxtrust.GetWith(ctx, NewCollateralGetter(client), "https://api.trustedservices.intel.com/cert")
			}
			if !errors.Is(err, tlsct.ErrConnectionCapacity) || ctx.Err() != nil || transport.calls.Load() != 1 {
				t.Fatalf("capacity was retried or obscured: calls=%d err=%v context=%v", transport.calls.Load(), err, ctx.Err())
			}
		})
	}
}

func TestSEVVerificationPreservesCapacityCause(t *testing.T) {
	transport := &collateralCapacityTransport{}
	getter := NewSEVCertGetter(&http.Client{Transport: transport})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			// Parse a real signed report and execute the production certificate
			// retrieval path. Capacity rejection prevents authenticating it.
			result := VerifySEVReportOnline(ctx, testdata.AttestationBytes, getter)
			_, present := result.Validity.Expiry()
			if !errors.Is(result.CertChainErr, tlsct.ErrConnectionCapacity) || result.OnlineVerified || present {
				t.Errorf("capacity cause lost or failed evidence authenticated: %v", result.CertChainErr)
			}
		})
	}
	wg.Wait()
	if transport.calls.Load() != 8 {
		t.Fatalf("certificate retrieval retried: calls=%d", transport.calls.Load())
	}
}

func TestTDXVerificationPreservesCapacityCause(t *testing.T) {
	transport := &collateralCapacityTransport{}
	getter := NewCollateralGetter(&http.Client{Transport: transport})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			result := VerifyTDXQuoteOnline(ctx, realTDXQuoteHex(), getter, time.Time{})
			_, present := result.Validity.Expiry()
			if !errors.Is(result.CollateralErr, tlsct.ErrConnectionCapacity) || present {
				t.Errorf("capacity cause lost or failed collateral authenticated: %v", result.CollateralErr)
			}
		})
	}
	wg.Wait()
	if transport.calls.Load() != 8 {
		t.Fatalf("collateral retrieval retried: calls=%d", transport.calls.Load())
	}
}

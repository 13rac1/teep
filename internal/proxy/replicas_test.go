package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// Every instance of a NEAR cloud model is verified: a quote that fails on
// one replica fails the factor in the published report and names the
// replica, although the first instance passes.
func TestFetchVerifiedReplicaFailure(t *testing.T) {
	s := newMinimalServer()
	defer s.Close()
	s.cfg.Offline = true
	s.verifyQuote = func(_ context.Context, quote string) *attestation.TDXVerifyResult {
		if quote == "replica-quote" {
			return &attestation.TDXVerifyResult{ParseErr: errors.New("quote does not parse")}
		}
		return &attestation.TDXVerifyResult{}
	}
	newRaw := func() *attestation.RawAttestation {
		return &attestation.RawAttestation{IntelQuote: "first-quote", ModelInstanceID: "19ae"}
	}
	verify := func(raw *attestation.RawAttestation) *attestation.VerificationReport {
		t.Helper()
		prov := &provider.Provider{Name: "nearcloud", SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
			Attester: &mockAttesterWithRaw{raw: raw}}
		report, _, _, err := s.fetchVerified(t.Context(), prov, "m", func(string, error) {})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}

	alone := verify(newRaw())
	raw := newRaw()
	raw.Replicas = []*attestation.RawAttestation{{IntelQuote: "replica-quote", ModelInstanceID: "cc79"}}
	merged := verify(raw)

	if got := merged.Metadata["instances"]; got != "2 (19ae, cc79)" {
		t.Errorf("instances = %q", got)
	}
	var replicaFailures int
	for i, f := range merged.Factors {
		if f.Status != attestation.Fail || !strings.HasPrefix(f.Detail, "instance cc79: ") {
			continue
		}
		replicaFailures++
		if alone.Factors[i].Status == attestation.Fail {
			t.Errorf("factor %s failed without the replica", f.Name)
		}
	}
	if replicaFailures == 0 {
		t.Fatalf("no factor names the failing replica: %+v", merged.Factors)
	}
	if merged.Failed <= alone.Failed {
		t.Errorf("failed = %d, want more than %d", merged.Failed, alone.Failed)
	}
}

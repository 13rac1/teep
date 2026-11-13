package verify

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
)

// teep verify checks the gateway quote that the instances share once.
func TestMergeReplicasGatewayOnce(t *testing.T) {
	calls := make(map[string]int)
	ev := &evidenceVerifier{
		opts: &Options{ProviderName: "nearcloud", ModelName: "m", Offline: true, Config: &config.Config{},
			Provider: &config.Provider{Name: "nearcloud", E2EE: true}},
		client: &http.Client{},
		tdx: func(_ context.Context, quote string) *attestation.TDXVerifyResult {
			calls[quote]++
			return &attestation.TDXVerifyResult{}
		},
		supplyChain: attestation.NewSupplyChainMemo(),
	}
	instance := func(quote, id string) *attestation.RawAttestation {
		return &attestation.RawAttestation{IntelQuote: quote, ModelInstanceID: id,
			GatewayIntelQuote: "gateway-quote", GatewayNonceHex: "n", GatewayAppCompose: "c"}
	}
	raw := instance("quote-a", "19ae")
	raw.Replicas = []*attestation.RawAttestation{instance("quote-b", "a8a2"), instance("quote-c", "cc79")}
	noE2EE := func() *attestation.E2EETestResult { return nil }
	first, _, err := ev.report(t.Context(), raw, noE2EE)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ev.mergeReplicas(t.Context(), raw, first, attestation.AdmissionTime{}, nil); err != nil {
		t.Fatal(err)
	}
	for quote, want := range map[string]int{"gateway-quote": 1, "quote-a": 1, "quote-b": 1, "quote-c": 1} {
		if calls[quote] != want {
			t.Errorf("%s verified %d times, want %d", quote, calls[quote], want)
		}
	}
}

// teep verify checks every instance of a NEAR cloud model: a quote that
// fails on one replica fails the factor in the report and names the replica.
func TestMergeReplicasReplicaFailure(t *testing.T) {
	ev := &evidenceVerifier{
		opts: &Options{ProviderName: "nearcloud", ModelName: "m", Offline: true, Config: &config.Config{},
			Provider: &config.Provider{Name: "nearcloud", E2EE: true}},
		client: &http.Client{},
		tdx: func(_ context.Context, quote string) *attestation.TDXVerifyResult {
			if quote == "replica-quote" {
				return &attestation.TDXVerifyResult{ParseErr: errors.New("quote does not parse")}
			}
			return &attestation.TDXVerifyResult{}
		},
	}
	noE2EE := func() *attestation.E2EETestResult { return nil }
	raw := &attestation.RawAttestation{IntelQuote: "first-quote", ModelInstanceID: "19ae"}
	alone, _, err := ev.report(t.Context(), raw, noE2EE)
	if err != nil {
		t.Fatal(err)
	}
	raw.Replicas = []*attestation.RawAttestation{{IntelQuote: "replica-quote", ModelInstanceID: "cc79"}}
	first, _, err := ev.report(t.Context(), raw, noE2EE)
	if err != nil {
		t.Fatal(err)
	}
	merged, _, err := ev.mergeReplicas(t.Context(), raw, first, attestation.AdmissionTime{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := merged.Metadata["instances"]; got != "2 (19ae, cc79)" {
		t.Errorf("instances = %q", got)
	}
	var replicaFailures int
	for i, f := range merged.Factors {
		if f.Status == attestation.Fail && strings.HasPrefix(f.Detail, "instance cc79: ") {
			replicaFailures++
			if alone.Factors[i].Status == attestation.Fail {
				t.Errorf("factor %s failed without the replica", f.Name)
			}
		}
	}
	if replicaFailures == 0 {
		t.Fatalf("no factor names the failing replica: %+v", merged.Factors)
	}
}

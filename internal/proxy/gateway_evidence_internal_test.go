package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

// The proxy and the verify command assemble reports through separate code
// paths. A gateway provider carries its quote in the gateway fields, so the
// proxy needs its own gateway verifier: without one it verifies no quote at
// all, and the core factors it does emit report absent evidence, which policy
// is allowed to excuse.
//
// SEE: TestBuildReport_GatewayEvidenceNeverVerified for the report-level
// invariant that catches the same fault from the other side.
func TestFetchAndVerify_VerifiesGatewayEvidence(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{}
	s.sevVerifier = func(_ context.Context, report []byte) *attestation.SEVVerifyResult {
		if len(report) == 0 {
			t.Error("SEV verifier called with no report bytes")
		}
		return &attestation.SEVVerifyResult{Measurement: make([]byte, 48)}
	}

	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		BackendFormat:         attestation.FormatTinfoil,
		Nonce:                 nonce.Hex(),
		NonceSource:           "client",
		GatewaySEVReportBytes: []byte("router-quote-bytes"),
		GatewayNonceHex:       nonce.Hex(),
	}
	prov := &provider.Provider{
		Name:              "tinfoil_v3_cloud",
		Attester:          &mockAttesterWithRaw{raw: raw},
		SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
		// Reaches the Tinfoil supply chain path, which compares the signed
		// reference values against the report that describes the enclave the
		// document came from. For a gateway provider that is the gateway
		// report, and choosing the core one instead fails every measurement
		// factor. SEE: attestation.SupplyChainSEVResult.
		SigstoreRepoForModel: func(string) string { return "tinfoilsh/confidential-model-router" },
	}

	report, gotRaw := s.fetchAndVerify(context.Background(), prov, "test-model")
	if report == nil || gotRaw == nil {
		t.Fatal("fetchAndVerify returned no report")
	}

	// The gateway tier exists only when a verification result was produced.
	var sawGatewayFactor bool
	for _, f := range report.Factors {
		if f.Name == attestation.FactorEvidenceVerified {
			t.Fatalf("gateway evidence was never verified: %s", f.Detail)
		}
		if f.Tier == attestation.TierGateway {
			sawGatewayFactor = true
		}
	}
	if !sawGatewayFactor {
		t.Error("report has no gateway factors; the proxy did not verify the gateway quote")
	}
}

// The supply chain comparison must read the same report the gateway verifier
// produced. Passing the core result instead leaves it nil for a gateway
// provider, and every measurement factor fails with "no parseable TDX or
// SEV-SNP result" — blocking a provider teep could in fact verify.
func TestFetchAndVerify_GatewaySuppliesSupplyChainResult(t *testing.T) {
	var gotReportBytes []byte
	s := newMinimalServer()
	s.cfg = &config.Config{Offline: true}
	s.sevVerifier = func(_ context.Context, report []byte) *attestation.SEVVerifyResult {
		gotReportBytes = report
		return &attestation.SEVVerifyResult{Measurement: make([]byte, 48)}
	}

	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		BackendFormat:         attestation.FormatTinfoil,
		Nonce:                 nonce.Hex(),
		NonceSource:           "client",
		GatewaySEVReportBytes: []byte("router-quote-bytes"),
		GatewayNonceHex:       nonce.Hex(),
	}
	prov := &provider.Provider{
		Name:                 "tinfoil_v3_cloud",
		Attester:             &mockAttesterWithRaw{raw: raw},
		SupplyChainPolicy:    attestation.NoSupplyChainPolicy(),
		SigstoreRepoForModel: func(string) string { return "tinfoilsh/confidential-model-router" },
	}

	report, _ := s.fetchAndVerify(context.Background(), prov, "test-model")
	if report == nil {
		t.Fatal("fetchAndVerify returned no report")
	}
	if string(gotReportBytes) != "router-quote-bytes" {
		t.Errorf("SEV verifier saw %q, want the gateway report", gotReportBytes)
	}

	// Offline, so the Sigstore fetch cannot run and the measurement factors are
	// excused. What must not appear is the "no parseable result" detail, which
	// says the supply chain was handed the wrong report entirely.
	for _, f := range report.Factors {
		if strings.Contains(f.Detail, "no parseable TDX or SEV-SNP result") {
			t.Errorf("factor %s was given the core report instead of the gateway report: %s", f.Name, f.Detail)
		}
	}
}

// E2EE for a gateway provider is authorised by the gateway REPORTDATA. Gating
// it on the core factor leaves prov.E2EE true and the gate permanently false,
// so buildUpstreamBody refuses every request and the provider serves nothing.
// The live proxy test that covers this needs TINFOIL_API_KEY and is skipped in
// CI, so the decision is asserted here without a network.
func TestFetchAndVerify_GatewayProviderActivatesE2EE(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{Offline: true}
	s.sevVerifier = func(_ context.Context, _ []byte) *attestation.SEVVerifyResult {
		return &attestation.SEVVerifyResult{Measurement: make([]byte, 48)}
	}

	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		BackendFormat:         attestation.FormatTinfoil,
		Nonce:                 nonce.Hex(),
		NonceSource:           "client",
		GatewaySEVReportBytes: []byte("router-quote-bytes"),
		GatewayNonceHex:       nonce.Hex(),
	}
	prov := &provider.Provider{
		Name:                  "tinfoil_v3_cloud",
		E2EE:                  true,
		E2EEKeyBoundByGateway: true,
		Attester:              &mockAttesterWithRaw{raw: raw},
		SupplyChainPolicy:     attestation.NoSupplyChainPolicy(),
		SigstoreRepoForModel:  func(string) string { return "tinfoilsh/confidential-model-router" },
	}

	report, _ := s.fetchAndVerify(context.Background(), prov, "test-model")
	if report == nil {
		t.Fatal("fetchAndVerify returned no report")
	}
	if report.E2EEBindingFactor != attestation.FactorGWReportData {
		t.Errorf("E2EE reads %q, want %q: the core factor never passes for a gateway provider, so every request is refused",
			report.E2EEBindingFactor, attestation.FactorGWReportData)
	}
}

// fromConfig owns the declaration, so the wiring is asserted where it is set.
func TestFromConfig_TinfoilCloudBindsE2EEToGateway(t *testing.T) {
	cp := &config.Provider{Name: "tinfoil_v3_cloud", BaseURL: "https://inference.tinfoil.sh", APIKey: "test-key"}
	p, err := fromConfig(cp, true, attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{})
	if err != nil {
		t.Fatalf("fromConfig: %v", err)
	}
	if !p.E2EEKeyBoundByGateway {
		t.Error("tinfoil_v3_cloud does not bind E2EE to the gateway; the core factor never passes and E2EE stays off")
	}
}

// nearcloud carries its gateway quote in GatewayIntelQuote. The proxy must run
// a TDX gateway verifier for it, not only the SEV one: unverifiedEvidence
// fails closed on evidence supplied without a result, and that factor is not
// in KnownFactors, so no allow_fail list can excuse it.
func TestFetchAndVerify_VerifiesGatewayTDXEvidence(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{Offline: true}
	s.verifyQuote = attestation.NewTDXVerifier(true, nil, time.Time{})

	nonce := attestation.NewNonce()
	raw := &attestation.RawAttestation{
		Nonce:             nonce.Hex(),
		NonceSource:       "client",
		GatewayIntelQuote: "not-a-real-tdx-quote",
	}
	prov := &provider.Provider{
		Name:              "nearcloud",
		Attester:          &mockAttesterWithRaw{raw: raw},
		SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
	}

	report, _ := s.fetchAndVerify(context.Background(), prov, "test-model")
	if report == nil {
		t.Fatal("fetchAndVerify returned no report")
	}
	for _, f := range report.Factors {
		if f.Name == attestation.FactorEvidenceVerified {
			t.Fatalf("gateway TDX evidence was never verified: %s", f.Detail)
		}
	}
}

func TestFetchAndVerify_PreservesGatewayEventLog(t *testing.T) {
	s := newMinimalServer()
	s.cfg = &config.Config{Offline: true}
	entries := []attestation.EventLogEntry{{IMR: 0, Digest: strings.Repeat("ab", 48)}}
	rtmrs, err := attestation.ReplayEventLog(entries)
	if err != nil {
		t.Fatal(err)
	}
	s.verifyQuote = func(context.Context, string) *attestation.TDXVerifyResult {
		return &attestation.TDXVerifyResult{RTMRs: rtmrs}
	}
	prov := &provider.Provider{
		Name: "nearcloud",
		Attester: &mockAttesterWithRaw{raw: &attestation.RawAttestation{
			GatewayIntelQuote: "gateway-quote",
			GatewayEventLog:   entries,
		}},
		SupplyChainPolicy: attestation.NoSupplyChainPolicy(),
	}
	report, _ := s.fetchAndVerify(context.Background(), prov, "test-model")
	if report == nil {
		t.Fatal("missing report")
	}
	for _, factor := range report.Factors {
		if factor.Name == attestation.FactorGWEventLogIntegrity {
			if factor.Status != attestation.Pass {
				t.Fatalf("gateway event log: %s: %s", factor.Status, factor.Detail)
			}
			return
		}
	}
	t.Fatal("missing gateway event log factor")
}

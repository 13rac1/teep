package proxy

import (
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/venice"
)

// Phala Cloud and NanoGPT forward the private-ai-gateway's ACI/1
// attestation: the proxy verifies the gateway quote with the REPORTDATA
// verifier of the route (the §3.2 statement for Phala Cloud's canonical
// report, keccak256 of the signing key for NanoGPT's compatibility route)
// and checks the gateway images, as teep verify does.
func TestFromConfigGatewayACIProviders(t *testing.T) {
	for _, tc := range []struct {
		name, baseURL string
		gateway       provider.ReportDataVerifier
	}{
		{"phalacloud", "https://tee.redpill.ai", aci.StatementReportDataVerifier{}},
		{"nanogpt", "https://nano-gpt.com/api", venice.ReportDataVerifier{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{
				tc.name: {Name: tc.name, BaseURL: tc.baseURL, APIKey: "test-key"},
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			prov := server.providers[tc.name]
			if prov.GatewayReportDataVerifier != tc.gateway {
				t.Fatalf("GatewayReportDataVerifier = %#v, want %#v", prov.GatewayReportDataVerifier, tc.gateway)
			}
			if prov.SupplyChainPolicy == nil || !prov.SupplyChainPolicy.AllowedInGateway("ghcr.io/dstack-tee/dstack-ingress") {
				t.Fatal("SupplyChainPolicy does not list the gateway images")
			}
			if _, ok := prov.Encryptor.(*aci.E2EE); !ok || prov.Preparer == nil {
				t.Fatalf("Encryptor = %T, Preparer = %T; want the E2EE v2 encryptor and a preparer", prov.Encryptor, prov.Preparer)
			}
		})
	}
}

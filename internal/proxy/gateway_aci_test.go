package proxy

import (
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/venice"
)

// Phala Cloud and NanoGPT forward the private-ai-gateway's ACI/1
// attestation: the proxy verifies its gateway quote with the gateway
// REPORTDATA verifier and checks the gateway images, as teep verify does.
func TestFromConfigGatewayACIProviders(t *testing.T) {
	for _, tc := range []struct{ name, baseURL string }{
		{"phalacloud", "https://tee.redpill.ai"},
		{"nanogpt", "https://nano-gpt.com/api"},
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
			if _, ok := prov.GatewayReportDataVerifier.(venice.ReportDataVerifier); !ok {
				t.Fatalf("GatewayReportDataVerifier = %#v, want venice.ReportDataVerifier", prov.GatewayReportDataVerifier)
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

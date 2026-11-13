package proxy

import (
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/venice"
)

// Phala Cloud answers with the private-ai-gateway's ACI/1 attestation: the
// proxy verifies its gateway quote with the gateway REPORTDATA verifier and
// checks the gateway images, as teep verify does.
func TestFromConfigPhalaCloudACI(t *testing.T) {
	server, err := New(&config.Config{Offline: true, Providers: map[string]*config.Provider{
		"phalacloud": {Name: "phalacloud", BaseURL: "https://tee.redpill.ai", APIKey: "test-key"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	prov := server.providers["phalacloud"]
	if _, ok := prov.GatewayReportDataVerifier.(venice.ReportDataVerifier); !ok {
		t.Fatalf("GatewayReportDataVerifier = %#v, want venice.ReportDataVerifier", prov.GatewayReportDataVerifier)
	}
	if prov.SupplyChainPolicy == nil || !prov.SupplyChainPolicy.AllowedInGateway("ghcr.io/dstack-tee/dstack-ingress") {
		t.Fatal("SupplyChainPolicy does not list the gateway images")
	}
}

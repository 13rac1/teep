package phalacloud_test

import (
	"context"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/phalacloud"
)

// Phala Cloud answers with the ACI/1 gateway variant of the private-ai-gateway;
// ParseAttestationResponse parses it with the shared ACI/1 parser.
func TestParseAttestationResponseACI(t *testing.T) {
	body, err := os.ReadFile("../aci/testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := phalacloud.ParseAttestationResponse(context.Background(), body)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.BackendFormat != attestation.FormatACI1 || !raw.ACIGatewayVariant || raw.GatewayIntelQuote == "" {
		t.Fatalf("format=%q gateway variant=%v gateway quote=%d", raw.BackendFormat, raw.ACIGatewayVariant, len(raw.GatewayIntelQuote))
	}
}

// The Phala Cloud policy lists the gateway images and validates.
func TestSupplyChainPolicyGatewayImages(t *testing.T) {
	p := phalacloud.SupplyChainPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if p.IsNoSupplyChainSurface() || !p.HasGatewayImages() {
		t.Fatal("Phala Cloud policy has no gateway images")
	}
	for _, repo := range []string{"ghcr.io/dstack-tee/dstack-ingress", "ghcr.io/edgelesssys/privatemode/privatemode-proxy"} {
		if !p.AllowedInGateway(repo) || p.AllowedInModel(repo) {
			t.Errorf("%s: gateway=%v model=%v, want gateway tier only", repo, p.AllowedInGateway(repo), p.AllowedInModel(repo))
		}
	}
}

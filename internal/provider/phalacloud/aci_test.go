package phalacloud_test

import (
	"context"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/phalacloud"
)

// Phala Cloud verifies the canonical ACI/1 report of /v1/aci/attestation;
// ParseAttestationResponse parses it with the canonical parser.
func TestParseAttestationResponseACI(t *testing.T) {
	body, err := os.ReadFile("../aci/testdata/canonical_report.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := phalacloud.ParseAttestationResponse(context.Background(), body)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.BackendFormat != attestation.FormatACI1 || !raw.ACICanonicalReport || raw.GatewayIntelQuote == "" {
		t.Fatalf("format=%q canonical=%v gateway quote=%d", raw.BackendFormat, raw.ACICanonicalReport, len(raw.GatewayIntelQuote))
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

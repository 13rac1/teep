package nanogpt_test

import (
	"context"
	"os"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nanogpt"
)

// NanoGPT forwards the ACI/1 gateway variant of the private-ai-gateway;
// ParseAttestationResponse parses it with the shared ACI/1 parser.
func TestParseAttestationResponseACI(t *testing.T) {
	body, err := os.ReadFile("../aci/testdata/gateway_variant.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nanogpt.ParseAttestationResponse(context.Background(), body)
	if err != nil {
		t.Fatalf("ParseAttestationResponse: %v", err)
	}
	if raw.BackendFormat != attestation.FormatACI1 || !raw.ACIGatewayVariant || raw.GatewayIntelQuote == "" {
		t.Fatalf("format=%q gateway variant=%v gateway quote=%d", raw.BackendFormat, raw.ACIGatewayVariant, len(raw.GatewayIntelQuote))
	}
}

// The NanoGPT policy keeps the dstack images in the model tier and adds the
// gateway images in the gateway tier.
func TestSupplyChainPolicyGatewayImages(t *testing.T) {
	p := nanogpt.SupplyChainPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !p.HasGatewayImages() {
		t.Fatal("NanoGPT policy has no gateway images")
	}
	for _, repo := range []string{"ghcr.io/dstack-tee/dstack-ingress", "ghcr.io/edgelesssys/privatemode/privatemode-proxy"} {
		if !p.AllowedInGateway(repo) || p.AllowedInModel(repo) {
			t.Errorf("%s: gateway=%v model=%v, want gateway tier only", repo, p.AllowedInGateway(repo), p.AllowedInModel(repo))
		}
	}
	if !p.AllowedInModel("vllm/vllm-openai") || p.AllowedInGateway("vllm/vllm-openai") {
		t.Error("vllm/vllm-openai must stay model tier only")
	}
}

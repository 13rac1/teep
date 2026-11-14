package nearcloud_test

import (
	"slices"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := nearcloud.DefaultMeasurementPolicy()

	if len(p.MRSeamAllow) == 0 {
		t.Error("MRSeamAllow should not be empty")
	}
	for i := range 3 {
		if len(p.RTMRAllow[i]) == 0 {
			t.Errorf("RTMRAllow[%d] should not be empty", i)
		}
	}
	t.Logf("MRSeamAllow: %d entries, RTMR0: %d, RTMR1: %d, RTMR2: %d",
		len(p.MRSeamAllow), len(p.RTMRAllow[0]), len(p.RTMRAllow[1]), len(p.RTMRAllow[2]))
}

func TestDefaultGatewayMeasurementPolicy(t *testing.T) {
	p := nearcloud.DefaultGatewayMeasurementPolicy()

	if len(p.MRSeamAllow) == 0 {
		t.Error("gateway MRSeamAllow should not be empty")
	}
	for i := range 3 {
		if len(p.RTMRAllow[i]) == 0 {
			t.Errorf("gateway RTMRAllow[%d] should not be empty", i)
		}
	}
}

func TestSupplyChainPolicy(t *testing.T) {
	p := nearcloud.SupplyChainPolicy()
	if p == nil {
		t.Fatal("SupplyChainPolicy should not be nil")
	}
	if len(p.Images) == 0 {
		t.Fatal("SupplyChainPolicy should have images")
	}

	// nearcloud has gateway-tier images.
	hasGateway := false
	for _, img := range p.Images {
		if img.GatewayTier {
			hasGateway = true
			break
		}
	}
	if !hasGateway {
		t.Error("nearcloud SupplyChainPolicy should include gateway-tier images")
	}
	t.Logf("SupplyChainPolicy: %d images", len(p.Images))
}

func TestSupplyChainPolicyTrustsOpenTelemetrySigner(t *testing.T) {
	p := nearcloud.SupplyChainPolicy()
	img := p.Lookup("otel/opentelemetry-collector-contrib")
	if img == nil {
		t.Fatal("OpenTelemetry collector component missing from policy")
	}
	if !img.ModelTier || !img.GatewayTier {
		t.Fatalf("OpenTelemetry component tiers: model=%v gateway=%v, want both", img.ModelTier, img.GatewayTier)
	}
	if img.Provenance != attestation.SigstorePresent {
		t.Fatalf("OpenTelemetry provenance = %v, want SigstorePresent", img.Provenance)
	}
	const wantFingerprint = "a8bd282038915eaf2ca9ac7d4cc2605ce6e7ae8aed5b19b06370e285f8a9d72e"
	if img.KeyFingerprint != wantFingerprint {
		t.Fatalf("OpenTelemetry key fingerprint = %q, want %q", img.KeyFingerprint, wantFingerprint)
	}
	if !p.TrustedProviderSigner(img) {
		t.Fatal("OpenTelemetry signer should be trusted provider-wide")
	}
}

func TestSupplyChainPolicyTrustsAlpineSigner(t *testing.T) {
	p := nearcloud.SupplyChainPolicy()
	img := p.Lookup("alpine")
	if img == nil {
		t.Fatal("alpine component missing from policy")
	}
	if img.ModelTier || !img.GatewayTier {
		t.Fatalf("alpine component tiers: model=%v gateway=%v, want gateway only", img.ModelTier, img.GatewayTier)
	}
	if img.Provenance != attestation.FulcioSigned {
		t.Fatalf("alpine provenance = %v, want FulcioSigned", img.Provenance)
	}
	for _, wantIdentity := range []string{
		"https://github.com/docker/github-builder-experimental/.github/workflows/bake.yml@refs/heads/build-distributed",
		"https://github.com/crazy-max/docker-github-builder/.github/workflows/bake.yml@refs/heads/main",
	} {
		if !slices.Contains(img.OIDCIdentities, wantIdentity) {
			t.Fatalf("alpine OIDC identities = %v, missing %q", img.OIDCIdentities, wantIdentity)
		}
	}
	if !p.TrustedProviderSigner(img) {
		t.Fatal("alpine signer should be trusted provider-wide")
	}
}

// NEAR AI model CVMs served these values in live quotes from 2026-11-04 on
// (os_image_hash 91fd5d69...).
func TestDefaultMeasurementPolicyAcceptsNEARAIModelOS2026_11(t *testing.T) {
	p := nearcloud.DefaultMeasurementPolicy()
	for i, v := range map[int]string{
		1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
		2: "bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71",
	} {
		if _, ok := p.RTMRAllow[i][v]; !ok {
			t.Errorf("RTMRAllow[%d] lacks %s...", i, v[:16])
		}
	}
}

// The NEAR AI cloud gateway served these values in live quotes from 2026-11-04 on
// (os_image_hash 8db40cb2...).
func TestDefaultGatewayMeasurementPolicyAcceptsNEARAIGatewayOS2026_11(t *testing.T) {
	p := nearcloud.DefaultGatewayMeasurementPolicy()
	if _, ok := p.MRTDAllow["7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173"]; !ok {
		t.Error("gateway MRTDAllow lacks 7fe60787...")
	}
	for i, v := range map[int]string{
		0: "d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211",
		1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
		2: "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
	} {
		if _, ok := p.RTMRAllow[i][v]; !ok {
			t.Errorf("gateway RTMRAllow[%d] lacks %s...", i, v[:16])
		}
	}
}

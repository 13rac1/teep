package neardirect_test

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := neardirect.DefaultMeasurementPolicy()

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

func TestSupplyChainPolicy(t *testing.T) {
	p := neardirect.SupplyChainPolicy()
	if p == nil {
		t.Fatal("SupplyChainPolicy should not be nil")
	}
	if len(p.Images) == 0 {
		t.Fatal("SupplyChainPolicy should have images")
	}

	// All neardirect images should be model-tier.
	for _, img := range p.Images {
		if !img.ModelTier {
			t.Errorf("image %q should be model-tier", img.Repo)
		}
	}
	t.Logf("SupplyChainPolicy: %d images", len(p.Images))
}

func TestSupplyChainPolicyTrustsOpenTelemetrySigner(t *testing.T) {
	p := neardirect.SupplyChainPolicy()
	img := p.Lookup("otel/opentelemetry-collector-contrib")
	if img == nil {
		t.Fatal("OpenTelemetry collector component missing from policy")
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

func TestSupplyChainPolicyDoesNotIncludeAlpine(t *testing.T) {
	p := neardirect.SupplyChainPolicy()
	if img := p.Lookup("alpine"); img != nil {
		t.Fatalf("neardirect should not include alpine, got %+v", *img)
	}
}

// NEAR AI model CVMs served these values in live quotes from 2026-11-04 on
// (os_image_hash 91fd5d69...).
func TestDefaultMeasurementPolicyAcceptsNEARAIModelOS2026_11(t *testing.T) {
	p := neardirect.DefaultMeasurementPolicy()
	for i, v := range map[int]string{
		1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
		2: "bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71",
	} {
		if _, ok := p.RTMRAllow[i][v]; !ok {
			t.Errorf("RTMRAllow[%d] lacks %s...", i, v[:16])
		}
	}
}

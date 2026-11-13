package aci

import (
	"slices"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

// The gateway image list names the images of the deployed gateway compose,
// gateway tier only, compose-pinned; the earlier dstacktee names are gone.
func TestGatewayImages(t *testing.T) {
	images := GatewayImages()
	repos := make([]string, 0, len(images))
	for _, img := range images {
		repos = append(repos, img.Repo)
		if !img.GatewayTier || img.ModelTier || img.Provenance != attestation.ComposeBindingOnly {
			t.Errorf("%s: gateway=%v model=%v provenance=%v, want compose-pinned gateway tier", img.Repo, img.GatewayTier, img.ModelTier, img.Provenance)
		}
	}
	want := []string{
		"ghcr.io/dstack-tee/dstack-ingress",
		"ghcr.io/redpill-ai/private-ai-launcher",
		"ghcr.io/dstack-tee/dstack-verifier",
		"ghcr.io/edgelesssys/privatemode/privatemode-proxy",
		"prom/node-exporter",
	}
	if !slices.Equal(repos, want) {
		t.Fatalf("gateway images = %v, want %v", repos, want)
	}
	// Each call returns a new list.
	images[0].Repo = "changed"
	if GatewayImages()[0].Repo == "changed" {
		t.Fatal("GatewayImages returned a shared list")
	}
	if GatewayMeasurementPolicy().MRSeamAllow == nil {
		t.Fatal("gateway measurement policy has no MRSEAM allowlist")
	}
}

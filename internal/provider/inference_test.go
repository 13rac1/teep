package provider_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/tlsct"
)

func TestPrepareInferenceDeadlinePrecedesEncryption(t *testing.T) {
	route, err := provider.NewResolvedRoute("https://cloud-api.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := tlsct.InferenceContext(t.Context(), time.Now().Add(-time.Second), true)
	defer cancel()
	prov := &provider.Provider{E2EE: true, Encryptor: neardirect.NewE2EE()}
	req, _, err := provider.PrepareInference(ctx, prov, route, &provider.InferenceInput{SigningKey: "invalid"})
	if req != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired attempt: request=%v error=%v", req, err)
	}
}

func TestPrepareInferenceMissingMaterial(t *testing.T) {
	route, err := provider.NewResolvedRoute("https://cloud-api.near.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, prov := range []*provider.Provider{{E2EE: true}, {E2EE: true, Encryptor: neardirect.NewE2EE()}} {
		req, encrypted, err := provider.PrepareInference(t.Context(), prov, route, &provider.InferenceInput{})
		if err == nil || req != nil || encrypted.Session != nil || encrypted.EHBP != nil {
			t.Fatal("missing encryption material accepted")
		}
	}
}

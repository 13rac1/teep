package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/tlsct"
)

func TestReverifyRejectsMissingCapturedTLSPeer(t *testing.T) {
	for name, fixture := range map[string]string{
		"nearcloud":  "nearcloud_gateway",
		"neardirect": "neardirect_near",
	} {
		t.Run(name, func(t *testing.T) {
			manifest, entries, err := capture.Load(filepath.Join("..", "..", "internal", "integration", "testdata", "current", fixture))
			if err != nil {
				t.Fatal(err)
			}
			for i := range entries {
				entries[i].PeerSPKIDER = nil
			}
			dir, err := capture.Save(t.TempDir(), &manifest, "", entries)
			if err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(t.TempDir(), "teep.toml")
			contents := fmt.Sprintf("[providers.%s]\napi_key = \"test-key\"\nbase_url = %q\ne2ee = %v\n", name, manifest.NearConfig.Origin, manifest.NearConfig.E2EE)
			if err := os.WriteFile(cfg, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEEP_CONFIG", cfg)
			err = runReverify(context.Background(), dir)
			if err == nil || (!strings.Contains(err.Error(), "attestation TLS binding") && !strings.Contains(err.Error(), "attestation URL or peer")) {
				t.Fatalf("missing peer data was not rejected: %v", err)
			}
		})
	}
}

// A capture whose recorded gateway TLS key is not the key that the gateway
// attestation binds is refused: the recorded peer key of the attestation
// request is replaced with another key.
func TestReverifyRejectsCapturedGatewaySPKIMismatch(t *testing.T) {
	manifest, entries, err := capture.Load(filepath.Join("..", "..", "internal", "integration", "testdata", "current", "nearcloud_gateway"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSPKI, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for i := range entries {
		if strings.Contains(entries[i].URL, "cloud-api.near.ai/v1/attestation/report") {
			entries[i].PeerSPKIDER = otherSPKI
			changed = true
		}
	}
	if !changed {
		t.Fatal("capture has no gateway attestation request")
	}
	fixture, err := capture.Save(t.TempDir(), &manifest, "", entries)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "teep.toml")
	if err := os.WriteFile(cfg, []byte("[providers.nearcloud]\napi_key = \"test-key\"\ne2ee = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEEP_CONFIG", cfg)
	if err := runReverify(t.Context(), fixture); !errors.Is(err, tlsct.ErrSPKIMismatch) {
		t.Fatalf("captured gateway mismatch was not rejected: %v", err)
	}
}

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/capture"
)

func TestReverifyRejectsMissingCapturedTLSPeer(t *testing.T) {
	for name, fixture := range map[string]string{
		"nearcloud":  "nearcloud_z-ai_glm-5.3-flash_20260909_201120",
		"neardirect": "neardirect_z-ai_glm-5.3-flash_20260909_201111",
	} {
		t.Run(name, func(t *testing.T) {
			manifest, entries, err := capture.Load(filepath.Join("..", "..", "internal", "integration", "testdata", fixture))
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

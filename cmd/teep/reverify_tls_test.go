package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReverifyRejectsMissingCapturedTLSPeer(t *testing.T) {
	for name, fixture := range map[string]string{
		"nearcloud":  "nearcloud_qwen_qwen3.5-122b-a10b_20260424_020614",
		"neardirect": "neardirect_qwen_qwen3.5-122b-a10b_20260424_021037",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := filepath.Join(t.TempDir(), "teep.toml")
			contents := fmt.Sprintf("[providers.%s]\napi_key = \"test-key\"\n", name)
			if name == "neardirect" {
				contents += "base_url = \"https://qwen35-122b.completions.near.ai\"\n"
			}
			if err := os.WriteFile(cfg, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEEP_CONFIG", cfg)
			err := runReverify(context.Background(), filepath.Join("..", "..", "internal", "integration", "testdata", fixture))
			if err == nil || !strings.Contains(err.Error(), "attestation TLS binding") {
				t.Fatalf("missing peer data was not rejected: %v", err)
			}
		})
	}
}

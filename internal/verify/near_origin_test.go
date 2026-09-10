package verify

import (
	"testing"

	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

func TestNearCloudCaptureUsesEffectiveOrigin(t *testing.T) {
	for _, origin := range []string{"", "https://api.near.ai", "https://unrelated.example/v1"} {
		for _, enabled := range []bool{false, true} {
			cp := &config.Provider{APIKey: "test", BaseURL: origin, E2EE: enabled}
			recorded, err := nearCaptureConfig("nearcloud", cp)
			if err != nil {
				t.Fatal(err)
			}
			if recorded.Origin != "https://"+nearcloud.GatewayHost() || recorded.E2EE != enabled {
				t.Fatal("capture did not record effective gateway and mode")
			}
			manifest := &capture.Manifest{Provider: "nearcloud", NearConfig: recorded}
			if _, err := validateNearReplay(manifest, cp, nil); err != nil {
				t.Fatal(err)
			}
			recorded.Origin = "https://unrelated.example"
			if _, err := validateNearReplay(manifest, cp, nil); err == nil {
				t.Fatal("accepted changed gateway in capture")
			}
		}
	}
	cp := &config.Provider{BaseURL: "https://API.NEAR.AI:443"}
	value, err := nearCaptureConfig("neardirect", cp)
	if err != nil || value.Origin != "https://api.near.ai" {
		t.Fatal("direct origin normalization changed", err)
	}
	cp.BaseURL = ""
	if _, err := nearCaptureConfig("neardirect", cp); err == nil {
		t.Fatal("direct accepted missing origin")
	}
}

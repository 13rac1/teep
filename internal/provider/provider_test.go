package provider_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider"
)

func TestProvider_Fields(t *testing.T) {
	p := &provider.Provider{
		Name:    "venice",
		BaseURL: "https://api.venice.ai",
		APIKey:  "secret",
		E2EE:    true,
	}

	if p.Name != "venice" {
		t.Errorf("Name = %q, want %q", p.Name, "venice")
	}
	if p.BaseURL != "https://api.venice.ai" {
		t.Errorf("BaseURL = %q, want %q", p.BaseURL, "https://api.venice.ai")
	}
	if !p.E2EE {
		t.Error("E2EE = false, want true")
	}
	// Attester and Preparer are nil when not set — zero value is acceptable.
	if p.Attester != nil {
		t.Error("Attester should be nil by default")
	}
	if p.Preparer != nil {
		t.Error("Preparer should be nil by default")
	}
}

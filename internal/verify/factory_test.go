package verify

import (
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/provider/venice"
)

func TestNewAttester(t *testing.T) {
	cp := &config.Provider{BaseURL: "http://localhost", APIKey: "key"}

	t.Run("venice", func(t *testing.T) {
		a, err := newAttester("venice", cp, false)
		if err != nil {
			t.Fatalf("newAttester(venice): %v", err)
		}
		if _, ok := a.(*venice.Attester); !ok {
			t.Errorf("newAttester(venice) returned %T, want *venice.Attester", a)
		}
	})

	t.Run("neardirect", func(t *testing.T) {
		a, err := newAttester("neardirect", cp, false)
		if err != nil {
			t.Fatalf("newAttester(neardirect): %v", err)
		}
		if _, ok := a.(*neardirect.Attester); !ok {
			t.Errorf("newAttester(neardirect) returned %T, want *neardirect.Attester", a)
		}
	})

	t.Run("nearcloud", func(t *testing.T) {
		a, err := newAttester("nearcloud", cp, false)
		if err != nil {
			t.Fatalf("newAttester(nearcloud): %v", err)
		}
		if _, ok := a.(*nearcloud.Attester); !ok {
			t.Errorf("newAttester(nearcloud) returned %T, want *nearcloud.Attester", a)
		}
	})

	t.Run("nanogpt", func(t *testing.T) {
		a, err := newAttester("nanogpt", cp, false)
		if err != nil {
			t.Fatalf("newAttester(nanogpt): %v", err)
		}
		if _, ok := a.(*nanogpt.Attester); !ok {
			t.Errorf("newAttester(nanogpt) returned %T, want *nanogpt.Attester", a)
		}
	})

	t.Run("phalacloud", func(t *testing.T) {
		a, err := newAttester("phalacloud", cp, false)
		if err != nil {
			t.Fatalf("newAttester(phalacloud): %v", err)
		}
		if _, ok := a.(*phalacloud.Attester); !ok {
			t.Errorf("newAttester(phalacloud) returned %T, want *phalacloud.Attester", a)
		}
	})

	t.Run("chutes", func(t *testing.T) {
		a, err := newAttester("chutes", cp, false)
		if err != nil {
			t.Fatalf("newAttester(chutes): %v", err)
		}
		if _, ok := a.(*chutes.Attester); !ok {
			t.Errorf("newAttester(chutes) returned %T, want *chutes.Attester", a)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		_, err := newAttester("bogus", cp, false)
		t.Logf("newAttester(bogus) error: %v", err)
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
		if !strings.Contains(err.Error(), "bogus") {
			t.Errorf("error should mention the provider name: %v", err)
		}
	})
}

func TestNewReportDataVerifier(t *testing.T) {
	tests := []struct {
		name    string
		wantNil bool
	}{
		{"venice", false},
		{"neardirect", false},
		{"nearcloud", false},
		{"nanogpt", false},
		{"phalacloud", false},
		{"chutes", false},
		{"unknown", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newReportDataVerifier(tc.name)
			if tc.wantNil {
				if got != nil {
					t.Errorf("newReportDataVerifier(%q) = %v, want nil", tc.name, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("newReportDataVerifier(%q) = nil, want non-nil", tc.name)
			}
		})
	}
}

func TestSupplyChainPolicy(t *testing.T) {
	tests := []struct {
		provider string
		wantNil  bool
	}{
		{"venice", false},
		{"neardirect", false},
		{"nearcloud", false},
		{"nanogpt", false},
		{"phalacloud", true},
		{"chutes", true},
		{"unknown", true},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			p := supplyChainPolicy(tc.provider)
			if tc.wantNil {
				if p != nil {
					t.Errorf("supplyChainPolicy(%q) = %v, want nil", tc.provider, p)
				}
				return
			}
			if p == nil {
				t.Fatalf("supplyChainPolicy(%q) = nil, want non-nil", tc.provider)
			}
			if len(p.Images) == 0 {
				t.Errorf("supplyChainPolicy(%q) returned policy with 0 images", tc.provider)
			}
			t.Logf("supplyChainPolicy(%q): %d images", tc.provider, len(p.Images))
		})
	}
}

func TestE2EEEnabledByDefault(t *testing.T) {
	tests := []struct {
		provider string
		want     bool
	}{
		{"venice", true},
		{"nearcloud", true},
		{"chutes", true},
		{"neardirect", true},
		{"nanogpt", false},
		{"unknown", false},
	}
	for _, tc := range tests {
		if got := e2eeEnabledByDefault(tc.provider); got != tc.want {
			t.Errorf("e2eeEnabledByDefault(%q) = %v, want %v", tc.provider, got, tc.want)
		}
	}
}

func TestChatPathForProvider(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"venice", "/api/v1/chat/completions"},
		{"nearcloud", "/v1/chat/completions"},
		{"neardirect", "/v1/chat/completions"},
		{"nanogpt", "/v1/chat/completions"},
		{"chutes", "/v1/chat/completions"},
		{"unknown", ""},
	}
	for _, tc := range tests {
		if got := chatPathForProvider(tc.provider); got != tc.want {
			t.Errorf("chatPathForProvider(%q) = %q, want %q", tc.provider, got, tc.want)
		}
	}
}

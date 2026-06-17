// Package verify implements attestation verification orchestration, extracted
// from cmd/teep for testability. Run is the primary entry point.
package verify

import (
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/provider/tinfoil"
	"github.com/13rac1/teep/internal/provider/venice"
)

// providerEnvVars maps provider names to their API key environment variables.
// Unexported to prevent accidental mutation by importers; use ProviderEnvVar
// to look up individual entries. This satisfies the repo's "no exported
// mutable package-level vars (maps/slices/pointers)" guidance.
var providerEnvVars = map[string]string{
	"venice":            "VENICE_API_KEY",
	"neardirect":        "NEARAI_API_KEY",
	"nearcloud":         "NEARAI_API_KEY",
	"nanogpt":           "NANOGPT_API_KEY",
	"phalacloud":        "PHALA_API_KEY",
	"chutes":            "CHUTES_API_KEY",
	"tinfoil_v3_cloud":  "TINFOIL_API_KEY",
	"tinfoil_v3_direct": "TINFOIL_API_KEY",
}

// ProviderEnvVar returns the API key environment variable name for the given
// provider, and whether the provider is known. Safe for concurrent use;
// callers cannot mutate the underlying map.
func ProviderEnvVar(name string) (string, bool) {
	v, ok := providerEnvVars[name]
	return v, ok
}

// HasProviderEnvVar reports whether the given provider (or any provider with
// the given prefix) has an entry in the env var map. Used by the teeplint
// checker to verify all providers have env var entries.
func HasProviderEnvVar(prov string) bool {
	if _, ok := providerEnvVars[prov]; ok {
		return true
	}
	for k := range providerEnvVars {
		if strings.HasPrefix(k, prov) {
			return true
		}
	}
	return false
}

func newAttester(name string, cp *config.Provider, offline bool) (provider.Attester, error) {
	switch name {
	case "venice":
		return venice.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "neardirect":
		return neardirect.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "nearcloud":
		return nearcloud.NewAttester(cp.APIKey, offline), nil
	case "nanogpt":
		return nanogpt.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "phalacloud":
		return phalacloud.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "chutes":
		return chutes.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		return tinfoil.NewAttester(cp.BaseURL, cp.APIKey, offline), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (supported: venice, neardirect, nearcloud, nanogpt, phalacloud, chutes, tinfoil_v3_cloud, tinfoil_v3_direct)", name)
	}
}

func newReportDataVerifier(name string) provider.ReportDataVerifier {
	switch name {
	case "venice":
		return venice.ReportDataVerifier{}
	case "neardirect", "nearcloud":
		return neardirect.ReportDataVerifier{}
	case "nanogpt":
		// NanoGPT uses the same dstack REPORTDATA binding as Venice.
		return venice.ReportDataVerifier{}
	case "phalacloud":
		return multi.Verifier{
			Verifiers: map[attestation.BackendFormat]provider.ReportDataVerifier{
				attestation.FormatDstack: venice.ReportDataVerifier{},
			},
		}
	case "chutes":
		return chutes.ReportDataVerifier{}
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		return tinfoil.ReportDataVerifier{}
	default:
		return nil
	}
}

func supplyChainPolicy(name string) *attestation.SupplyChainPolicy {
	switch name {
	case "venice":
		return venice.SupplyChainPolicy()
	case "neardirect":
		return neardirect.SupplyChainPolicy()
	case "nearcloud":
		return nearcloud.SupplyChainPolicy()
	case "nanogpt":
		return nanogpt.SupplyChainPolicy()
	case "phalacloud":
		return nil // no supply chain policy yet
	case "chutes":
		return nil // cosign+IMA model, no docker-compose
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		return nil // Sigstore-based, not compose-based
	default:
		return nil
	}
}

// e2eeEnabledByDefault reports whether the named provider has E2EE enabled
// by default in config.go's applyAPIKeyEnv.
func e2eeEnabledByDefault(name string) bool {
	switch name {
	case "venice", "nearcloud", "neardirect", "chutes":
		return true
	default:
		return false
	}
}

// chatPathForProvider returns the upstream chat completions path for the named provider.
func chatPathForProvider(name string) string {
	switch name {
	case "venice":
		return "/api/v1/chat/completions"
	case "nearcloud", "neardirect", "nanogpt":
		return "/v1/chat/completions"
	case "chutes":
		return "/v1/chat/completions"
	case "tinfoil_v3_cloud", "tinfoil_v3_direct":
		return "/v1/chat/completions"
	default:
		return ""
	}
}

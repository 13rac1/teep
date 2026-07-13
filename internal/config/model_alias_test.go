package config

import (
	"strings"
	"testing"
)

func TestLoadTOMLModelAliases(t *testing.T) {
	toml := `
[providers.tinfoil_v3_direct]
api_key = "test-key"
base_url = "https://inference.tinfoil.sh"
e2ee = true

[providers.tinfoil_v3_direct.model_aliases]
"deepseek-ai/DeepSeek-V3.2-Exp" = "deepseek-v3.2-exp"
glm-latest = "glm-5-2"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.ModelAliases) != 2 {
		t.Fatalf("ModelAliases: got %d entries, want 2: %#v", len(cfg.ModelAliases), cfg.ModelAliases)
	}
	ma, ok := cfg.ModelAliases["deepseek-ai/DeepSeek-V3.2-Exp"]
	if !ok {
		t.Fatal(`ModelAliases["deepseek-ai/DeepSeek-V3.2-Exp"] missing`)
	}
	if ma.Provider != "tinfoil_v3_direct" || ma.UpstreamModel != "deepseek-v3.2-exp" {
		t.Fatalf("alias = %#v, want provider=tinfoil_v3_direct upstream=deepseek-v3.2-exp", ma)
	}
	ma2, ok := cfg.ModelAliases["glm-latest"]
	if !ok {
		t.Fatal(`ModelAliases["glm-latest"] missing`)
	}
	if ma2.Provider != "tinfoil_v3_direct" || ma2.UpstreamModel != "glm-5-2" {
		t.Fatalf("alias = %#v, want provider=tinfoil_v3_direct upstream=glm-5-2", ma2)
	}
}

func TestLoadTOMLModelAliases_RejectsColon(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"

[providers.venice.model_aliases]
"bad:alias" = "some-model"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for alias containing ':'")
	}
	if !strings.Contains(err.Error(), "must not contain ':'") {
		t.Fatalf("Load() error = %v, want mention of ':' rejection", err)
	}
}

func TestLoadTOMLModelAliases_RejectsDuplicateAcrossProviders(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"

[providers.venice.model_aliases]
shared-name = "venice-model"

[providers.neardirect]
api_key = "k2"
base_url = "https://api.near.ai"

[providers.neardirect.model_aliases]
shared-name = "neardirect-model"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for duplicate alias across providers")
	}
	if !strings.Contains(err.Error(), "already defined by provider") {
		t.Fatalf("Load() error = %v, want mention of duplicate alias", err)
	}
}

func TestLoadTOMLModelAliases_RejectsProviderNameCollision(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"

[providers.neardirect]
api_key = "k2"
base_url = "https://api.near.ai"

[providers.neardirect.model_aliases]
venice = "some-model"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for alias colliding with provider name")
	}
	if !strings.Contains(err.Error(), "collides with a configured provider name") {
		t.Fatalf("Load() error = %v, want mention of provider-name collision", err)
	}
}

func TestLoadTOMLModelAliases_RejectsEmptyUpstreamModel(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"

[providers.venice.model_aliases]
some-alias = ""
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for alias mapping to empty model name")
	}
	if !strings.Contains(err.Error(), "maps to an empty model name") {
		t.Fatalf("Load() error = %v, want mention of empty model name", err)
	}
}

func TestLoadTOMLModelAliases_RejectsInvalidCharacters(t *testing.T) {
	toml := `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"

[providers.venice.model_aliases]
"bad alias" = "some-model"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want error for alias with disallowed characters")
	}
	if !strings.Contains(err.Error(), "contains characters outside") {
		t.Fatalf("Load() error = %v, want mention of disallowed characters", err)
	}
}

func TestLoadTOMLModelAliases_AllowsSlashInAlias(t *testing.T) {
	// The plan's own motivating example uses a slash-containing upstream
	// model name as the alias itself (e.g. "deepseek-ai/DeepSeek-V3.2-Exp"),
	// so '/' must be accepted even though ':' is rejected.
	toml := `
[providers.tinfoil_v3_direct]
api_key = "k"
base_url = "https://inference.tinfoil.sh"

[providers.tinfoil_v3_direct.model_aliases]
"deepseek-ai/DeepSeek-V3.2-Exp" = "deepseek-v3.2-exp"
`
	path := writeConfigFile(t, toml, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if _, ok := cfg.ModelAliases["deepseek-ai/DeepSeek-V3.2-Exp"]; !ok {
		t.Fatal("expected slash-containing alias to be accepted")
	}
}

func TestLoadTOMLModelAliases_NoAliasesIsEmptyNotNil(t *testing.T) {
	path := writeConfigFile(t, `
[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
`, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.ModelAliases == nil {
		t.Fatal("ModelAliases = nil, want non-nil empty map")
	}
	if len(cfg.ModelAliases) != 0 {
		t.Fatalf("ModelAliases: got %d entries, want 0", len(cfg.ModelAliases))
	}
}

// --- buildModelAliases / validateModelAlias unit tests (no TOML/env needed) ---

func TestBuildModelAliases_DeterministicAcrossRuns(t *testing.T) {
	providers := map[string]ProviderConfig{
		"a": {ModelAliases: map[string]string{"alias-a1": "m1", "alias-a2": "m2"}},
		"b": {ModelAliases: map[string]string{"alias-b1": "m3"}},
	}
	first, err := buildModelAliases(providers)
	if err != nil {
		t.Fatalf("buildModelAliases: %v", err)
	}
	for range 20 {
		got, err := buildModelAliases(providers)
		if err != nil {
			t.Fatalf("buildModelAliases: %v", err)
		}
		if len(got) != len(first) {
			t.Fatalf("buildModelAliases produced %d entries, want %d", len(got), len(first))
		}
		for alias, ma := range first {
			if got[alias] != ma {
				t.Fatalf("buildModelAliases non-deterministic: alias %q = %#v, want %#v", alias, got[alias], ma)
			}
		}
	}
}

func TestBuildModelAliases_RejectsEmptyAlias(t *testing.T) {
	providers := map[string]ProviderConfig{
		"a": {ModelAliases: map[string]string{"": "m1"}},
	}
	if _, err := buildModelAliases(providers); err == nil {
		t.Fatal("buildModelAliases: want error for empty alias")
	}
}

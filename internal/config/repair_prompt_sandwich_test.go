package config

import "testing"

func TestLoadTOMLRepairPromptSandwich_DefaultOff(t *testing.T) {
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
	if cfg.RepairPromptSandwich {
		t.Error("cfg.RepairPromptSandwich = true, want false (default off)")
	}
	if RepairPromptSandwichEnabled("venice", cfg) {
		t.Error("RepairPromptSandwichEnabled(venice) = true, want false (default off, no overrides)")
	}
}

func TestLoadTOMLRepairPromptSandwich_GlobalOn(t *testing.T) {
	path := writeConfigFile(t, `
repair_prompt_sandwich = true

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
	if !cfg.RepairPromptSandwich {
		t.Error("cfg.RepairPromptSandwich = false, want true")
	}
	if !RepairPromptSandwichEnabled("venice", cfg) {
		t.Error("RepairPromptSandwichEnabled(venice) = false, want true (global on, no per-provider override)")
	}
}

func TestLoadTOMLRepairPromptSandwich_PerProviderOverridesGlobalOff(t *testing.T) {
	path := writeConfigFile(t, `
repair_prompt_sandwich = false

[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
repair_prompt_sandwich = true

[providers.neardirect]
api_key = "k2"
base_url = "https://api.near.ai"
`, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !RepairPromptSandwichEnabled("venice", cfg) {
		t.Error("RepairPromptSandwichEnabled(venice) = false, want true (explicit per-provider override)")
	}
	if RepairPromptSandwichEnabled("neardirect", cfg) {
		t.Error("RepairPromptSandwichEnabled(neardirect) = true, want false (inherits global off, no override)")
	}
}

func TestLoadTOMLRepairPromptSandwich_PerProviderExplicitlyOffOverridesGlobalOn(t *testing.T) {
	path := writeConfigFile(t, `
repair_prompt_sandwich = true

[providers.venice]
api_key = "k"
base_url = "https://api.venice.ai"
repair_prompt_sandwich = false
`, 0o600)
	setenv(t, "TEEP_CONFIG", path)
	unsetenv(t, "TEEP_LISTEN_ADDR")
	clearProviderEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if RepairPromptSandwichEnabled("venice", cfg) {
		t.Error("RepairPromptSandwichEnabled(venice) = true, want false (explicit per-provider override to false beats global true)")
	}
}

func TestRepairPromptSandwichEnabled_UnknownProviderUsesGlobal(t *testing.T) {
	cfg := &Config{RepairPromptSandwich: true, ProviderRepairPromptSandwich: map[string]bool{}}
	if !RepairPromptSandwichEnabled("some-provider-not-in-config", cfg) {
		t.Error("RepairPromptSandwichEnabled(unknown provider) = false, want true (falls back to global)")
	}
}

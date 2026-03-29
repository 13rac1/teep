package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"

	"github.com/BurntSushi/toml"
)

// ObservedMeasurements holds TDX measurement values extracted from a
// verification report's metadata. Empty strings mean "not observed".
type ObservedMeasurements struct {
	MRSeam string
	MRTD   string
	RTMR0  string
	RTMR1  string
	RTMR2  string
	RTMR3  string

	// Gateway fields (nearcloud only).
	GatewayMRSeam string
	GatewayMRTD   string
	GatewayRTMR0  string
	GatewayRTMR1  string
	GatewayRTMR2  string
	GatewayRTMR3  string
}

// UpdateConfig reads the TOML config at path, adds the observed measurement
// values to the [providers.<providerName>.policy] section (deduplicating),
// sets warn_measurements = false for that provider, and writes the result
// back. The original file is backed up to path+".bak".
//
// If path is empty or the file does not exist, a new config is created.
func UpdateConfig(path, providerName string, observed *ObservedMeasurements) error {
	var f updateFile
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is from trusted CLI flag or $TEEP_CONFIG
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read config: %w", err)
		}
		if len(data) > 0 {
			if _, err := toml.Decode(string(data), &f); err != nil {
				return fmt.Errorf("parse config: %w", err)
			}
			// Backup original.
			if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
				return fmt.Errorf("backup config: %w", err)
			}
		}
	}

	if f.Providers == nil {
		f.Providers = make(map[string]updateProvider)
	}
	prov := f.Providers[providerName]
	// Populate known defaults for new provider entries so the resulting
	// config is usable without manual editing of base_url / api_key_env.
	if prov.BaseURL == "" {
		if d, ok := knownProviderDefaults[providerName]; ok {
			prov.BaseURL = d.baseURL
			prov.APIKeyEnv = d.keyEnvVar
			prov.E2EE = d.e2ee
		}
	}
	mergeObserved(&prov.Policy, observed)
	prov.Policy.WarnMeasurements = false
	f.Providers[providerName] = prov

	return writeConfig(path, &f)
}

// updateFile mirrors the TOML config structure for update editing.
// Note: toml.Decode into a struct drops unknown keys and all comments;
// the .bak backup preserves the original file for manual recovery.
type updateFile struct {
	Providers     map[string]updateProvider `toml:"providers,omitempty"`
	Policy        updatePolicy              `toml:"policy,omitempty"`
	PoCSigningKey string                    `toml:"poc_signing_key,omitempty"`
}

type updateProvider struct {
	APIKey    string       `toml:"api_key,omitempty"`
	APIKeyEnv string       `toml:"api_key_env,omitempty"`
	BaseURL   string       `toml:"base_url,omitempty"`
	E2EE      bool         `toml:"e2ee,omitempty"`
	Policy    updatePolicy `toml:"policy,omitempty"`
}

type updatePolicy struct {
	Enforce     []string `toml:"enforce,omitempty"`
	MRTDAllow   []string `toml:"mrtd_allow,omitempty"`
	MRSEAMAllow []string `toml:"mrseam_allow,omitempty"`
	RTMR0Allow  []string `toml:"rtmr0_allow,omitempty"`
	RTMR1Allow  []string `toml:"rtmr1_allow,omitempty"`
	RTMR2Allow  []string `toml:"rtmr2_allow,omitempty"`
	RTMR3Allow  []string `toml:"rtmr3_allow,omitempty"`

	GatewayMRTDAllow   []string `toml:"gateway_mrtd_allow,omitempty"`
	GatewayMRSEAMAllow []string `toml:"gateway_mrseam_allow,omitempty"`
	GatewayRTMR0Allow  []string `toml:"gateway_rtmr0_allow,omitempty"`
	GatewayRTMR1Allow  []string `toml:"gateway_rtmr1_allow,omitempty"`
	GatewayRTMR2Allow  []string `toml:"gateway_rtmr2_allow,omitempty"`
	GatewayRTMR3Allow  []string `toml:"gateway_rtmr3_allow,omitempty"`

	WarnMeasurements bool `toml:"warn_measurements,omitempty"`
}

// mergeObserved adds observed values into the provider policy, deduplicating.
func mergeObserved(p *updatePolicy, observed *ObservedMeasurements) {
	p.MRSEAMAllow = addUnique(p.MRSEAMAllow, observed.MRSeam)
	p.MRTDAllow = addUnique(p.MRTDAllow, observed.MRTD)
	p.RTMR0Allow = addUnique(p.RTMR0Allow, observed.RTMR0)
	p.RTMR1Allow = addUnique(p.RTMR1Allow, observed.RTMR1)
	p.RTMR2Allow = addUnique(p.RTMR2Allow, observed.RTMR2)
	p.RTMR3Allow = addUnique(p.RTMR3Allow, observed.RTMR3)

	p.GatewayMRSEAMAllow = addUnique(p.GatewayMRSEAMAllow, observed.GatewayMRSeam)
	p.GatewayMRTDAllow = addUnique(p.GatewayMRTDAllow, observed.GatewayMRTD)
	p.GatewayRTMR0Allow = addUnique(p.GatewayRTMR0Allow, observed.GatewayRTMR0)
	p.GatewayRTMR1Allow = addUnique(p.GatewayRTMR1Allow, observed.GatewayRTMR1)
	p.GatewayRTMR2Allow = addUnique(p.GatewayRTMR2Allow, observed.GatewayRTMR2)
	p.GatewayRTMR3Allow = addUnique(p.GatewayRTMR3Allow, observed.GatewayRTMR3)
}

// addUnique appends val to list if non-empty and not already present.
func addUnique(list []string, val string) []string {
	if val == "" {
		return list
	}
	if slices.Contains(list, val) {
		return list
	}
	list = append(list, val)
	sort.Strings(list)
	return list
}

// knownProviderDefaults provides base_url, api_key_env, and e2ee defaults
// for each known provider, matching the values in config.go applyAPIKeyEnv.
// Used to populate new provider entries created by --update-config.
var knownProviderDefaults = map[string]struct {
	baseURL   string
	keyEnvVar string
	e2ee      bool
}{
	"venice":     {baseURL: "https://api.venice.ai", keyEnvVar: "VENICE_API_KEY", e2ee: true},
	"neardirect": {baseURL: "https://completions.near.ai", keyEnvVar: "NEARAI_API_KEY"},
	"nearcloud":  {baseURL: "https://cloud-api.near.ai", keyEnvVar: "NEARAI_API_KEY", e2ee: true},
	"nanogpt":    {baseURL: "https://nano-gpt.com/api", keyEnvVar: "NANOGPT_API_KEY"},
}

func writeConfig(path string, f *updateFile) error {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(f); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if path == "" {
		_, err := io.Copy(os.Stdout, &buf)
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

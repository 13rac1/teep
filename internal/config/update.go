package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

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
// and writes the result back. If the existing config file is non-empty, its
// original contents are backed up to path+".bak".
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
			// Strict decode: fail closed on unknown keys rather than
			// silently dropping them from the rewritten file. See
			// config.go's loadTOML for the same pattern.
			meta, err := toml.Decode(string(data), &f)
			if err != nil {
				return fmt.Errorf("parse config: %w", err)
			}
			if undecoded := meta.Undecoded(); len(undecoded) > 0 {
				return fmt.Errorf("unknown config keys: %v (refusing to rewrite; update teep or remove the key)", undecoded)
			}

			// Backup original before rewriting.
			if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
				return fmt.Errorf("backup config: %w", err)
			}
			warnIfCommentsPresent(path, data)
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
	f.Providers[providerName] = prov

	return writeConfig(path, &f)
}

// updateFile mirrors the TOML config structure for update editing.
// Note: strict-decoded (see UpdateConfig) so unknown keys refuse the
// update rather than being silently dropped; comments are still lost on
// rewrite (a loud notice is printed and the .bak backup preserves the
// original file for manual recovery).
//
// AllowFail fields use *[]string (not []string+omitempty) so that an
// absent key (nil pointer, omitted on encode) round-trips distinctly from
// an explicitly-empty list (`allow_fail = []`, non-nil pointer to an empty
// slice, emitted verbatim on encode). Collapsing the two via omitempty
// would silently downgrade an explicit "enforce all factors" back to the
// weaker Go defaults on the next rewrite.
type updateFile struct {
	Providers map[string]updateProvider `toml:"providers,omitempty"`
	// MaxConns uses "omitzero" (not "omitempty"): the BurntSushi/toml
	// encoder's "omitempty" only recognizes zero-length arrays/slices/maps/
	// strings, structs-of-zero-values, and bool false — it does NOT treat a
	// zero int as empty (that is what "omitzero" is for). Tagging an int
	// field "omitempty" is a no-op on encode, so an unset max_conns was
	// always rewritten back out as the literal `max_conns = 0`, which then
	// fails strict validation on the next Load() ("max_conns must be a
	// positive integer, got 0"). max_conns has no valid zero value, so
	// "omitzero" (omit when 0) is the correct and sufficient fix.
	MaxConns  int          `toml:"max_conns,omitzero"`
	AllowFail *[]string    `toml:"allow_fail"`
	Policy    updatePolicy `toml:"policy,omitempty"`
}

type updateProvider struct {
	APIKey    string       `toml:"api_key,omitempty"`
	APIKeyEnv string       `toml:"api_key_env,omitempty"`
	BaseURL   string       `toml:"base_url,omitempty"`
	E2EE      bool         `toml:"e2ee,omitempty"`
	AllowFail *[]string    `toml:"allow_fail"`
	Policy    updatePolicy `toml:"policy,omitempty"`
}

type updatePolicy struct {
	AllowFail   *[]string `toml:"allow_fail"`
	MRTDAllow   []string  `toml:"mrtd_allow,omitempty"`
	MRSEAMAllow []string  `toml:"mrseam_allow,omitempty"`
	RTMR0Allow  []string  `toml:"rtmr0_allow,omitempty"`
	RTMR1Allow  []string  `toml:"rtmr1_allow,omitempty"`
	RTMR2Allow  []string  `toml:"rtmr2_allow,omitempty"`
	RTMR3Allow  []string  `toml:"rtmr3_allow,omitempty"`

	GatewayMRTDAllow   []string `toml:"gateway_mrtd_allow,omitempty"`
	GatewayMRSEAMAllow []string `toml:"gateway_mrseam_allow,omitempty"`
	GatewayRTMR0Allow  []string `toml:"gateway_rtmr0_allow,omitempty"`
	GatewayRTMR1Allow  []string `toml:"gateway_rtmr1_allow,omitempty"`
	GatewayRTMR2Allow  []string `toml:"gateway_rtmr2_allow,omitempty"`
	GatewayRTMR3Allow  []string `toml:"gateway_rtmr3_allow,omitempty"`
}

// mergeObserved adds observed values into the provider policy, deduplicating.
func mergeObserved(p *updatePolicy, observed *ObservedMeasurements) {
	p.MRSEAMAllow = addUnique(p.MRSEAMAllow, observed.MRSeam)
	p.MRTDAllow = addUnique(p.MRTDAllow, observed.MRTD)
	p.RTMR0Allow = addUnique(p.RTMR0Allow, observed.RTMR0)
	p.RTMR1Allow = addUnique(p.RTMR1Allow, observed.RTMR1)
	p.RTMR2Allow = addUnique(p.RTMR2Allow, observed.RTMR2)
	// RTMR3 is omitted: it is verified via event log replay and varies
	// across instances, so pinning it in allowlists is overly brittle.

	p.GatewayMRSEAMAllow = addUnique(p.GatewayMRSEAMAllow, observed.GatewayMRSeam)
	p.GatewayMRTDAllow = addUnique(p.GatewayMRTDAllow, observed.GatewayMRTD)
	p.GatewayRTMR0Allow = addUnique(p.GatewayRTMR0Allow, observed.GatewayRTMR0)
	p.GatewayRTMR1Allow = addUnique(p.GatewayRTMR1Allow, observed.GatewayRTMR1)
	p.GatewayRTMR2Allow = addUnique(p.GatewayRTMR2Allow, observed.GatewayRTMR2)
	// Gateway RTMR3 omitted for the same reason as RTMR3.
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
	"neardirect": {baseURL: "https://completions.near.ai", keyEnvVar: "NEARAI_API_KEY", e2ee: true},
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// warnIfCommentsPresent prints a prominent, unmissable notice to stderr when
// the original config file contains comments. --update-config round-trips
// the file through TOML structs, which does not preserve comments; silently
// dropping them would be a surprising loss for a maintenance command. The
// original content (comments included) is always available at path+".bak".
func warnIfCommentsPresent(path string, data []byte) {
	if !containsComment(data) {
		return
	}
	fmt.Fprintf(os.Stderr, "\n"+
		"*** WARNING: %s contains comments.\n"+
		"*** --update-config does NOT preserve comments; they will be\n"+
		"*** dropped from the rewritten file.\n"+
		"*** The original file (with comments) has been saved to %s.\n\n",
		path, path+".bak")
}

// containsComment reports whether data contains a TOML comment: a '#' that
// is not inside a basic ("...") or literal ('...') string, on any line.
func containsComment(data []byte) bool {
	return slices.ContainsFunc(strings.Split(string(data), "\n"), lineHasComment)
}

// lineHasComment reports whether line contains a TOML comment marker,
// tracking basic and literal string state so a '#' inside a quoted value
// (e.g. an API key) is not mistaken for a comment.
func lineHasComment(line string) bool {
	var inBasic, inLiteral bool
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inBasic:
			switch c {
			case '\\':
				i++ // skip escaped character
			case '"':
				inBasic = false
			}
		case inLiteral:
			if c == '\'' {
				inLiteral = false
			}
		case c == '"':
			inBasic = true
		case c == '\'':
			inLiteral = true
		case c == '#':
			return true
		}
	}
	return false
}

// Package config loads and validates teep proxy configuration from an optional
// TOML file and environment variable overrides.
//
// Load order:
//
//  1. Built-in defaults (listen addr 127.0.0.1:8080, default enforced factors).
//  2. TOML file at $TEEP_CONFIG, if set.
//  3. Environment variables (TEEP_LISTEN_ADDR, VENICE_API_KEY, NEARAI_API_KEY).
//
// API keys are never logged; use RedactKey to produce a safe representation.
package config

import (
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/13rac1/teep/internal/attestation"
)

const (
	// DefaultListenAddr is the proxy's default listen address.
	// It deliberately binds only to loopback — never to all interfaces.
	DefaultListenAddr = "127.0.0.1:8080"

	// AttestationTimeout is the HTTP client timeout for attestation fetches.
	AttestationTimeout = 30 * time.Second
)

// DefaultEnforced lists the factor names that block the proxy on failure.
var DefaultEnforced = attestation.DefaultEnforced

// ProviderConfig holds the TOML-parsed configuration for one provider.
// Either APIKey or APIKeyEnv must be set; APIKeyEnv takes precedence if both
// are present. The resolved key is exposed via the Provider struct, not here.
type ProviderConfig struct {
	APIKey    string            `toml:"api_key"`
	APIKeyEnv string            `toml:"api_key_env"`
	BaseURL   string            `toml:"base_url"`
	E2EE      bool              `toml:"e2ee"`
	Models    map[string]string `toml:"models"`
}

// PolicyConfig holds the optional [policy] section from the TOML file.
type PolicyConfig struct {
	Enforce []string `toml:"enforce"`
}

// tomlFile mirrors the top-level structure of the optional TOML config file.
type tomlFile struct {
	Providers map[string]ProviderConfig `toml:"providers"`
	Policy    PolicyConfig              `toml:"policy"`
}

// Provider is a fully resolved provider configuration, ready for use by the
// proxy and attestation verifier. Attester and Preparer are populated in Phase 4.
type Provider struct {
	Name     string
	BaseURL  string
	APIKey   string
	ModelMap map[string]string // client model → upstream model
	E2EE     bool
}

// MapModel translates a client-facing model name to the upstream model name.
// Returns the input unchanged if no mapping exists.
func (p *Provider) MapModel(clientModel string) string {
	if mapped, ok := p.ModelMap[clientModel]; ok {
		return mapped
	}
	return clientModel
}

// Config is the fully resolved runtime configuration for the teep proxy.
type Config struct {
	// ListenAddr is the TCP address the proxy HTTP server binds to.
	ListenAddr string

	// Providers is the map of provider name → resolved provider config.
	Providers map[string]*Provider

	// Enforced is the list of attestation factor names that block the proxy
	// when they fail. Defaults to DefaultEnforced.
	Enforced []string

	// Offline skips external verification calls (Intel PCS collateral,
	// Proof of Cloud registry). Set via --offline flag at runtime.
	Offline bool
}

// Load reads configuration from the optional TOML file (path from $TEEP_CONFIG)
// and applies environment variable overrides. It logs a warning to stderr if
// the listen address is non-loopback or if the config file has insecure
// permissions, but does not return an error for either condition.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr: DefaultListenAddr,
		Providers:  make(map[string]*Provider),
		Enforced:   append([]string(nil), DefaultEnforced...),
	}

	configPath := os.Getenv("TEEP_CONFIG")
	if configPath != "" {
		if err := loadTOML(cfg, configPath); err != nil {
			return nil, fmt.Errorf("loading config file %q: %w", configPath, err)
		}
	}

	applyEnvOverrides(cfg)
	warnNonLoopback(cfg.ListenAddr)
	return cfg, nil
}

// loadTOML parses the TOML file at path and merges its values into cfg.
// It checks file permissions before parsing and logs a warning if the file
// is readable by group or world.
func loadTOML(cfg *Config, path string) error {
	if err := checkFilePermissions(path); err != nil {
		slog.Warn("config file permission check", "err", err)
	}

	var f tomlFile
	if _, err := toml.DecodeFile(path, &f); err != nil {
		return fmt.Errorf("TOML decode: %w", err)
	}

	for name, pc := range f.Providers {
		p := resolveProvider(name, pc)
		cfg.Providers[name] = p
	}

	if len(f.Policy.Enforce) > 0 {
		known := make(map[string]bool, len(attestation.KnownFactors))
		for _, name := range attestation.KnownFactors {
			known[name] = true
		}
		for _, name := range f.Policy.Enforce {
			if !known[name] {
				return fmt.Errorf("unknown enforce factor %q", name)
			}
		}
		cfg.Enforced = f.Policy.Enforce
	}

	return nil
}

// resolveProvider builds a Provider from a ProviderConfig, resolving the API
// key from the env var if APIKeyEnv is set.
func resolveProvider(name string, pc ProviderConfig) *Provider {
	apiKey := pc.APIKey
	if pc.APIKeyEnv != "" {
		if v := os.Getenv(pc.APIKeyEnv); v != "" {
			apiKey = v
		}
	}

	models := make(map[string]string, len(pc.Models))
	maps.Copy(models, pc.Models)

	return &Provider{
		Name:     name,
		BaseURL:  pc.BaseURL,
		APIKey:   apiKey,
		ModelMap: models,
		E2EE:     pc.E2EE,
	}
}

// applyEnvOverrides applies environment variable overrides to cfg.
// TEEP_LISTEN_ADDR overrides the listen address.
// VENICE_API_KEY and NEARAI_API_KEY inject or override provider API keys.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("TEEP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	applyAPIKeyEnv(cfg, "venice", "VENICE_API_KEY", "https://api.venice.ai", true)
	applyAPIKeyEnv(cfg, "nearai", "NEARAI_API_KEY", "https://api.near.ai", false)
}

// applyAPIKeyEnv sets or updates the API key for the named provider from the
// given environment variable. If the provider does not yet exist in cfg and the
// env var is set, a minimal provider entry is created with the given defaults.
func applyAPIKeyEnv(cfg *Config, name, envVar, defaultBaseURL string, defaultE2EE bool) {
	key := os.Getenv(envVar)
	if key == "" {
		return
	}

	p, ok := cfg.Providers[name]
	if !ok {
		p = &Provider{
			Name:     name,
			BaseURL:  defaultBaseURL,
			E2EE:     defaultE2EE,
			ModelMap: make(map[string]string),
		}
		cfg.Providers[name] = p
	}
	p.APIKey = key
}

// checkFilePermissions returns an error if the file at path is group- or
// world-readable (permission bits 0o044 set).
func checkFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o066 != 0 {
		return fmt.Errorf("%q has insecure permissions %04o (group- or world-readable/writable); restrict to 0600", path, mode)
	}
	return nil
}

// warnNonLoopback logs a warning to stderr if addr does not resolve to a
// loopback interface. A misconfigured listen address that binds to all
// interfaces exposes the proxy to the local network or internet.
func warnNonLoopback(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Unparseable address — warn rather than crash; server startup will
		// catch the real error.
		slog.Warn("cannot parse listen address", "addr", addr, "err", err)
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		slog.Warn("listen address is not loopback; proxy is reachable from the network", "addr", addr)
	}
}

// RedactKey returns a redacted representation of an API key safe for logging.
// It shows the first four characters followed by "****". If the key is shorter
// than four characters it is fully replaced with "****".
func RedactKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return key[:4] + "****"
}

// NewAttestationClient returns an *http.Client with a 30-second timeout,
// suitable for fetching attestation data from TEE provider endpoints.
func NewAttestationClient() *http.Client {
	return &http.Client{Timeout: AttestationTimeout}
}

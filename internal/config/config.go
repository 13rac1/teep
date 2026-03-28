// Package config loads and validates teep proxy configuration from an optional
// TOML file and environment variable overrides.
//
// Load order:
//
//  1. Built-in defaults (listen addr 127.0.0.1:8337, default enforced factors).
//  2. TOML file at $TEEP_CONFIG, if set.
//  3. Environment variables (TEEP_LISTEN_ADDR, VENICE_API_KEY, NEARAI_API_KEY, NANOGPT_API_KEY).
//
// API keys are never logged; use RedactKey to produce a safe representation.
package config

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/tlsct"
)

const (
	// DefaultListenAddr is the proxy's default listen address.
	// It deliberately binds only to loopback — never to all interfaces.
	DefaultListenAddr = "127.0.0.1:8337"

	// AttestationTimeout is the HTTP client timeout for attestation fetches.
	AttestationTimeout = 30 * time.Second
)

// DefaultEnforced lists the factor names that block the proxy on failure.
var DefaultEnforced = attestation.DefaultEnforced

// ProviderConfig holds the TOML-parsed configuration for one provider.
// Either APIKey or APIKeyEnv must be set; APIKeyEnv takes precedence if both
// are present. The resolved key is exposed via the Provider struct, not here.
type ProviderConfig struct {
	APIKey    string `toml:"api_key"`
	APIKeyEnv string `toml:"api_key_env"`
	BaseURL   string `toml:"base_url"`
	E2EE      bool   `toml:"e2ee"`
}

// PolicyConfig holds the optional [policy] section from the TOML file.
type PolicyConfig struct {
	Enforce     []string `toml:"enforce"`
	MRTDAllow   []string `toml:"mrtd_allow"`
	MRSEAMAllow []string `toml:"mrseam_allow"`
	RTMR0Allow  []string `toml:"rtmr0_allow"`
	RTMR1Allow  []string `toml:"rtmr1_allow"`
	RTMR2Allow  []string `toml:"rtmr2_allow"`
	RTMR3Allow  []string `toml:"rtmr3_allow"`

	// Gateway-specific measurement allowlists (GW-M-04).
	GatewayMRTDAllow   []string `toml:"gateway_mrtd_allow"`
	GatewayMRSEAMAllow []string `toml:"gateway_mrseam_allow"`
	GatewayRTMR0Allow  []string `toml:"gateway_rtmr0_allow"`
	GatewayRTMR1Allow  []string `toml:"gateway_rtmr1_allow"`
	GatewayRTMR2Allow  []string `toml:"gateway_rtmr2_allow"`
	GatewayRTMR3Allow  []string `toml:"gateway_rtmr3_allow"`

	// WarnMeasurements, when true, causes measurement allowlist mismatches to
	// produce warnings instead of blocking. Operators can deploy allowlists
	// in observation mode before enforcing them.
	WarnMeasurements bool `toml:"warn_measurements"`
}

// tomlFile mirrors the top-level structure of the optional TOML config file.
type tomlFile struct {
	Providers     map[string]ProviderConfig `toml:"providers"`
	Policy        PolicyConfig              `toml:"policy"`
	PoCSigningKey string                    `toml:"poc_signing_key"`
}

// Provider is a fully resolved provider configuration, ready for use by the
// proxy and attestation verifier. Attester and Preparer are populated in Phase 4.
type Provider struct {
	Name    string
	BaseURL string
	APIKey  string
	E2EE    bool
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

	// MeasurementPolicy defines optional allowlists for TDX measurements.
	MeasurementPolicy attestation.MeasurementPolicy

	// GatewayMeasurementPolicy defines optional allowlists for gateway CVM
	// TDX measurements, separate from model backend measurements (GW-M-04).
	GatewayMeasurementPolicy attestation.MeasurementPolicy

	// Offline skips external verification calls (Intel PCS collateral,
	// Proof of Cloud registry, and Certificate Transparency checks).
	// Set via --offline flag at runtime.
	Offline bool

	// PoCSigningKey is the optional base64-encoded ed25519 public key for
	// verifying EdDSA signatures on Proof of Cloud JWTs (GW-M-11).
	// When empty, only JWT claims are validated (no signature verification).
	PoCSigningKey string
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

	policy, err := buildMeasurementPolicy(&f.Policy)
	if err != nil {
		return err
	}
	cfg.MeasurementPolicy = policy

	gatewayPolicy, err := buildGatewayMeasurementPolicy(&f.Policy)
	if err != nil {
		return err
	}
	cfg.GatewayMeasurementPolicy = gatewayPolicy

	cfg.PoCSigningKey = f.PoCSigningKey

	return nil
}

func buildMeasurementPolicy(p *PolicyConfig) (attestation.MeasurementPolicy, error) {
	var out attestation.MeasurementPolicy

	var err error
	out.MRTDAllow, err = normalizeAllowlist(p.MRTDAllow, "policy.mrtd_allow")
	if err != nil {
		return out, err
	}
	out.MRSeamAllow, err = normalizeAllowlist(p.MRSEAMAllow, "policy.mrseam_allow")
	if err != nil {
		return out, err
	}

	for i, list := range [4][]string{p.RTMR0Allow, p.RTMR1Allow, p.RTMR2Allow, p.RTMR3Allow} {
		out.RTMRAllow[i], err = normalizeAllowlist(list, fmt.Sprintf("policy.rtmr%d_allow", i))
		if err != nil {
			return out, err
		}
	}

	out.WarnOnly = p.WarnMeasurements
	return out, nil
}

func buildGatewayMeasurementPolicy(p *PolicyConfig) (attestation.MeasurementPolicy, error) {
	var out attestation.MeasurementPolicy

	var err error
	out.MRTDAllow, err = normalizeAllowlist(p.GatewayMRTDAllow, "policy.gateway_mrtd_allow")
	if err != nil {
		return out, err
	}
	out.MRSeamAllow, err = normalizeAllowlist(p.GatewayMRSEAMAllow, "policy.gateway_mrseam_allow")
	if err != nil {
		return out, err
	}

	for i, list := range [4][]string{p.GatewayRTMR0Allow, p.GatewayRTMR1Allow, p.GatewayRTMR2Allow, p.GatewayRTMR3Allow} {
		out.RTMRAllow[i], err = normalizeAllowlist(list, fmt.Sprintf("policy.gateway_rtmr%d_allow", i))
		if err != nil {
			return out, err
		}
	}

	out.WarnOnly = p.WarnMeasurements
	return out, nil
}

// tdxMeasurementBytes is the expected size (in bytes) of TDX measurement
// values (MRTD, MRSEAM, RTMR0–3): 48 bytes = 384 bits (SHA-384).
const tdxMeasurementBytes = 48

func normalizeAllowlist(values []string, field string) (map[string]struct{}, error) {
	if values == nil {
		return map[string]struct{}{}, nil // field absent from TOML — no policy
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s is set but empty; remove the key to disable policy, or add at least one hex value", field)
	}
	norm := make(map[string]struct{}, len(values))
	for _, v := range values {
		s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "0x")
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid hex %q: %w", field, v, err)
		}
		if len(b) != tdxMeasurementBytes {
			return nil, fmt.Errorf("%s entry %q decodes to %d bytes, want %d", field, v, len(b), tdxMeasurementBytes)
		}
		norm[s] = struct{}{}
	}
	return norm, nil
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

	return &Provider{
		Name:    name,
		BaseURL: pc.BaseURL,
		APIKey:  apiKey,
		E2EE:    pc.E2EE,
	}
}

// applyEnvOverrides applies environment variable overrides to cfg.
// TEEP_LISTEN_ADDR overrides the listen address.
// VENICE_API_KEY, NEARAI_API_KEY, and NANOGPT_API_KEY inject or override provider API keys.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("TEEP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	applyAPIKeyEnv(cfg, "venice", "VENICE_API_KEY", "https://api.venice.ai", true)
	applyAPIKeyEnv(cfg, "neardirect", "NEARAI_API_KEY", "https://completions.near.ai", false)
	applyAPIKeyEnv(cfg, "nearcloud", "NEARAI_API_KEY", "https://cloud-api.near.ai", true)
	applyAPIKeyEnv(cfg, "nanogpt", "NANOGPT_API_KEY", "https://nano-gpt.com/api", false)
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
			Name:    name,
			BaseURL: defaultBaseURL,
			E2EE:    defaultE2EE,
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

// NewAttestationClient returns an *http.Client with a 30-second timeout and
// tuned transport, suitable for fetching attestation data from TEE provider
// endpoints. The default MaxIdleConnsPerHost (2) is too low for providers
// that serve multiple models from the same host. In offline mode, CT checks
// are disabled to avoid external CT log list downloads.
func NewAttestationClient(offline ...bool) *http.Client {
	ctEnabled := len(offline) == 0 || !offline[0]
	return tlsct.NewHTTPClientWithTransport(AttestationTimeout, &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, ctEnabled)
}

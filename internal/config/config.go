// Package config loads and validates teep proxy configuration from an optional
// TOML file and environment variable overrides.
//
// Load order:
//
//  1. Built-in defaults (listen addr 127.0.0.1:8337, default enforced factors).
//  2. TOML file at $TEEP_CONFIG, if set.
//  3. Environment variables (TEEP_LISTEN_ADDR, TEEP_MAX_CONNS, VENICE_API_KEY, NEARAI_API_KEY, NANOGPT_API_KEY).
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
	"strconv"
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

	// MaxConnections is the upper bound accepted for TEEP_MAX_CONNS.
	// Values above this are clamped with a warning.
	MaxConnections = 10000

	// rlimitHeadroom is the number of file descriptors reserved for non-connection
	// use (log files, config files, attestation HTTP clients, etc.) when computing
	// the default connection limit from RLIMIT_NOFILE.
	rlimitHeadroom = 50

	// AttestationTimeout is the HTTP client timeout for attestation fetches.
	// 45 seconds accommodates Chutes' multi-GPU evidence endpoint which
	// consistently takes ~30 seconds for large TEE deployments.
	AttestationTimeout = 45 * time.Second
)

// DefaultAllowFail lists the factor names that are allowed to fail without
// blocking the proxy. Every factor NOT in this list is enforced.
var DefaultAllowFail = attestation.DefaultAllowFail

// providerDefaultAllowFail maps provider names to their provider-specific
// Go-level default allow_fail lists. Providers not in this map fall back to
// the global DefaultAllowFail.
var providerDefaultAllowFail = map[string][]string{
	"chutes":     attestation.ChutesDefaultAllowFail,
	"nearcloud":  attestation.NearcloudDefaultAllowFail,
	"neardirect": attestation.NeardirectDefaultAllowFail,
}

// ProviderDefaultAllowFail returns a defensive copy of the provider-specific
// default allow_fail lists. Callers must not rely on mutating the returned
// map or its slices to change enforcement behavior at runtime.
func ProviderDefaultAllowFail() map[string][]string {
	out := make(map[string][]string, len(providerDefaultAllowFail))
	for provider, allowList := range providerDefaultAllowFail {
		if allowList == nil {
			continue
		}
		copied := make([]string, len(allowList))
		copy(copied, allowList)
		out[provider] = copied
	}
	return out
}

// ProviderConfig holds the TOML-parsed configuration for one provider.
// Either APIKey or APIKeyEnv must be set; APIKeyEnv takes precedence if both
// are present. The resolved key is exposed via the Provider struct, not here.
type ProviderConfig struct {
	APIKey    string       `toml:"api_key"`
	APIKeyEnv string       `toml:"api_key_env"`
	BaseURL   string       `toml:"base_url"`
	E2EE      bool         `toml:"e2ee"`
	AllowFail []string     `toml:"allow_fail"`
	Policy    PolicyConfig `toml:"policy"`
}

// PolicyConfig holds the optional [policy] section from the TOML file.
type PolicyConfig struct {
	AllowFail   []string `toml:"allow_fail"`
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
}

// tomlFile mirrors the top-level structure of the optional TOML config file.
type tomlFile struct {
	Providers map[string]ProviderConfig `toml:"providers"`
	AllowFail []string                  `toml:"allow_fail"`
	Policy    PolicyConfig              `toml:"policy"`
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

	// MaxConns is the maximum number of concurrent inbound connections.
	// By default this is computed by defaultMaxConns() from RLIMIT_NOFILE
	// and can be overridden with TEEP_MAX_CONNS.
	MaxConns int

	// Providers is the map of provider name → resolved provider config.
	Providers map[string]*Provider

	// AllowFail lists factor names that are allowed to fail without blocking.
	// Every factor NOT in this list is enforced. When nil (no TOML loaded or
	// programmatic config), MergedAllowFail selects per-provider or global
	// Go defaults. Use MergedAllowFail to obtain the effective list.
	AllowFail []string

	// ProviderAllowFail holds per-provider allow_fail overrides parsed from
	// [providers.X] TOML sections. Keys are provider names.
	ProviderAllowFail map[string][]string

	// MeasurementPolicy defines optional allowlists for TDX measurements.
	MeasurementPolicy attestation.MeasurementPolicy

	// GatewayMeasurementPolicy defines optional allowlists for gateway CVM
	// TDX measurements, separate from model backend measurements (GW-M-04).
	GatewayMeasurementPolicy attestation.MeasurementPolicy

	// ProviderPolicies holds per-provider measurement allowlists parsed from
	// [providers.X.policy] TOML sections. Keys are provider names.
	ProviderPolicies map[string]attestation.MeasurementPolicy

	// ProviderGatewayPolicies holds per-provider gateway measurement
	// allowlists parsed from [providers.X.policy] gateway_ fields.
	ProviderGatewayPolicies map[string]attestation.MeasurementPolicy

	// GlobalAllowFailDefined is true when the TOML config explicitly sets a
	// global allow_fail list (including an empty list), either via the root
	// allow_fail field or [policy].allow_fail. When false, MergedAllowFail
	// checks per-provider Go defaults before the global default.
	GlobalAllowFailDefined bool

	// Offline skips external verification calls (Intel PCS collateral,
	// Proof of Cloud registry, and Certificate Transparency checks).
	// Set via --offline flag at runtime.
	Offline bool

	// Force forwards requests even when enforced attestation factors fail.
	// Set via --force flag. WARNING: this reduces security guarantees.
	Force bool
}

// warnIfRlimitLow logs a warning when the soft RLIMIT_NOFILE is below 1000,
// regardless of whether MaxConns was set by default or by TEEP_MAX_CONNS.
func warnIfRlimitLow(soft int) {
	if soft < 1000 {
		slog.Warn("RLIMIT_NOFILE is very low; consider raising 'ulimit -n'",
			"rlimit_nofile", soft)
	}
}

// defaultMaxConns computes the default connection limit from RLIMIT_NOFILE,
// reserving rlimitHeadroom FDs for non-connection use and emitting startup
// warnings when the system FD limit is very low or explicitly unlimited.
func defaultMaxConns() int {
	soft, unlimited, err := nofileRlimit()
	if err != nil {
		slog.Warn("cannot read RLIMIT_NOFILE; using built-in default",
			"default", 1000, "err", err)
		return 1000
	}
	if unlimited {
		slog.Info("RLIMIT_NOFILE is unlimited; connection limit defaults to 1000; "+
			"set TEEP_MAX_CONNS to configure explicitly",
			"default", 1000)
		return 1000
	}
	warnIfRlimitLow(soft)
	return max(1, min(soft-rlimitHeadroom, MaxConnections))
}

// Load reads configuration from the optional TOML file (path from $TEEP_CONFIG)
// and applies environment variable overrides. It logs a warning to stderr if
// the listen address is non-loopback or if the config file has insecure
// permissions, but does not return an error for either condition.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:              DefaultListenAddr,
		MaxConns:                defaultMaxConns(),
		Providers:               make(map[string]*Provider),
		ProviderAllowFail:       make(map[string][]string),
		ProviderPolicies:        make(map[string]attestation.MeasurementPolicy),
		ProviderGatewayPolicies: make(map[string]attestation.MeasurementPolicy),
	}

	configPath := os.Getenv("TEEP_CONFIG")
	if configPath != "" {
		if err := loadTOML(cfg, configPath); err != nil {
			return nil, fmt.Errorf("loading config file %q: %w", configPath, err)
		}
	}

	applyEnvOverrides(cfg)
	warnNonLoopback(cfg.ListenAddr)
	if cfg.GlobalAllowFailDefined {
		for _, factor := range cfg.AllowFail {
			slog.Warn("security factor in global allow_fail; failures will not block requests", "factor", factor)
		}
	}
	for name, factors := range cfg.ProviderAllowFail {
		for _, factor := range factors {
			slog.Warn("security factor in provider allow_fail; failures will not block requests", "provider", name, "factor", factor)
		}
	}
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
	meta, err := toml.DecodeFile(path, &f)
	if err != nil {
		return fmt.Errorf("TOML decode: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("unknown config keys: %v", undecoded)
	}

	for name := range f.Providers {
		pc := f.Providers[name]
		p := resolveProvider(name, &pc)
		cfg.Providers[name] = p

		// Parse per-provider allow_fail list.
		// Use meta.IsDefined to distinguish "not set" from explicitly empty
		// (allow_fail = []), which means "enforce all factors".
		if meta.IsDefined("providers", name, "allow_fail") {
			if err := validateAllowFail(pc.AllowFail); err != nil {
				return fmt.Errorf("providers.%s.allow_fail: %w", name, err)
			}
			cfg.ProviderAllowFail[name] = pc.AllowFail
		}

		// Parse per-provider [providers.X.policy] sections.
		pp, err := buildMeasurementPolicy(&pc.Policy)
		if err != nil {
			return fmt.Errorf("providers.%s.policy: %w", name, err)
		}
		if hasMeasurementPolicy(pp) {
			cfg.ProviderPolicies[name] = pp
		}
		gpp, err := buildGatewayMeasurementPolicy(&pc.Policy)
		if err != nil {
			return fmt.Errorf("providers.%s.policy (gateway): %w", name, err)
		}
		if hasMeasurementPolicy(gpp) {
			cfg.ProviderGatewayPolicies[name] = gpp
		}
	}

	// Top-level allow_fail (from toml file root or [policy] section).
	// Provider-level takes precedence; this is the global fallback.
	// Use meta.IsDefined to distinguish "not set" from explicitly empty
	// (allow_fail = []), which means "enforce all factors".
	topLevelAF := f.AllowFail
	topLevelDefined := meta.IsDefined("allow_fail")
	if !topLevelDefined && meta.IsDefined("policy", "allow_fail") {
		topLevelAF = f.Policy.AllowFail
		topLevelDefined = true
	}
	if topLevelDefined {
		if err := validateAllowFail(topLevelAF); err != nil {
			return fmt.Errorf("allow_fail: %w", err)
		}
		cfg.AllowFail = topLevelAF
		cfg.GlobalAllowFailDefined = true
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

	return out, nil
}

// validateAllowFail checks that every name in the allow_fail list is a known factor.
func validateAllowFail(names []string) error {
	known := make(map[string]bool, len(attestation.KnownFactors))
	for _, n := range attestation.KnownFactors {
		known[n] = true
	}
	for _, n := range names {
		if !known[n] {
			return fmt.Errorf("unknown allow_fail factor %q", n)
		}
	}
	return nil
}

// MergedAllowFail returns the allow_fail list for a provider, applying a
// four-layer merge (first defined wins):
//  1. Per-provider TOML override  ([providers.X] allow_fail)
//  2. Global TOML override        (top-level allow_fail)
//  3. Per-provider Go defaults    (ProviderDefaultAllowFail)
//  4. Global Go defaults          (DefaultAllowFail)
//
// When offline is true, factors that require network access (OnlineFactors)
// are automatically added to the result so they cannot block requests.
func MergedAllowFail(providerName string, cfg *Config, offline bool) []string {
	var af []string
	switch {
	case cfg.ProviderAllowFail[providerName] != nil:
		// Use != nil (not ok) so that an explicitly empty slice is honored.
		af = cfg.ProviderAllowFail[providerName]
	case cfg.GlobalAllowFailDefined || cfg.AllowFail != nil:
		// GlobalAllowFailDefined is set by loadTOML; cfg.AllowFail != nil
		// covers programmatic configs (tests, proxy setup) that set
		// AllowFail directly without calling Load().
		af = cfg.AllowFail
	default:
		if paf, ok := ProviderDefaultAllowFail()[providerName]; ok {
			af = paf
		} else {
			af = DefaultAllowFail
		}
	}
	if offline {
		return attestation.WithOfflineAllowFail(af)
	}
	// Return a copy so callers cannot mutate shared defaults.
	return append([]string(nil), af...)
}

// hasMeasurementPolicy reports whether p has any configured allowlists.
func hasMeasurementPolicy(p attestation.MeasurementPolicy) bool {
	return p.HasMRTDPolicy() || p.HasMRSeamPolicy() ||
		p.HasRTMRPolicy(0) || p.HasRTMRPolicy(1) ||
		p.HasRTMRPolicy(2) || p.HasRTMRPolicy(3)
}

// MergedMeasurementPolicy returns a MeasurementPolicy that merges three layers:
// per-provider TOML > global TOML > Go defaults. For each allowlist field, the
// most specific non-empty layer wins.
func MergedMeasurementPolicy(providerName string, cfg *Config, goDefaults attestation.MeasurementPolicy) attestation.MeasurementPolicy {
	global := cfg.MeasurementPolicy
	perProvider, hasPerProvider := cfg.ProviderPolicies[providerName]

	out := goDefaults
	out = mergeAllowlists(out, global)
	if hasPerProvider {
		out = mergeAllowlists(out, perProvider)
	}
	return out
}

// MergedGatewayMeasurementPolicy returns a gateway MeasurementPolicy with the
// same three-layer merge: per-provider TOML > global TOML > Go defaults.
func MergedGatewayMeasurementPolicy(providerName string, cfg *Config, goDefaults attestation.MeasurementPolicy) attestation.MeasurementPolicy {
	global := cfg.GatewayMeasurementPolicy
	perProvider, hasPerProvider := cfg.ProviderGatewayPolicies[providerName]

	out := goDefaults
	out = mergeAllowlists(out, global)
	if hasPerProvider {
		out = mergeAllowlists(out, perProvider)
	}
	return out
}

// mergeAllowlists applies overlay on top of base: for each field that has a
// configured policy in overlay, it replaces the corresponding field in base.
func mergeAllowlists(base, overlay attestation.MeasurementPolicy) attestation.MeasurementPolicy {
	if overlay.HasMRTDPolicy() {
		base.MRTDAllow = overlay.MRTDAllow
	}
	if overlay.HasMRSeamPolicy() {
		base.MRSeamAllow = overlay.MRSeamAllow
	}
	for i := range overlay.RTMRAllow {
		if overlay.HasRTMRPolicy(i) {
			base.RTMRAllow[i] = overlay.RTMRAllow[i]
		}
	}
	return base
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
func resolveProvider(name string, pc *ProviderConfig) *Provider {
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
// TEEP_MAX_CONNS overrides the maximum concurrent connections.
// VENICE_API_KEY, NEARAI_API_KEY, and NANOGPT_API_KEY inject or override provider API keys.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("TEEP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("TEEP_MAX_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		switch {
		case err != nil:
			slog.Warn("TEEP_MAX_CONNS is not a valid integer; ignoring override",
				"value", v, "keeping", cfg.MaxConns)
		case n <= 0:
			slog.Warn("TEEP_MAX_CONNS must be a positive integer; ignoring override",
				"value", n, "keeping", cfg.MaxConns)
		case n > MaxConnections:
			slog.Warn("TEEP_MAX_CONNS exceeds maximum; clamping", "value", n, "max", MaxConnections)
			cfg.MaxConns = MaxConnections
		default:
			if soft, unlimited, rerr := nofileRlimit(); rerr == nil && !unlimited {
				warnIfRlimitLow(soft)
				if n > soft-rlimitHeadroom {
					slog.Warn("TEEP_MAX_CONNS exceeds usable file descriptor headroom",
						"teep_max_conns", n, "rlimit_nofile", soft, "headroom", rlimitHeadroom)
				}
			}
			cfg.MaxConns = n
		}
	}

	applyAPIKeyEnv(cfg, "venice", "VENICE_API_KEY", "https://api.venice.ai", true)
	applyAPIKeyEnv(cfg, "neardirect", "NEARAI_API_KEY", "https://completions.near.ai", false)
	applyAPIKeyEnv(cfg, "nearcloud", "NEARAI_API_KEY", "https://cloud-api.near.ai", true)
	applyAPIKeyEnv(cfg, "nanogpt", "NANOGPT_API_KEY", "https://nano-gpt.com/api", false)
	applyAPIKeyEnv(cfg, "phalacloud", "PHALA_API_KEY", "https://api.redpill.ai", false)
	applyAPIKeyEnv(cfg, "chutes", "CHUTES_API_KEY", "https://api.chutes.ai", true)
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

// RetryTransport retries requests on 5xx responses and network errors. For
// requests with a body it requires req.GetBody to be set so the body can be
// reset between attempts (http.NewRequestWithContext sets GetBody automatically
// when passed a *bytes.Reader). If a retry is needed and GetBody is nil for a
// request with a body, the last error is returned immediately rather than
// sending an empty body. GET requests have no body and are always retried
// unconditionally.
//
// Base must be non-nil.
//
// All attestation endpoints retried by this transport are effectively
// idempotent reads. Do not use for POST endpoints with side effects (nonce
// consumption, billing) without explicit consideration.
type RetryTransport struct {
	Base        http.RoundTripper
	MaxAttempts int           // 0 → default 3
	MaxDelay    time.Duration // 0 → default 4s
}

// RoundTrip executes the request, retrying on 5xx and network errors.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := t.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	maxDelay := t.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 4 * time.Second
	}
	hasBody := req.Body != nil && req.Body != http.NoBody
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			if hasBody && req.GetBody == nil {
				// Body was consumed on the first attempt and cannot be reset.
				return nil, lastErr
			}
			exp := min(attempt-1, 30) // cap to avoid int64 overflow; 2^30s >> any realistic maxDelay
			timer := time.NewTimer(min(time.Duration(1<<exp)*time.Second, maxDelay))
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
			slog.WarnContext(req.Context(), "retrying after error",
				"host", req.URL.Host, "path", req.URL.Path, "attempt", attempt+1, "err", lastErr)
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				req.Body = body
			}
		}
		resp, err := t.Base.RoundTrip(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// NewAttestationClient returns an *http.Client with a 30-second timeout and
// tuned transport, suitable for fetching attestation data from TEE provider
// endpoints. The default MaxIdleConnsPerHost (2) is too low for providers
// that serve multiple models from the same host. In offline mode, CT checks
// are disabled to avoid external CT log list downloads.
func NewAttestationClient(offline bool) *http.Client {
	client := tlsct.NewHTTPClientWithTransport(AttestationTimeout, &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}, !offline)
	client.Transport = tlsct.WrapLogging(client.Transport)
	client.Transport = &RetryTransport{Base: client.Transport}
	return client
}

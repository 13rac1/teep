package attestation

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Status is the result of a single verification factor check.
type Status uint8

const (
	// Pass means the factor was checked and the check succeeded.
	Pass Status = iota
	// Fail means the factor was checked and the check failed.
	Fail
	// Skip means the factor was not applicable or data was unavailable.
	Skip
)

// String returns a human-readable label for the status.
func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Fail:
		return "FAIL"
	case Skip:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

// Tier constants for grouping verification factors in reports.
const (
	TierCore        = "Tier 1: Core Attestation"
	TierBinding     = "Tier 2: Binding & Crypto"
	TierSupplyChain = "Tier 3: Supply Chain & Channel Integrity"
	TierGateway     = "Tier 4: Gateway Attestation"
)

// FactorResult records the outcome of one verification factor.
type FactorResult struct {
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Enforced bool   `json:"enforced"` // from policy config
	Tier     string `json:"tier"`
	Deferred bool   `json:"deferred,omitempty"` // true = post-report-build evaluation; Skip not promoted to Fail
}

// VerificationReport holds the factor-by-factor results of an attestation
// verification run. Produced by BuildReport.
type VerificationReport struct {
	Title          string            `json:"title,omitempty"` // header label; defaults to "Attestation Report"
	Provider       string            `json:"provider"`
	Model          string            `json:"model"`
	Timestamp      time.Time         `json:"timestamp"`
	Factors        []FactorResult    `json:"factors"`
	Passed         int               `json:"passed"`
	Failed         int               `json:"failed"`
	Skipped        int               `json:"skipped"`
	EnforcedFailed int               `json:"enforced_failed"`
	AllowedFailed  int               `json:"allowed_failed"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Blocked returns true if any enforced factor has failed. When Blocked is true,
// the proxy must refuse to forward the request or perform E2EE.
func (r *VerificationReport) Blocked() bool {
	for _, f := range r.Factors {
		if f.Status == Fail && f.Enforced {
			return true
		}
	}
	return false
}

// Clone returns a deep copy of the report. Factors and Metadata are copied so
// mutations to the clone do not affect the original (or vice-versa). Use this
// before calling MarkE2EEUsable to avoid racing with concurrent readers of
// a cached report.
func (r *VerificationReport) Clone() *VerificationReport {
	if r == nil {
		return nil
	}
	dst := *r
	dst.Factors = make([]FactorResult, len(r.Factors))
	copy(dst.Factors, r.Factors)
	if r.Metadata != nil {
		dst.Metadata = make(map[string]string, len(r.Metadata))
		maps.Copy(dst.Metadata, r.Metadata)
	}
	return &dst
}

// BlockedFactors returns the names and details of every enforced factor that
// has failed. The slice is nil when Blocked() would return false.
func (r *VerificationReport) BlockedFactors() []FactorResult {
	var out []FactorResult
	for _, f := range r.Factors {
		if f.Status == Fail && f.Enforced {
			out = append(out, f)
		}
	}
	return out
}

// ReportDataBindingPassed returns true if the tdx_reportdata_binding factor
// passed. Without this, a MITM can substitute the enclave public key and
// E2EE becomes security theater. E2EE must never be activated unless this
// returns true.
func (r *VerificationReport) ReportDataBindingPassed() bool {
	for _, f := range r.Factors {
		if f.Name == "tdx_reportdata_binding" {
			return f.Status == Pass
		}
	}
	return false
}

// MarkE2EEUsable updates the e2ee_usable factor to Pass after a successful
// E2EE roundtrip in the proxy path. Counters are recomputed from the full
// factor list to avoid desync. This must only be called when E2EE was
// actually used for a live request and the response was successfully
// decrypted.
func (r *VerificationReport) MarkE2EEUsable(detail string) {
	for i := range r.Factors {
		if r.Factors[i].Name == "e2ee_usable" {
			if r.Factors[i].Status == Skip {
				r.Factors[i].Status = Pass
				r.Factors[i].Detail = detail
				r.recomputeCounters()
			}
			return
		}
	}
}

// MarkE2EEFailed demotes the e2ee_usable factor to Fail after a post-relay
// decryption failure. This is the counterpart to MarkE2EEUsable and keeps
// the report consistent with the e2eeFailed blocking state. Counters are
// recomputed from the full factor list.
func (r *VerificationReport) MarkE2EEFailed(detail string) {
	for i := range r.Factors {
		if r.Factors[i].Name == "e2ee_usable" {
			if r.Factors[i].Status != Fail {
				r.Factors[i].Status = Fail
				r.Factors[i].Detail = detail
				r.recomputeCounters()
			}
			return
		}
	}
}

// recomputeCounters recalculates all summary counters from the Factors slice.
// Called after any post-build factor mutation to prevent counter desync.
func (r *VerificationReport) recomputeCounters() {
	passed, failed, skipped := 0, 0, 0
	enforcedFailed, allowedFailed := 0, 0
	for _, f := range r.Factors {
		switch f.Status {
		case Pass:
			passed++
		case Fail:
			failed++
			if f.Enforced {
				enforcedFailed++
			} else {
				allowedFailed++
			}
		case Skip:
			skipped++
		}
	}
	r.Passed = passed
	r.Failed = failed
	r.Skipped = skipped
	r.EnforcedFailed = enforcedFailed
	r.AllowedFailed = allowedFailed
}

// DefaultAllowFail lists the factor names that are allowed to fail without
// blocking the proxy. Every factor in KnownFactors that is NOT in this list
// is enforced by default. This inversion is safer than a positive enforce
// list: any new factor added to KnownFactors is automatically enforced
// unless explicitly exempted here.
var DefaultAllowFail = []string{
	"tdx_quote_present",
	"tdx_quote_structure",
	"tdx_hardware_config",
	"tdx_boot_config",
	"intel_pcs_collateral",
	"tdx_tcb_current",
	"nvidia_payload_present",
	"nvidia_claims",
	"nvidia_nras_verified",
	"e2ee_capable",
	"e2ee_usable",
	"tls_key_binding",
	"cpu_gpu_chain",
	"measured_model_weights",
	"cpu_id_registry",
	// Gateway factors (nearcloud only).
	"gateway_tdx_quote_present",
	"gateway_tdx_quote_structure",
	"gateway_tdx_hardware_config",
	"gateway_tdx_boot_config",
	"gateway_tdx_reportdata_binding",
	"gateway_cpu_id_registry",
}

// NearcloudDefaultAllowFail is the nearcloud-specific default allow_fail list.
// It enforces more factors than the global DefaultAllowFail, reflecting the
// nearcloud provider's stronger attestation support.
var NearcloudDefaultAllowFail = []string{
	"tdx_hardware_config",
	"tdx_boot_config",
	"cpu_gpu_chain",
	"measured_model_weights",
	"cpu_id_registry",
	// Gateway factors (nearcloud only).
	"gateway_tdx_hardware_config",
	"gateway_tdx_boot_config",
	"gateway_tdx_reportdata_binding",
	"gateway_cpu_id_registry",
}

// NeardirectDefaultAllowFail is the neardirect-specific default allow_fail
// list. It enforces more factors than the global DefaultAllowFail, reflecting
// the neardirect provider's stronger attestation support.
var NeardirectDefaultAllowFail = []string{
	"tdx_hardware_config",
	"tdx_boot_config",
	"cpu_gpu_chain",
	"measured_model_weights",
	"cpu_id_registry",
}

// ChutesDefaultAllowFail is the chutes-specific default allow_fail list.
// Chutes runs sek8s inside Intel TDX VMs and supports NVIDIA GPU attestation.
// Core TDX quote integrity (structure, cert chain, signature, debug mode,
// MRTD/MRSEAM) and REPORTDATA binding are enforced. TDX hardware/boot config
// and NVIDIA signature/NRAS are allowed to fail because these factors are not
// yet consistent across the Chutes fleet. Supply-chain and build provenance
// factors remain allowed-to-fail until the sek8s platform exposes the
// necessary evidence.
var ChutesDefaultAllowFail = []string{
	"tdx_hardware_config",
	"tdx_boot_config",
	"nvidia_signature",
	"nvidia_nras_verified",
	"tls_key_binding",
	"cpu_gpu_chain",
	"measured_model_weights",
	"build_transparency_log",
	"cpu_id_registry",
	"compose_binding",
	"sigstore_verification",
	"event_log_integrity",
}

// KnownFactors is the complete set of factor names produced by BuildReport.
// Used by config validation to reject typos in the allow_fail list.
var KnownFactors = []string{
	"nonce_match", "tdx_quote_present", "tdx_quote_structure", "tdx_cert_chain",
	"tdx_quote_signature", "tdx_debug_disabled",
	"tdx_mrseam_mrtd", "tdx_hardware_config", "tdx_boot_config",
	"signing_key_present",
	"tdx_reportdata_binding", "intel_pcs_collateral", "tdx_tcb_current",
	"tdx_tcb_not_revoked", "nvidia_payload_present", "nvidia_signature", "nvidia_claims",
	"nvidia_nonce_client_bound", "nvidia_nras_verified", "e2ee_capable", "e2ee_usable", "tls_key_binding", "cpu_gpu_chain",
	"measured_model_weights", "build_transparency_log", "cpu_id_registry",
	"compose_binding", "sigstore_verification", "event_log_integrity",
	// Gateway factors (nearcloud only).
	"gateway_nonce_match", "gateway_tdx_quote_present", "gateway_tdx_quote_structure",
	"gateway_tdx_cert_chain", "gateway_tdx_quote_signature", "gateway_tdx_debug_disabled",
	"gateway_tdx_mrseam_mrtd", "gateway_tdx_hardware_config", "gateway_tdx_boot_config",
	"gateway_tdx_reportdata_binding", "gateway_compose_binding", "gateway_cpu_id_registry",
	"gateway_event_log_integrity",
}

// OnlineFactors lists factors whose evaluation requires network access to
// external services (Intel PCS, NVIDIA NRAS, Proof of Cloud, Sigstore/Rekor,
// live E2EE inference test).
//
// Note: e2ee_usable is included because it is evaluated via a live encrypted
// inference against the provider (see testE2EE in cmd/teep/main.go). The
// local crypto self-test (TestE2EESetup) validates key exchange and encryption
// without network access, but does not exercise the full E2EE round-trip and
// is therefore not sufficient to satisfy e2ee_usable in online mode.
//
// In --offline mode every factor in this list is automatically added to
// allow_fail so that the absence of network connectivity cannot block
// requests.
var OnlineFactors = []string{
	"intel_pcs_collateral",
	"tdx_tcb_current",
	"tdx_tcb_not_revoked",
	"nvidia_nras_verified",
	"e2ee_usable",
	"build_transparency_log",
	"cpu_id_registry",
	"sigstore_verification",
	"gateway_cpu_id_registry",
}

// WithOfflineAllowFail returns a new allow_fail list that unions the given
// list with OnlineFactors. Used when --offline mode is active to prevent
// online-dependent factors from blocking requests.
func WithOfflineAllowFail(allowFail []string) []string {
	have := make(map[string]bool, len(allowFail))
	for _, f := range allowFail {
		have[f] = true
	}
	merged := append([]string(nil), allowFail...)
	for _, f := range OnlineFactors {
		if !have[f] {
			merged = append(merged, f)
		}
	}
	return merged
}

// WithAllowFail returns a new allow_fail list with the given factor added
// if not already present. Returns a copy; does not modify the input slice.
func WithAllowFail(allowFail []string, factor string) []string {
	if slices.Contains(allowFail, factor) {
		return append([]string(nil), allowFail...)
	}
	merged := append([]string(nil), allowFail...)
	return append(merged, factor)
}

// E2EETestResult holds the outcome of a live E2EE test inference.
type E2EETestResult struct {
	// Attempted is true when the E2EE test was started (encryption, request
	// construction, or HTTP exchange was attempted). It does not imply a
	// response was successfully received — check Err for the outcome.
	Attempted bool
	// NoAPIKey is true when the test was skipped because no API key was available.
	NoAPIKey bool
	// APIKeyEnv is the name of the environment variable for this provider's API key.
	APIKeyEnv string
	// Err is non-nil when the test failed (request error, unencrypted response fields, decryption error).
	Err error
	// Detail is a human-readable summary of the test outcome.
	Detail string
	// KeyType is the canonical E2EE key type derived from the attestation
	// (e.g. "ecdsa", "ed25519", "ml-kem-768").
	KeyType string
}

// knownSigningAlgos is the allowlist of canonical algorithm names that may
// appear in RawAttestation.SigningAlgo. Values outside this set are reported
// as "unknown" rather than passed through verbatim, since SigningAlgo is
// provider-supplied and flows into on-disk manifests.
var knownSigningAlgos = map[string]bool{
	"ecdsa":      true,
	"ed25519":    true,
	"ml-kem-768": true,
	"secp256k1":  true,
}

// E2EEKeyType returns the canonical E2EE key-type string for the attestation.
// Returns "" when no signing key is present.
// When SigningAlgo is absent, the type is inferred from key length as a
// best-effort heuristic; this is informational only and must not be used for
// security decisions.
func (r *RawAttestation) E2EEKeyType() string {
	if r.SigningKey == "" {
		return ""
	}
	if r.SigningAlgo != "" {
		if knownSigningAlgos[r.SigningAlgo] {
			return r.SigningAlgo
		}
		return "unknown"
	}
	// Infer from key length as best-effort fallback (informational only).
	if len(r.SigningKey) == 64 {
		return "ed25519"
	}
	return "ecdsa"
}

// ComposeBindingResult holds the outcome of verifying the app_compose → MRConfigID binding.
type ComposeBindingResult struct {
	// Checked is true when AppCompose was present and verification was attempted.
	Checked bool
	// Err is non-nil when the binding check failed.
	Err error
}

// ReportInput bundles all inputs to BuildReport. Adding a new verification
// result type (e.g. AMD SEV-SNP) means adding a field here — no existing
// call sites change because unset fields default to nil.
type ReportInput struct {
	Provider          string
	Model             string
	Raw               *RawAttestation
	Nonce             Nonce
	AllowFail         []string
	Policy            MeasurementPolicy
	ImageRepos        []string
	GatewayImageRepos []string
	DigestToRepo      map[string]string // digest hex → normalized image repo, for policy checks
	SupplyChainPolicy *SupplyChainPolicy

	TDX        *TDXVerifyResult
	Nvidia     *NvidiaVerifyResult
	NvidiaNRAS *NvidiaVerifyResult
	PoC        *PoCResult
	Compose    *ComposeBindingResult
	Sigstore   []SigstoreResult
	Rekor      []RekorProvenance

	// Gateway fields — only populated for nearcloud provider.
	GatewayTDX      *TDXVerifyResult
	GatewayPoC      *PoCResult
	GatewayNonceHex string // echoed request_nonce from gateway response
	GatewayNonce    Nonce  // nonce we sent to the gateway
	GatewayCompose  *ComposeBindingResult
	GatewayEventLog []EventLogEntry
	GatewayPolicy   MeasurementPolicy // separate measurement allowlists for gateway CVM (GW-M-04)

	// E2EETest is the result of a live E2EE test inference. Nil when
	// the provider is not E2EE-capable or the test was not attempted.
	E2EETest *E2EETestResult

	// E2EEConfigured is true when the provider has E2EE enabled in its
	// configuration. Used by the proxy path where E2EETest is not
	// populated at report-build time but the provider will use E2EE
	// for actual requests. When true and E2EETest is nil, e2ee_usable
	// reports "pending live test" instead of "not configured".
	E2EEConfigured bool
}

// ---------------------------------------------------------------------------
// evaluatorFunc — each verification factor is a function of this type.
// ---------------------------------------------------------------------------

// evaluatorFunc evaluates one or more verification factors against the input.
type evaluatorFunc func(in *ReportInput) []FactorResult

// factor is a convenience constructor for a single-element []FactorResult.
func factor(tier, name string, status Status, detail string) []FactorResult {
	return []FactorResult{{Tier: tier, Name: name, Status: status, Detail: detail}}
}

// BuildReport runs verification factors against the input and returns a
// complete VerificationReport. The AllowFail field lists factors that are
// allowed to fail without blocking. Every other factor is enforced.
// Pass DefaultAllowFail for production use.
// Gateway factors are included only for nearcloud.
func BuildReport(in *ReportInput) *VerificationReport {
	allowFailSet := make(map[string]bool, len(in.AllowFail))
	for _, name := range in.AllowFail {
		allowFailSet[name] = true
	}

	evaluators := buildEvaluators(in.GatewayTDX != nil)
	var factors []FactorResult
	for _, eval := range evaluators {
		for _, f := range eval(in) {
			f.Enforced = !allowFailSet[f.Name]
			factors = append(factors, f)
		}
	}

	// Promote Skip → Fail for enforced factors.
	// Deferred factors (e.g. e2ee_usable) stay Skip because they can only
	// be evaluated via a live roundtrip — promoting them to Fail would
	// block the very request needed to prove they work. Post-relay
	// enforcement catches failures instead.
	for i := range factors {
		if factors[i].Status == Skip && factors[i].Enforced && !factors[i].Deferred {
			factors[i].Status = Fail
			factors[i].Detail += " (enforced)"
		}
	}

	passed, failed, skipped := 0, 0, 0
	enforcedFailed, allowedFailed := 0, 0
	for _, f := range factors {
		switch f.Status {
		case Pass:
			passed++
		case Fail:
			failed++
			if f.Enforced {
				enforcedFailed++
			} else {
				allowedFailed++
			}
		case Skip:
			skipped++
		}
	}

	return &VerificationReport{
		Provider:       in.Provider,
		Model:          in.Model,
		Timestamp:      time.Now(),
		Factors:        factors,
		Passed:         passed,
		Failed:         failed,
		Skipped:        skipped,
		EnforcedFailed: enforcedFailed,
		AllowedFailed:  allowedFailed,
		Metadata:       buildMetadata(in),
	}
}

// buildEvaluators returns the ordered list of factor evaluators. Gateway
// evaluators are appended only when includeGateway is true.
func buildEvaluators(includeGateway bool) []evaluatorFunc {
	evals := []evaluatorFunc{
		// Tier 1: Core Attestation
		evalNonceMatch,
		evalTDXQuotePresent,
		evalTDXParseDependent,
		evalTDXMrseamMrtd,
		evalTDXHardwareConfig,
		evalTDXBootConfig,
		evalSigningKeyPresent,
		// Tier 2: Binding & Crypto
		evalTDXReportDataBinding,
		evalIntelPCSCollateral,
		evalTDXTCBCurrent,
		evalTDXTCBNotRevoked,
		evalNvidiaPayloadPresent,
		evalNvidiaSignature,
		evalNvidiaClaims,
		evalNvidiaClientNonceBound,
		evalNvidiaNRASVerified,
		evalE2EECapable,
		evalE2EEUsable,
		// Tier 3: Supply Chain & Channel Integrity
		evalTLSKeyBinding,
		evalCPUGPUChain,
		evalMeasuredModelWeights,
		evalBuildTransparencyLog,
		evalCPUIDRegistry,
		evalComposeBinding,
		evalSigstoreVerification,
		evalEventLogIntegrity,
	}
	if includeGateway {
		evals = append(evals,
			evalGatewayNonceMatch,
			evalGatewayTDXQuotePresent,
			evalGatewayTDXParseDependent,
			evalGatewayTDXMrseamMrtd,
			evalGatewayTDXHardwareConfig,
			evalGatewayTDXBootConfig,
			evalGatewayTDXReportDataBinding,
			evalGatewayComposeBinding,
			evalGatewayCPUIDRegistry,
			evalGatewayEventLogIntegrity,
		)
	}
	return evals
}

// ---------------------------------------------------------------------------
// Tier 1: Core Attestation evaluators
// ---------------------------------------------------------------------------

func evalNonceMatch(in *ReportInput) []FactorResult {
	if in.Raw.Nonce == "" {
		return factor(TierCore, "nonce_match", Fail, "nonce field absent from attestation response")
	}
	if subtle.ConstantTimeCompare([]byte(in.Raw.Nonce), []byte(in.Nonce.Hex())) != 1 {
		return factor(TierCore, "nonce_match", Fail, fmt.Sprintf("nonce mismatch: got %q, want %q", truncHex(in.Raw.Nonce), truncHex(in.Nonce.Hex())))
	}
	detail := fmt.Sprintf("nonce matches (%d hex chars)", len(in.Raw.Nonce))
	if in.Raw.NonceSource != "" {
		detail += fmt.Sprintf(" (%s-supplied)", in.Raw.NonceSource)
	}
	return factor(TierCore, "nonce_match", Pass, detail)
}
func evalTDXQuotePresent(in *ReportInput) []FactorResult {
	if in.Raw.IntelQuote == "" {
		return factor(TierCore, "tdx_quote_present", Fail, "intel_quote field is absent from attestation response")
	}
	return factor(TierCore, "tdx_quote_present", Pass, fmt.Sprintf("TDX quote present (%d hex chars)", len(in.Raw.IntelQuote)))
}
func evalTDXParseDependent(in *ReportInput) []FactorResult {
	if in.TDX == nil {
		return []FactorResult{
			{Tier: TierCore, Name: "tdx_quote_structure", Status: Fail, Detail: "no TDX quote available to parse"},
			{Tier: TierCore, Name: "tdx_cert_chain", Status: Fail, Detail: "no TDX quote available; cannot verify cert chain"},
			{Tier: TierCore, Name: "tdx_quote_signature", Status: Fail, Detail: "no TDX quote available; cannot verify signature"},
			{Tier: TierCore, Name: "tdx_debug_disabled", Status: Fail, Detail: "no TDX quote available; cannot check debug flag"},
		}
	}

	if in.TDX.ParseErr != nil {
		return []FactorResult{
			{Tier: TierCore, Name: "tdx_quote_structure", Status: Fail, Detail: fmt.Sprintf("TDX quote parse failed: %v", in.TDX.ParseErr)},
			{Tier: TierCore, Name: "tdx_cert_chain", Status: Skip, Detail: "quote parse failed; cert chain not extracted"},
			{Tier: TierCore, Name: "tdx_quote_signature", Status: Skip, Detail: "quote parse failed; signature not verified"},
			{Tier: TierCore, Name: "tdx_debug_disabled", Status: Skip, Detail: "quote parse failed; debug flag not checked"},
		}
	}

	// ParseErr is nil — evaluate each sub-factor directly.
	results := []FactorResult{tdxQuoteStructure(in)}

	if in.TDX.CertChainErr != nil {
		results = append(results, FactorResult{Tier: TierCore, Name: "tdx_cert_chain", Status: Fail, Detail: fmt.Sprintf("cert chain verification failed: %v", in.TDX.CertChainErr)})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: "tdx_cert_chain", Status: Pass, Detail: "certificate chain valid (Intel root CA)"})
	}

	if in.TDX.SignatureErr != nil {
		results = append(results, FactorResult{Tier: TierCore, Name: "tdx_quote_signature", Status: Fail, Detail: fmt.Sprintf("quote signature invalid: %v", in.TDX.SignatureErr)})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: "tdx_quote_signature", Status: Pass, Detail: "quote signature verified"})
	}

	if in.TDX.DebugEnabled {
		results = append(results, FactorResult{Tier: TierCore, Name: "tdx_debug_disabled", Status: Fail, Detail: "TD_ATTRIBUTES debug bit is set — this is a debug enclave; do not trust for production"})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: "tdx_debug_disabled", Status: Pass, Detail: "debug bit is 0 (production enclave)"})
	}

	return results
}

// tdxQuoteStructure evaluates the tdx_quote_structure factor — structural
// validity only. Measurement policy checks are handled by the dedicated
// tdx_mrseam_mrtd, tdx_hardware_config, and tdx_boot_config factors.
// Precondition: in.TDX.ParseErr == nil.
func tdxQuoteStructure(in *ReportInput) FactorResult {
	mrtdHex := hex.EncodeToString(in.TDX.MRTD)

	detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(in.TDX))
	if len(mrtdHex) >= 16 {
		detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(in.TDX), mrtdHex[:16])
	}
	return FactorResult{Tier: TierCore, Name: "tdx_quote_structure", Status: Pass, Detail: detail}
}

// evalTDXMrseamMrtd checks MRSEAM and MRTD against measurement policy
// allowlists. Skips when no policy is configured.
// Precondition: in.TDX != nil && in.TDX.ParseErr == nil.
func evalTDXMrseamMrtd(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierCore, "tdx_mrseam_mrtd", Skip, "no parseable TDX quote; cannot check MRSEAM/MRTD")
	}
	if !in.Policy.HasMRTDPolicy() && !in.Policy.HasMRSeamPolicy() {
		return factor(TierCore, "tdx_mrseam_mrtd", Skip, "no MRSEAM/MRTD measurement policy configured")
	}

	mrtdHex := hex.EncodeToString(in.TDX.MRTD)
	mrSeamHex := hex.EncodeToString(in.TDX.MRSeam)

	if in.Policy.HasMRTDPolicy() && !containsAllowlist(in.Policy.MRTDAllow, mrtdHex) {
		return factor(TierCore, "tdx_mrseam_mrtd", Fail,
			fmt.Sprintf("MRTD not in policy allowlist: %s...", prefixHex(mrtdHex)))
	}
	if in.Policy.HasMRSeamPolicy() && !containsAllowlist(in.Policy.MRSeamAllow, mrSeamHex) {
		return factor(TierCore, "tdx_mrseam_mrtd", Fail,
			fmt.Sprintf("MRSEAM not in policy allowlist: %s...", prefixHex(mrSeamHex)))
	}

	var matched string
	switch {
	case in.Policy.HasMRTDPolicy() && in.Policy.HasMRSeamPolicy():
		matched = "MRTD/MRSEAM"
	case in.Policy.HasMRTDPolicy():
		matched = "MRTD"
	default:
		matched = "MRSEAM"
	}
	return factor(TierCore, "tdx_mrseam_mrtd", Pass, matched+" policy matched")
}

// evalTDXHardwareConfig checks RTMR0 against measurement policy allowlists.
// Skips when no RTMR0 policy is configured.
func evalTDXHardwareConfig(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierCore, "tdx_hardware_config", Skip, "no parseable TDX quote; cannot check RTMR0")
	}
	if !in.Policy.HasRTMRPolicy(0) {
		return factor(TierCore, "tdx_hardware_config", Skip, "no RTMR0 measurement policy configured")
	}
	rtmrHex := hex.EncodeToString(in.TDX.RTMRs[0][:])
	if _, ok := in.Policy.RTMRAllow[0][rtmrHex]; !ok {
		return factor(TierCore, "tdx_hardware_config", Fail,
			fmt.Sprintf("RTMR[0] not in policy allowlist: %s...", prefixHex(rtmrHex)))
	}
	return factor(TierCore, "tdx_hardware_config", Pass, "RTMR0 policy matched")
}

// evalTDXBootConfig checks RTMR1 and RTMR2 against measurement policy
// allowlists. Skips when neither RTMR1 nor RTMR2 policy is configured.
func evalTDXBootConfig(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierCore, "tdx_boot_config", Skip, "no parseable TDX quote; cannot check RTMR1/RTMR2")
	}
	if !in.Policy.HasRTMRPolicy(1) && !in.Policy.HasRTMRPolicy(2) {
		return factor(TierCore, "tdx_boot_config", Skip, "no RTMR1/RTMR2 measurement policy configured")
	}
	for _, i := range []int{1, 2} {
		if !in.Policy.HasRTMRPolicy(i) {
			continue
		}
		rtmrHex := hex.EncodeToString(in.TDX.RTMRs[i][:])
		if _, ok := in.Policy.RTMRAllow[i][rtmrHex]; !ok {
			return factor(TierCore, "tdx_boot_config", Fail,
				fmt.Sprintf("RTMR[%d] not in policy allowlist: %s...", i, prefixHex(rtmrHex)))
		}
	}
	return factor(TierCore, "tdx_boot_config", Pass, "RTMR1/RTMR2 policy matched")
}
func evalSigningKeyPresent(in *ReportInput) []FactorResult {
	if in.Raw.SigningKey == "" {
		return factor(TierCore, "signing_key_present", Fail, "signing_key field absent from attestation response")
	}
	return factor(TierCore, "signing_key_present", Pass, fmt.Sprintf("enclave pubkey present (%s...)", in.Raw.SigningKey[:min(10, len(in.Raw.SigningKey))]))
}

// ---------------------------------------------------------------------------
// Tier 2: Binding & Crypto evaluators
// ---------------------------------------------------------------------------

func evalTDXReportDataBinding(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierBinding, "tdx_reportdata_binding", Fail, "no parseable TDX quote; REPORTDATA binding cannot be verified")
	}
	if in.Raw.SigningKey == "" {
		return factor(TierBinding, "tdx_reportdata_binding", Fail, "enclave public key absent; REPORTDATA binding cannot be verified")
	}
	if in.TDX.ReportDataBindingErr != nil {
		return factor(TierBinding, "tdx_reportdata_binding", Fail, fmt.Sprintf("REPORTDATA does not bind enclave public key: %v", in.TDX.ReportDataBindingErr))
	}
	if in.TDX.ReportDataBindingDetail != "" {
		return factor(TierBinding, "tdx_reportdata_binding", Pass, in.TDX.ReportDataBindingDetail)
	}
	return factor(TierBinding, "tdx_reportdata_binding", Fail, "no REPORTDATA verifier configured for this provider")
}
func evalIntelPCSCollateral(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierBinding, "intel_pcs_collateral", Skip, "no parseable TDX quote")
	}
	if in.TDX.TcbStatus != "" {
		return factor(TierBinding, "intel_pcs_collateral", Pass,
			fmt.Sprintf("Intel PCS collateral fetched (TCB status: %s)", in.TDX.TcbStatus))
	}
	if in.TDX.CollateralErr != nil {
		return factor(TierBinding, "intel_pcs_collateral", Skip,
			fmt.Sprintf("Intel PCS collateral fetch failed: %v", in.TDX.CollateralErr))
	}
	return factor(TierBinding, "intel_pcs_collateral", Skip, "offline mode; Intel PCS collateral not fetched")
}
func evalTDXTCBCurrent(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierBinding, "tdx_tcb_current", Skip, "no parseable TDX quote; TCB SVN not extracted")
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusUpToDate {
		detail := "TCB is UpToDate per Intel PCS"
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (advisories: %s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		return factor(TierBinding, "tdx_tcb_current", Pass, detail)
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusSwHardeningNeeded || in.TDX.TcbStatus == pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded {
		detail := fmt.Sprintf("TCB status: %s — software/config mitigations required for known advisories", in.TDX.TcbStatus)
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		return factor(TierBinding, "tdx_tcb_current", Fail, detail)
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusOutOfDate || in.TDX.TcbStatus == pcs.TcbComponentStatusRevoked || in.TDX.TcbStatus == pcs.TcbComponentStatusOutOfDateConfigurationNeeded {
		detail := fmt.Sprintf("TCB status: %s — firmware has known vulnerabilities", in.TDX.TcbStatus)
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		return factor(TierBinding, "tdx_tcb_current", Fail, detail)
	}
	if in.TDX.CollateralErr != nil {
		svnHex := hex.EncodeToString(in.TDX.TeeTCBSVN)
		return factor(TierBinding, "tdx_tcb_current", Skip,
			fmt.Sprintf("TEE_TCB_SVN: %s (Intel PCS collateral fetch failed: %v)", svnHex, in.TDX.CollateralErr))
	}
	svnHex := hex.EncodeToString(in.TDX.TeeTCBSVN)
	return factor(TierBinding, "tdx_tcb_current", Skip,
		fmt.Sprintf("TEE_TCB_SVN: %s (offline; full check requires Intel PCS)", svnHex))
}
func evalTDXTCBNotRevoked(in *ReportInput) []FactorResult {
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierBinding, "tdx_tcb_not_revoked", Skip, "no parseable TDX quote")
	}
	if in.TDX.TcbStatus == "" {
		if in.TDX.CollateralErr != nil {
			return factor(TierBinding, "tdx_tcb_not_revoked", Skip,
				fmt.Sprintf("Intel PCS collateral fetch failed: %v", in.TDX.CollateralErr))
		}
		return factor(TierBinding, "tdx_tcb_not_revoked", Skip, "offline; Intel PCS collateral not fetched")
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusRevoked {
		return factor(TierBinding, "tdx_tcb_not_revoked", Fail,
			"TCB status: Revoked — Intel has determined this firmware is fundamentally compromised")
	}
	return factor(TierBinding, "tdx_tcb_not_revoked", Pass,
		fmt.Sprintf("TCB status %s is not Revoked", in.TDX.TcbStatus))
}
func evalNvidiaPayloadPresent(in *ReportInput) []FactorResult {
	if in.Raw.NvidiaPayload != "" {
		return factor(TierBinding, "nvidia_payload_present", Pass, fmt.Sprintf("NVIDIA payload present (%d chars)", len(in.Raw.NvidiaPayload)))
	}
	if len(in.Raw.GPUEvidence) > 0 {
		return factor(TierBinding, "nvidia_payload_present", Pass, fmt.Sprintf("GPU evidence present (%d GPUs, SPDM format)", len(in.Raw.GPUEvidence)))
	}
	return factor(TierBinding, "nvidia_payload_present", Fail, "nvidia_payload field is absent from attestation response")
}
func evalNvidiaSignature(in *ReportInput) []FactorResult {
	if in.Nvidia == nil {
		if in.Raw.NvidiaPayload == "" && len(in.Raw.GPUEvidence) == 0 {
			return factor(TierBinding, "nvidia_signature", Skip, "no NVIDIA payload to verify")
		}
		return factor(TierBinding, "nvidia_signature", Fail, "NVIDIA verification was not attempted")
	}
	if in.Nvidia.SignatureErr != nil {
		return factor(TierBinding, "nvidia_signature", Fail, fmt.Sprintf("signature invalid: %v", in.Nvidia.SignatureErr))
	}
	return factor(TierBinding, "nvidia_signature", Pass, nvidiaSignatureDetail(in.Nvidia))
}
func evalNvidiaClaims(in *ReportInput) []FactorResult {
	if in.Nvidia == nil {
		if in.Raw.NvidiaPayload == "" && len(in.Raw.GPUEvidence) == 0 {
			return factor(TierBinding, "nvidia_claims", Skip, "no NVIDIA payload to check")
		}
		return factor(TierBinding, "nvidia_claims", Fail, "NVIDIA verification was not attempted")
	}
	if in.Nvidia.ClaimsErr != nil {
		return factor(TierBinding, "nvidia_claims", Fail, fmt.Sprintf("claims invalid: %v", in.Nvidia.ClaimsErr))
	}
	return factor(TierBinding, "nvidia_claims", Pass, nvidiaClaimsDetail(in.Nvidia))
}
func evalNvidiaClientNonceBound(in *ReportInput) []FactorResult {
	if in.Nvidia == nil {
		if in.Raw.NvidiaPayload == "" && len(in.Raw.GPUEvidence) == 0 {
			return factor(TierBinding, "nvidia_nonce_client_bound", Skip, "no NVIDIA payload; nonce not checked")
		}
		return factor(TierBinding, "nvidia_nonce_client_bound", Skip, "NVIDIA verification not attempted")
	}
	if in.Nvidia.Nonce == "" {
		return factor(TierBinding, "nvidia_nonce_client_bound", Skip, "nonce field not found in NVIDIA payload")
	}
	if subtle.ConstantTimeCompare([]byte(in.Nvidia.Nonce), []byte(in.Nonce.Hex())) == 1 {
		return factor(TierBinding, "nvidia_nonce_client_bound", Pass, nvidiaClientNonceDetail(in.Nvidia))
	}
	return factor(TierBinding, "nvidia_nonce_client_bound", Fail, fmt.Sprintf(
		"NVIDIA nonce mismatch: got %q, want %q",
		truncHex(in.Nvidia.Nonce), truncHex(in.Nonce.Hex())))
}
func evalNvidiaNRASVerified(in *ReportInput) []FactorResult {
	if in.NvidiaNRAS == nil {
		if in.Raw.NvidiaPayload == "" || in.Raw.NvidiaPayload[0] != '{' {
			return factor(TierBinding, "nvidia_nras_verified", Skip, "no EAT payload; NRAS not applicable")
		}
		return factor(TierBinding, "nvidia_nras_verified", Skip, "offline mode; NRAS verification skipped")
	}
	if in.NvidiaNRAS.SignatureErr != nil {
		return factor(TierBinding, "nvidia_nras_verified", Fail,
			fmt.Sprintf("NRAS JWT signature invalid: %v", in.NvidiaNRAS.SignatureErr))
	}
	if in.NvidiaNRAS.ClaimsErr != nil {
		return factor(TierBinding, "nvidia_nras_verified", Fail,
			fmt.Sprintf("NRAS JWT claims invalid: %v", in.NvidiaNRAS.ClaimsErr))
	}
	if !in.NvidiaNRAS.OverallResult {
		return factor(TierBinding, "nvidia_nras_verified", Fail, nrasDiagDetail(in.NvidiaNRAS))
	}
	return factor(TierBinding, "nvidia_nras_verified", Pass, "NRAS: true (JWT verified)")
}

// nrasDiagDetail formats per-GPU diagnostic claims when NRAS overall result is false.
// When all GPUs report the same error, it deduplicates to avoid repetition.
func nrasDiagDetail(r *NvidiaVerifyResult) string {
	if len(r.GPUDiags) == 0 {
		return "NRAS result: false"
	}

	// Check if all GPUs have the same error.
	if allSameError(r.GPUDiags) {
		d := r.GPUDiags[0]
		if d.ErrorDetails != "" {
			return fmt.Sprintf("NRAS result: false; all %d GPUs: %s", len(r.GPUDiags), d.ErrorDetails)
		}
	}

	var b strings.Builder
	b.WriteString("NRAS result: false")
	for i, d := range r.GPUDiags {
		if i >= 8 {
			fmt.Fprintf(&b, "; ... and %d more GPUs", len(r.GPUDiags)-8)
			break
		}
		switch {
		case d.ErrorDetails != "":
			fmt.Fprintf(&b, "; %s: %s", d.GPUID, d.ErrorDetails)
		case d.MeasRes != "":
			fmt.Fprintf(&b, "; %s: measres=%s nonce=%t driver=%s hwmodel=%s",
				d.GPUID, d.MeasRes, d.NonceMatch, d.DriverVersion, d.HWModel)
		default:
			fmt.Fprintf(&b, "; %s: no diagnostic claims", d.GPUID)
		}
	}
	return b.String()
}

func allSameError(diags []NRASGPUDiag) bool {
	if len(diags) < 2 {
		return false
	}
	first := diags[0].ErrorDetails
	for _, d := range diags[1:] {
		if d.ErrorDetails != first {
			return false
		}
	}
	return first != ""
}

func evalE2EECapable(in *ReportInput) []FactorResult {
	switch {
	case in.Raw.SigningKey == "":
		return factor(TierBinding, "e2ee_capable", Fail, "enclave public key absent; E2EE key exchange not possible")
	case in.Raw.SigningAlgo == "ml-kem-768":
		// ML-KEM-768 post-quantum key (1184 bytes, base64-encoded).
		b, err := base64.StdEncoding.DecodeString(in.Raw.SigningKey)
		if err != nil {
			return factor(TierBinding, "e2ee_capable", Fail, fmt.Sprintf("ML-KEM-768 public key invalid base64: %v", err))
		}
		if len(b) != 1184 {
			return factor(TierBinding, "e2ee_capable", Fail, fmt.Sprintf("ML-KEM-768 public key wrong size: %d bytes, want 1184", len(b)))
		}
		return factor(TierBinding, "e2ee_capable", Pass, "ML-KEM-768 public key valid (1184 bytes); post-quantum E2EE key exchange possible")
	case in.Raw.SigningAlgo == "ed25519" || len(in.Raw.SigningKey) == 64:
		// Ed25519 key (64 hex chars).
		if err := validateEd25519Hex(in.Raw.SigningKey); err != nil {
			return factor(TierBinding, "e2ee_capable", Fail, fmt.Sprintf("enclave ed25519 public key invalid: %v", err))
		}
		return factor(TierBinding, "e2ee_capable", Pass, "enclave ed25519 public key valid; E2EE key exchange possible (ed25519)")
	default:
		// secp256k1 key (130 hex chars, uncompressed).
		if err := validateSecp256k1Hex(in.Raw.SigningKey); err != nil {
			return factor(TierBinding, "e2ee_capable", Fail, fmt.Sprintf("enclave public key invalid: %v", err))
		}
		detail := "enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible"
		if in.Raw.SigningAlgo != "" {
			detail += fmt.Sprintf(" (%s)", in.Raw.SigningAlgo)
		}
		return factor(TierBinding, "e2ee_capable", Pass, detail)
	}
}

func evalE2EEUsable(in *ReportInput) []FactorResult {
	if in.E2EETest == nil {
		if in.E2EEConfigured {
			return []FactorResult{{Tier: TierBinding, Name: "e2ee_usable", Status: Skip, Detail: "E2EE configured; pending live test", Deferred: true}}
		}
		return factor(TierBinding, "e2ee_usable", Skip, "E2EE not configured for this provider")
	}
	if in.E2EETest.NoAPIKey {
		env := in.E2EETest.APIKeyEnv
		if env == "" {
			env = "<unknown>"
		}
		return factor(TierBinding, "e2ee_usable", Skip, fmt.Sprintf("API key required ($%s)", env))
	}
	if in.E2EETest.Err != nil {
		return factor(TierBinding, "e2ee_usable", Fail, in.E2EETest.Err.Error())
	}
	if in.E2EETest.Attempted {
		detail := in.E2EETest.Detail
		if detail == "" {
			detail = "E2EE test inference succeeded"
		}
		return factor(TierBinding, "e2ee_usable", Pass, detail)
	}
	// Not attempted but no error — offline or other skip.
	detail := in.E2EETest.Detail
	if detail == "" {
		detail = "E2EE test not attempted"
	}
	return factor(TierBinding, "e2ee_usable", Skip, detail)
}

// validateEd25519Hex checks that s is 64 valid hex characters (32-byte Ed25519
// public key) and that the bytes form a valid point on the Ed25519 curve.
func validateEd25519Hex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("expected 64 hex chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("not valid hex: %w", err)
	}
	if _, err := new(edwards25519.Point).SetBytes(b); err != nil {
		return fmt.Errorf("not a valid ed25519 point: %w", err)
	}
	return nil
}

// validateSecp256k1Hex checks that s is 130 hex characters starting with "04"
// (uncompressed secp256k1 public key format). Full point-on-curve validation
// happens at E2EE session setup time.
func validateSecp256k1Hex(s string) error {
	if len(s) != 130 {
		return fmt.Errorf("expected 130 hex chars, got %d", len(s))
	}
	if s[:2] != "04" {
		return fmt.Errorf("must start with '04' (uncompressed), got %q", s[:2])
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("not valid hex: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tier 3: Supply Chain & Channel Integrity evaluators
// ---------------------------------------------------------------------------

func evalTLSKeyBinding(in *ReportInput) []FactorResult {
	switch {
	case in.Raw.TLSFingerprint != "":
		fpPreview := in.Raw.TLSFingerprint
		if len(fpPreview) > 16 {
			fpPreview = fpPreview[:16] + "..."
		}
		return factor(TierSupplyChain, "tls_key_binding", Pass,
			fmt.Sprintf("TLS certificate SPKI bound to attestation (%s)", fpPreview))
	case in.Raw.SigningKey != "":
		return factor(TierSupplyChain, "tls_key_binding", Skip,
			"provider uses E2EE key exchange; TLS binding not applicable")
	default:
		return factor(TierSupplyChain, "tls_key_binding", Fail,
			"no TLS certificate binding in attestation")
	}
}
func evalCPUGPUChain(_ *ReportInput) []FactorResult {
	return factor(TierSupplyChain, "cpu_gpu_chain", Fail, "CPU-GPU attestation not bound")
}
func evalMeasuredModelWeights(_ *ReportInput) []FactorResult {
	return factor(TierSupplyChain, "measured_model_weights", Fail, "no model weight hashes")
}
func evalBuildTransparencyLog(in *ReportInput) []FactorResult {
	scPolicy := in.SupplyChainPolicy

	if scPolicy != nil {
		if f, done := checkImageRepoPolicy(in, scPolicy); done {
			return []FactorResult{f}
		}
	}

	if len(in.Rekor) == 0 {
		return []FactorResult{buildTransparencyNoRekor(in, scPolicy)}
	}

	return []FactorResult{rekorProvenanceResult(in, scPolicy)}
}

// checkImageRepoPolicy validates model and gateway image repos against the
// supply chain policy. Returns (result, true) on policy violation.
func checkImageRepoPolicy(in *ReportInput, scPolicy *SupplyChainPolicy) (FactorResult, bool) {
	btlFail := FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail}

	if len(in.ImageRepos) == 0 {
		btlFail.Detail = "no attested model image repositories extracted from compose"
		return btlFail, true
	}
	for _, repo := range in.ImageRepos {
		if !scPolicy.AllowedInModel(repo) {
			btlFail.Detail = fmt.Sprintf("model container policy: image %q not in supply chain policy (%s)",
				repo, strings.Join(scPolicy.ModelRepoNames(), ", "))
			return btlFail, true
		}
	}
	if scPolicy.HasGatewayImages() {
		if len(in.GatewayImageRepos) == 0 {
			btlFail.Detail = "no attested gateway image repositories extracted from compose"
			return btlFail, true
		}
		for _, repo := range in.GatewayImageRepos {
			if !scPolicy.AllowedInGateway(repo) {
				btlFail.Detail = fmt.Sprintf("gateway container policy: image %q not in supply chain policy (%s)",
					repo, strings.Join(scPolicy.GatewayRepoNames(), ", "))
				return btlFail, true
			}
		}
	} else if len(in.GatewayImageRepos) > 0 {
		btlFail.Detail = fmt.Sprintf("provider %q has no gateway images in supply chain policy but %d gateway image repos were extracted",
			in.Provider, len(in.GatewayImageRepos))
		return btlFail, true
	}
	return FactorResult{}, false
}

// buildTransparencyNoRekor handles the build_transparency_log factor when
// no Rekor provenance is available.
func buildTransparencyNoRekor(in *ReportInput, scPolicy *SupplyChainPolicy) FactorResult {
	if scPolicy != nil {
		return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
			Detail: "no Rekor provenance fetched for attested image digests"}
	}
	if in.Raw.ComposeHash != "" {
		hashPreview := in.Raw.ComposeHash
		if len(hashPreview) > 8 {
			hashPreview = hashPreview[:8] + "..."
		}
		return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Skip,
			Detail: fmt.Sprintf("compose hash present (%s) but no Rekor provenance fetched", hashPreview)}
	}
	if in.Raw.BackendFormat == FormatChutes {
		return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Skip,
			Detail: "chutes attestation does not include container image metadata; supply chain verification is validator-side only"}
	}
	return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
		Detail: "no build transparency log"}
}

// rekorEntryKind is the classification of a single Rekor provenance entry.
type rekorEntryKind int

const (
	rekorFulcio   rekorEntryKind = iota // Fulcio-signed provenance
	rekorSigstore                       // Sigstore presence only
	rekorFailed                         // policy violation or unexpected signer
)

// classifyRekorEntry classifies a single Rekor entry against the supply chain
// policy. On rekorFailed, failDetail is the error message. On rekorFulcio,
// commitDetail is populated for the first verified entry.
func classifyRekorEntry(r *RekorProvenance, img *ImageProvenance, imageRepo string, scPolicy *SupplyChainPolicy) (kind rekorEntryKind, failDetail string) {
	if r.Err != nil {
		if img != nil && img.Provenance == FulcioSigned {
			return rekorFailed, fmt.Sprintf("image %q: Rekor provenance fetch failed: %v", imageRepo, r.Err)
		}
		return rekorSigstore, ""
	}

	switch {
	case img != nil && img.Provenance == FulcioSigned:
		if detail, failed := verifyFulcioEntry(r, img, imageRepo); failed {
			return rekorFailed, detail
		}
		return rekorFulcio, ""

	case img != nil:
		if img.Provenance == SigstorePresent && img.KeyFingerprint != "" && r.KeyFingerprint != "" {
			fpGot, errG := hex.DecodeString(r.KeyFingerprint)
			fpWant, errW := hex.DecodeString(img.KeyFingerprint)
			if errG != nil || errW != nil || subtle.ConstantTimeCompare(fpGot, fpWant) != 1 {
				return rekorFailed, fmt.Sprintf("image %q: unexpected signing key fingerprint %s (expected %s)",
					imageRepo, truncHex(r.KeyFingerprint), truncHex(img.KeyFingerprint))
			}
		}
		return rekorSigstore, ""

	case scPolicy == nil:
		if !r.HasCert {
			return rekorSigstore, ""
		}
		if r.OIDCIssuer != "https://token.actions.githubusercontent.com" {
			return rekorFailed, "unexpected OIDC issuer: " + r.OIDCIssuer
		}
		return rekorFulcio, ""

	default:
		return rekorFailed, fmt.Sprintf("image %q: not in supply chain policy", imageRepo)
	}
}

// rekorProvenanceResult verifies Rekor provenance entries against the supply
// chain policy.
func rekorProvenanceResult(in *ReportInput, scPolicy *SupplyChainPolicy) FactorResult {
	var fulcioVerified int
	var sigstorePresent int
	var setVerified int
	var inclusionVerified int
	var detail string

	for i := range in.Rekor {
		r := &in.Rekor[i]
		imageRepo := in.DigestToRepo[r.Digest]
		var img *ImageProvenance
		if scPolicy != nil {
			img = scPolicy.Lookup(imageRepo)
		}

		kind, failDetail := classifyRekorEntry(r, img, imageRepo, scPolicy)
		switch kind {
		case rekorFailed:
			return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail, Detail: failDetail}
		case rekorFulcio:
			if r.SETErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
					Detail: fmt.Sprintf("image %q: Rekor SET verification failed: %v", imageRepo, r.SETErr)}
			}
			if r.InclusionErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
					Detail: fmt.Sprintf("image %q: Rekor inclusion proof verification failed: %v", imageRepo, r.InclusionErr)}
			}
			if r.SETVerified {
				setVerified++
			}
			if r.InclusionVerified {
				inclusionVerified++
			}
			fulcioVerified++
			if detail == "" {
				detail = formatRekorCommitDetail(r)
			}
		case rekorSigstore:
			if r.SETErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
					Detail: fmt.Sprintf("image %q: Rekor SET verification failed for Sigstore entry: %v", imageRepo, r.SETErr)}
			}
			if !r.SETVerified {
				return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
					Detail: fmt.Sprintf("image %q: Rekor SET verification did not succeed for Sigstore entry", imageRepo)}
			}
			if r.InclusionErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
					Detail: fmt.Sprintf("image %q: Rekor inclusion proof verification failed for Sigstore entry: %v", imageRepo, r.InclusionErr)}
			}
			if !r.InclusionVerified {
				return FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log", Status: Fail,
					Detail: fmt.Sprintf("image %q: Rekor inclusion proof verification did not succeed for Sigstore entry", imageRepo)}
			}
			setVerified++
			inclusionVerified++
			sigstorePresent++
		}
	}

	return formatBuildTransparencyResult(scPolicy, fulcioVerified, sigstorePresent, setVerified, inclusionVerified, len(in.Rekor), detail)
}

// verifyFulcioEntry checks a single Rekor entry against a FulcioSigned policy.
// Returns (detail, true) on failure.
func verifyFulcioEntry(r *RekorProvenance, img *ImageProvenance, imageRepo string) (string, bool) {
	if r.SignatureErr != nil && !img.NoDSSE {
		return fmt.Sprintf("image %q: DSSE envelope signature verification failed: %v", imageRepo, r.SignatureErr), true
	}
	if !r.HasCert && r.HasNonFulcioCert {
		return fmt.Sprintf("image %q: expected Fulcio certificate but entry has non-Fulcio X.509 cert (no OIDC issuer OID)", imageRepo), true
	}
	if !r.HasCert {
		return fmt.Sprintf("image %q: expected Fulcio certificate but entry has raw key", imageRepo), true
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(strings.TrimSpace(r.OIDCIssuer))),
		[]byte(strings.ToLower(strings.TrimSpace(img.OIDCIssuer))),
	) != 1 {
		return fmt.Sprintf("image %q: unexpected OIDC issuer %q (expected %q)", imageRepo, r.OIDCIssuer, img.OIDCIssuer), true
	}
	if img.OIDCIdentity != "" && subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(strings.TrimSpace(r.SubjectURI))),
		[]byte(strings.ToLower(strings.TrimSpace(img.OIDCIdentity))),
	) != 1 {
		return fmt.Sprintf("image %q: unexpected OIDC identity %q (expected %q)", imageRepo, r.SubjectURI, img.OIDCIdentity), true
	}
	repoID := strings.TrimSpace(r.SourceRepo)
	repoURL := strings.TrimSpace(r.SourceRepoURL)
	if !containsFold(repoID, img.SourceRepos) && !containsFold(repoURL, img.SourceRepos) {
		return fmt.Sprintf("image %q: unexpected source repo %q (expected %v)", imageRepo, repoID, img.SourceRepos), true
	}
	return "", false
}

// formatRekorCommitDetail formats a commit summary from a Rekor provenance entry.
func formatRekorCommitDetail(r *RekorProvenance) string {
	commit := r.SourceCommit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	return fmt.Sprintf("%s@%s, %s", r.SourceRepo, commit, r.RunnerEnv)
}

// formatBuildTransparencyResult produces the final factor result for
// build_transparency_log after processing all Rekor entries.
func formatBuildTransparencyResult(scPolicy *SupplyChainPolicy, fulcioVerified, sigstorePresent, setVerified, inclusionVerified, rekorCount int, detail string) FactorResult {
	f := FactorResult{Tier: TierSupplyChain, Name: "build_transparency_log"}
	logVerify := ""
	if setVerified > 0 || inclusionVerified > 0 {
		verifiedCount := fulcioVerified + sigstorePresent
		logVerify = fmt.Sprintf("; log integrity: SET %d/%d, inclusion %d/%d",
			setVerified, verifiedCount,
			inclusionVerified, verifiedCount)
	}
	switch {
	case scPolicy != nil && fulcioVerified > 0 && sigstorePresent > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d image(s) verified by Fulcio provenance; %d present in Sigstore (%s%s)",
			fulcioVerified, sigstorePresent, detail, logVerify)
	case scPolicy != nil && fulcioVerified > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d image(s) verified by Fulcio provenance (%s%s)", fulcioVerified, detail, logVerify)
	case scPolicy != nil && sigstorePresent > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d image(s) present in Sigstore (no Fulcio provenance%s)", sigstorePresent, logVerify)
	case fulcioVerified > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d/%d image(s) have Sigstore build provenance (%s%s)", fulcioVerified, rekorCount, detail, logVerify)
	default:
		f.Status = Skip
		f.Detail = "all images signed with raw keys (no Fulcio build provenance)"
	}
	return f
}
func evalCPUIDRegistry(in *ReportInput) []FactorResult {
	if in.PoC != nil {
		switch {
		case in.PoC.Registered:
			return factor(TierSupplyChain, "cpu_id_registry", Pass,
				fmt.Sprintf("Proof of Cloud: registered (%s)", in.PoC.Label))
		case in.PoC.Err != nil:
			return factor(TierSupplyChain, "cpu_id_registry", Skip,
				fmt.Sprintf("Proof of Cloud query failed: %v", in.PoC.Err))
		default:
			return factor(TierSupplyChain, "cpu_id_registry", Fail,
				"hardware not found in Proof of Cloud registry; paste intel_quote from --capture at proofofcloud.org to verify")
		}
	}
	if in.TDX != nil && in.TDX.PPID != "" {
		return factor(TierSupplyChain, "cpu_id_registry", Skip,
			fmt.Sprintf("PPID extracted (%s...) but offline; use default mode to check Proof of Cloud",
				in.TDX.PPID[:min(8, len(in.TDX.PPID))]))
	}
	if in.Raw.DeviceID != "" {
		idPreview := in.Raw.DeviceID
		if len(idPreview) > 8 {
			idPreview = idPreview[:8] + "..."
		}
		return factor(TierSupplyChain, "cpu_id_registry", Skip,
			fmt.Sprintf("device ID present (%s) but no registry to verify against", idPreview))
	}
	return factor(TierSupplyChain, "cpu_id_registry", Fail, "no CPU ID registry check")
}
func evalComposeBinding(in *ReportInput) []FactorResult {
	switch {
	case in.Compose == nil || !in.Compose.Checked:
		if in.Raw.BackendFormat == FormatChutes {
			return factor(TierSupplyChain, "compose_binding", Skip, "chutes uses cosign image admission + IMA, not docker-compose; compose binding not applicable")
		}
		return factor(TierSupplyChain, "compose_binding", Skip, "no app_compose in attestation response")
	case in.Compose.Err != nil:
		return factor(TierSupplyChain, "compose_binding", Fail, fmt.Sprintf("compose binding failed: %v", in.Compose.Err))
	default:
		return factor(TierSupplyChain, "compose_binding", Pass, "sha256(app_compose) matches MRConfigID")
	}
}
func evalSigstoreVerification(in *ReportInput) []FactorResult {
	if len(in.Sigstore) == 0 {
		if in.Raw.BackendFormat == FormatChutes {
			return factor(TierSupplyChain, "sigstore_verification", Skip, "chutes attestation does not include container image digests; cosign verification is validator-side only")
		}
		return factor(TierSupplyChain, "sigstore_verification", Skip, "no image digests to verify")
	}

	scPolicy := in.SupplyChainPolicy
	var composeOnly int
	for _, r := range in.Sigstore {
		if r.OK {
			continue
		}
		if scPolicy != nil && len(in.DigestToRepo) > 0 {
			repo := in.DigestToRepo[r.Digest]
			img := scPolicy.Lookup(repo)
			if img != nil && img.Provenance == ComposeBindingOnly {
				composeOnly++
				continue
			}
		}
		var failDetail string
		if r.Err != nil {
			failDetail = r.Err.Error()
		} else {
			failDetail = fmt.Sprintf("HTTP %d", r.Status)
		}
		return factor(TierSupplyChain, "sigstore_verification", Fail,
			fmt.Sprintf("Sigstore check failed for sha256:%s (%s)", r.Digest[:min(16, len(r.Digest))], failDetail))
	}

	inSigstore := len(in.Sigstore) - composeOnly
	if composeOnly > 0 {
		return factor(TierSupplyChain, "sigstore_verification", Pass,
			fmt.Sprintf("%d image digest(s) found in Sigstore transparency log; %d not Sigstore-signed (compose-pinned)", inSigstore, composeOnly))
	}
	return factor(TierSupplyChain, "sigstore_verification", Pass,
		fmt.Sprintf("%d image digest(s) found in Sigstore transparency log", len(in.Sigstore)))
}
func evalEventLogIntegrity(in *ReportInput) []FactorResult {
	if len(in.Raw.EventLog) == 0 {
		if in.Raw.BackendFormat == FormatChutes {
			return factor(TierSupplyChain, "event_log_integrity", Skip, "chutes performs RTMR verification validator-side against a golden baseline; event log not exposed to clients")
		}
		return factor(TierSupplyChain, "event_log_integrity", Skip, "no event log entries in attestation response")
	}
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierSupplyChain, "event_log_integrity", Skip, "no parseable TDX quote; cannot compare RTMRs")
	}

	replayed, err := ReplayEventLog(in.Raw.EventLog)
	if err != nil {
		return factor(TierSupplyChain, "event_log_integrity", Fail, fmt.Sprintf("event log replay failed: %v", err))
	}

	for i := range 4 {
		if replayed[i] != in.TDX.RTMRs[i] {
			return factor(TierSupplyChain, "event_log_integrity", Fail,
				fmt.Sprintf("RTMR[%d] mismatch: replayed %s, quote %s",
					i, hex.EncodeToString(replayed[i][:])[:16]+"...",
					hex.EncodeToString(in.TDX.RTMRs[i][:])[:16]+"..."))
		}
	}

	return factor(TierSupplyChain, "event_log_integrity", Pass,
		fmt.Sprintf("event log replayed (%d entries), all 4 RTMRs match quote", len(in.Raw.EventLog)))
}

// ---------------------------------------------------------------------------
// Tier 4: Gateway Attestation evaluators (nearcloud only)
// ---------------------------------------------------------------------------

func evalGatewayNonceMatch(in *ReportInput) []FactorResult {
	switch {
	case in.GatewayNonceHex == "":
		return factor(TierGateway, "gateway_nonce_match", Fail, "gateway request_nonce absent")
	case subtle.ConstantTimeCompare([]byte(in.GatewayNonceHex), []byte(in.GatewayNonce.Hex())) == 1:
		return factor(TierGateway, "gateway_nonce_match", Pass, fmt.Sprintf("gateway nonce matches (%d hex chars)", len(in.GatewayNonceHex)))
	default:
		return factor(TierGateway, "gateway_nonce_match", Fail, fmt.Sprintf("gateway nonce mismatch: got %q, want %q", truncHex(in.GatewayNonceHex), truncHex(in.GatewayNonce.Hex())))
	}
}
func evalGatewayTDXQuotePresent(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil {
		return factor(TierGateway, "gateway_tdx_quote_present", Fail, "gateway TDX quote not available")
	}
	return factor(TierGateway, "gateway_tdx_quote_present", Pass,
		fmt.Sprintf("gateway TDX quote present (%d hex chars)", len(in.Raw.GatewayIntelQuote)))
}

// Precondition: in.GatewayTDX != nil (guaranteed by buildEvaluators).
func evalGatewayTDXParseDependent(in *ReportInput) []FactorResult {
	if in.GatewayTDX.ParseErr != nil {
		return []FactorResult{
			{Tier: TierGateway, Name: "gateway_tdx_quote_structure", Status: Fail, Detail: fmt.Sprintf("gateway TDX quote parse failed: %v", in.GatewayTDX.ParseErr)},
			{Tier: TierGateway, Name: "gateway_tdx_cert_chain", Status: Skip, Detail: "gateway quote parse failed; cert chain not extracted"},
			{Tier: TierGateway, Name: "gateway_tdx_quote_signature", Status: Skip, Detail: "gateway quote parse failed; signature not verified"},
			{Tier: TierGateway, Name: "gateway_tdx_debug_disabled", Status: Skip, Detail: "gateway quote parse failed; debug flag not checked"},
		}
	}

	results := make([]FactorResult, 0, 4)
	results = append(results, gatewayTDXQuoteStructure(in))

	// gateway_tdx_cert_chain
	if in.GatewayTDX.CertChainErr != nil {
		results = append(results, FactorResult{Tier: TierGateway, Name: "gateway_tdx_cert_chain", Status: Fail, Detail: fmt.Sprintf("gateway cert chain verification failed: %v", in.GatewayTDX.CertChainErr)})
	} else {
		results = append(results, FactorResult{Tier: TierGateway, Name: "gateway_tdx_cert_chain", Status: Pass, Detail: "gateway certificate chain valid (Intel root CA)"})
	}

	// gateway_tdx_quote_signature
	if in.GatewayTDX.SignatureErr != nil {
		results = append(results, FactorResult{Tier: TierGateway, Name: "gateway_tdx_quote_signature", Status: Fail, Detail: fmt.Sprintf("gateway quote signature invalid: %v", in.GatewayTDX.SignatureErr)})
	} else {
		results = append(results, FactorResult{Tier: TierGateway, Name: "gateway_tdx_quote_signature", Status: Pass, Detail: "gateway quote signature verified"})
	}

	// gateway_tdx_debug_disabled
	if in.GatewayTDX.DebugEnabled {
		results = append(results, FactorResult{Tier: TierGateway, Name: "gateway_tdx_debug_disabled", Status: Fail, Detail: "gateway TD_ATTRIBUTES debug bit is set — debug enclave"})
	} else {
		results = append(results, FactorResult{Tier: TierGateway, Name: "gateway_tdx_debug_disabled", Status: Pass, Detail: "gateway debug bit is 0 (production enclave)"})
	}

	return results
}

// gatewayTDXQuoteStructure evaluates the gateway_tdx_quote_structure factor —
// structural validity only. Measurement policy checks are handled by the
// dedicated gateway_tdx_mrseam_mrtd, gateway_tdx_hardware_config, and
// gateway_tdx_boot_config factors.
// Precondition: in.GatewayTDX.ParseErr == nil.
func gatewayTDXQuoteStructure(in *ReportInput) FactorResult {
	mrtdHex := hex.EncodeToString(in.GatewayTDX.MRTD)

	detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(in.GatewayTDX))
	if len(mrtdHex) >= 16 {
		detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(in.GatewayTDX), mrtdHex[:16])
	}
	return FactorResult{Tier: TierGateway, Name: "gateway_tdx_quote_structure", Status: Pass, Detail: detail}
}

// evalGatewayTDXMrseamMrtd checks gateway MRSEAM and MRTD against the
// gateway measurement policy allowlists. Skips when no policy is configured.
func evalGatewayTDXMrseamMrtd(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil || in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, "gateway_tdx_mrseam_mrtd", Skip, "no parseable gateway TDX quote; cannot check MRSEAM/MRTD")
	}
	gp := in.GatewayPolicy
	if !gp.HasMRTDPolicy() && !gp.HasMRSeamPolicy() {
		return factor(TierGateway, "gateway_tdx_mrseam_mrtd", Skip, "no gateway MRSEAM/MRTD measurement policy configured")
	}

	mrtdHex := hex.EncodeToString(in.GatewayTDX.MRTD)
	mrSeamHex := hex.EncodeToString(in.GatewayTDX.MRSeam)

	if gp.HasMRTDPolicy() && !containsAllowlist(gp.MRTDAllow, mrtdHex) {
		return factor(TierGateway, "gateway_tdx_mrseam_mrtd", Fail,
			fmt.Sprintf("gateway MRTD not in policy allowlist: %s...", prefixHex(mrtdHex)))
	}
	if gp.HasMRSeamPolicy() && !containsAllowlist(gp.MRSeamAllow, mrSeamHex) {
		return factor(TierGateway, "gateway_tdx_mrseam_mrtd", Fail,
			fmt.Sprintf("gateway MRSEAM not in policy allowlist: %s...", prefixHex(mrSeamHex)))
	}

	var matched string
	switch {
	case gp.HasMRTDPolicy() && gp.HasMRSeamPolicy():
		matched = "gateway MRTD/MRSEAM"
	case gp.HasMRTDPolicy():
		matched = "gateway MRTD"
	default:
		matched = "gateway MRSEAM"
	}
	return factor(TierGateway, "gateway_tdx_mrseam_mrtd", Pass, matched+" policy matched")
}

// evalGatewayTDXHardwareConfig checks gateway RTMR0 against the gateway
// measurement policy allowlists. Skips when no RTMR0 policy is configured.
func evalGatewayTDXHardwareConfig(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil || in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, "gateway_tdx_hardware_config", Skip, "no parseable gateway TDX quote; cannot check RTMR0")
	}
	gp := in.GatewayPolicy
	if !gp.HasRTMRPolicy(0) {
		return factor(TierGateway, "gateway_tdx_hardware_config", Skip, "no gateway RTMR0 measurement policy configured")
	}
	rtmrHex := hex.EncodeToString(in.GatewayTDX.RTMRs[0][:])
	if _, ok := gp.RTMRAllow[0][rtmrHex]; !ok {
		return factor(TierGateway, "gateway_tdx_hardware_config", Fail,
			fmt.Sprintf("gateway RTMR[0] not in policy allowlist: %s...", prefixHex(rtmrHex)))
	}
	return factor(TierGateway, "gateway_tdx_hardware_config", Pass, "gateway RTMR0 policy matched")
}

// evalGatewayTDXBootConfig checks gateway RTMR1 and RTMR2 against the
// gateway measurement policy allowlists. Skips when neither is configured.
func evalGatewayTDXBootConfig(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil || in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, "gateway_tdx_boot_config", Skip, "no parseable gateway TDX quote; cannot check RTMR1/RTMR2")
	}
	gp := in.GatewayPolicy
	if !gp.HasRTMRPolicy(1) && !gp.HasRTMRPolicy(2) {
		return factor(TierGateway, "gateway_tdx_boot_config", Skip, "no gateway RTMR1/RTMR2 measurement policy configured")
	}
	for _, i := range []int{1, 2} {
		if !gp.HasRTMRPolicy(i) {
			continue
		}
		rtmrHex := hex.EncodeToString(in.GatewayTDX.RTMRs[i][:])
		if _, ok := gp.RTMRAllow[i][rtmrHex]; !ok {
			return factor(TierGateway, "gateway_tdx_boot_config", Fail,
				fmt.Sprintf("gateway RTMR[%d] not in gateway policy allowlist: %s...", i, prefixHex(rtmrHex)))
		}
	}
	return factor(TierGateway, "gateway_tdx_boot_config", Pass, "gateway RTMR1/RTMR2 policy matched")
}
func evalGatewayTDXReportDataBinding(in *ReportInput) []FactorResult {
	switch {
	case in.GatewayTDX.ParseErr != nil:
		return factor(TierGateway, "gateway_tdx_reportdata_binding", Fail,
			"gateway TDX quote parse failed; REPORTDATA binding cannot be verified")
	case in.GatewayTDX.ReportDataBindingErr != nil:
		return factor(TierGateway, "gateway_tdx_reportdata_binding", Fail,
			fmt.Sprintf("gateway REPORTDATA binding failed: %v", in.GatewayTDX.ReportDataBindingErr))
	case in.GatewayTDX.ReportDataBindingDetail != "":
		return factor(TierGateway, "gateway_tdx_reportdata_binding", Pass,
			in.GatewayTDX.ReportDataBindingDetail)
	default:
		return factor(TierGateway, "gateway_tdx_reportdata_binding", Fail,
			"no gateway REPORTDATA verifier ran")
	}
}
func evalGatewayComposeBinding(in *ReportInput) []FactorResult {
	switch {
	case in.GatewayCompose == nil || !in.GatewayCompose.Checked:
		return factor(TierGateway, "gateway_compose_binding", Skip, "no gateway app_compose in attestation response")
	case in.GatewayCompose.Err != nil:
		return factor(TierGateway, "gateway_compose_binding", Fail, fmt.Sprintf("gateway compose binding failed: %v", in.GatewayCompose.Err))
	default:
		return factor(TierGateway, "gateway_compose_binding", Pass, "gateway sha256(app_compose) matches MRConfigID")
	}
}
func evalGatewayCPUIDRegistry(in *ReportInput) []FactorResult {
	if in.GatewayPoC != nil {
		switch {
		case in.GatewayPoC.Registered:
			return factor(TierGateway, "gateway_cpu_id_registry", Pass,
				fmt.Sprintf("gateway Proof of Cloud: registered (%s)", in.GatewayPoC.Label))
		case in.GatewayPoC.Err != nil:
			return factor(TierGateway, "gateway_cpu_id_registry", Skip,
				fmt.Sprintf("gateway Proof of Cloud query failed: %v", in.GatewayPoC.Err))
		default:
			return factor(TierGateway, "gateway_cpu_id_registry", Fail,
				"gateway hardware not found in Proof of Cloud registry; paste gateway intel_quote from --capture at proofofcloud.org to verify")
		}
	}
	if in.GatewayTDX != nil && in.GatewayTDX.PPID != "" {
		return factor(TierGateway, "gateway_cpu_id_registry", Skip,
			fmt.Sprintf("gateway PPID extracted (%s...) but offline; use default mode to check Proof of Cloud",
				in.GatewayTDX.PPID[:min(8, len(in.GatewayTDX.PPID))]))
	}
	return factor(TierGateway, "gateway_cpu_id_registry", Skip,
		"gateway CPU ID registry check not available")
}
func evalGatewayEventLogIntegrity(in *ReportInput) []FactorResult {
	if len(in.GatewayEventLog) == 0 {
		return factor(TierGateway, "gateway_event_log_integrity", Skip, "no gateway event log entries in attestation response")
	}
	if in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, "gateway_event_log_integrity", Skip, "gateway TDX quote not parseable; cannot compare RTMRs")
	}

	replayed, err := ReplayEventLog(in.GatewayEventLog)
	if err != nil {
		return factor(TierGateway, "gateway_event_log_integrity", Fail, fmt.Sprintf("gateway event log replay failed: %v", err))
	}

	for i := range 4 {
		if replayed[i] != in.GatewayTDX.RTMRs[i] {
			return factor(TierGateway, "gateway_event_log_integrity", Fail,
				fmt.Sprintf("gateway RTMR[%d] mismatch: replayed %s, quote %s",
					i, hex.EncodeToString(replayed[i][:])[:16]+"...",
					hex.EncodeToString(in.GatewayTDX.RTMRs[i][:])[:16]+"..."))
		}
	}

	return factor(TierGateway, "gateway_event_log_integrity", Pass,
		fmt.Sprintf("gateway event log replayed (%d entries), all 4 RTMRs match quote", len(in.GatewayEventLog)))
}

// ---------------------------------------------------------------------------
// Supply chain policy types and helpers (unchanged)
// ---------------------------------------------------------------------------

// ProvenanceType describes the expected level of Sigstore/Rekor evidence for
// a container image.
type ProvenanceType int

const (
	// FulcioSigned means the image must have a Fulcio-issued certificate in
	// Rekor with a matching OIDC issuer and source repository.
	FulcioSigned ProvenanceType = iota
	// SigstorePresent means the image has an entry in the Sigstore
	// transparency log but specific signer identity is not checked (raw-key
	// signatures or third-party Fulcio certs such as alpine or datadog/agent).
	SigstorePresent
	// ComposeBindingOnly means the image is not expected to be in Sigstore.
	// Security relies on the pinned digest in the attested compose manifest.
	ComposeBindingOnly
)

func (p ProvenanceType) String() string {
	switch p {
	case FulcioSigned:
		return "fulcio-signed"
	case SigstorePresent:
		return "sigstore-present"
	case ComposeBindingOnly:
		return "compose-binding-only"
	default:
		return "unknown"
	}
}

// ImageProvenance declares the expected supply chain evidence for a single
// container image repository.
type ImageProvenance struct {
	Repo           string         // normalised image repo (e.g. "datadog/agent")
	ModelTier      bool           // allowed in model compose
	GatewayTier    bool           // allowed in gateway compose
	Provenance     ProvenanceType // expected evidence level
	KeyFingerprint string         // SHA-256 hex of PKIX public key; checked for SigstorePresent
	OIDCIssuer     string         // required when Provenance == FulcioSigned
	OIDCIdentity   string         // SAN URI (workflow identity); checked for FulcioSigned
	SourceRepos    []string       // required when Provenance == FulcioSigned (repo ID and/or URL)
	NoDSSE         bool           // true = DSSE envelope lacks signatures; skip DSSE check
}

// SupplyChainPolicy defines the allowed container image repos for a provider.
type SupplyChainPolicy struct {
	Images []ImageProvenance
}

// Lookup returns the ImageProvenance entry for repo, or nil.
func (p *SupplyChainPolicy) Lookup(repo string) *ImageProvenance {
	v := strings.ToLower(strings.TrimSpace(repo))
	for i := range p.Images {
		if strings.ToLower(strings.TrimSpace(p.Images[i].Repo)) == v {
			return &p.Images[i]
		}
	}
	return nil
}

// AllowedInModel reports whether repo has a policy entry permitting model tier.
func (p *SupplyChainPolicy) AllowedInModel(repo string) bool {
	img := p.Lookup(repo)
	return img != nil && img.ModelTier
}

// AllowedInGateway reports whether repo has a policy entry permitting gateway tier.
func (p *SupplyChainPolicy) AllowedInGateway(repo string) bool {
	img := p.Lookup(repo)
	return img != nil && img.GatewayTier
}

// HasGatewayImages reports whether any image in the policy allows gateway tier.
func (p *SupplyChainPolicy) HasGatewayImages() bool {
	for i := range p.Images {
		if p.Images[i].GatewayTier {
			return true
		}
	}
	return false
}

// ModelRepoNames returns model-tier image repository names.
func (p *SupplyChainPolicy) ModelRepoNames() []string {
	var out []string
	for i := range p.Images {
		if p.Images[i].ModelTier {
			out = append(out, p.Images[i].Repo)
		}
	}
	return out
}

// GatewayRepoNames returns gateway-tier image repository names.
func (p *SupplyChainPolicy) GatewayRepoNames() []string {
	var out []string
	for i := range p.Images {
		if p.Images[i].GatewayTier {
			out = append(out, p.Images[i].Repo)
		}
	}
	return out
}

func containsFold(value string, allowed []string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	for _, entry := range allowed {
		if v == strings.ToLower(strings.TrimSpace(entry)) {
			return true
		}
	}
	return false
}

func prefixHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16]
}

func truncHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

func containsAllowlist(m map[string]struct{}, v string) bool {
	_, ok := m[v]
	return ok
}

// tdxQuoteVersion returns a human-readable version string for the parsed TDX quote.
func tdxQuoteVersion(r *TDXVerifyResult) string {
	switch r.quote.(type) {
	case *pb.QuoteV4:
		return "QuoteV4"
	case *pb.QuoteV5:
		return "QuoteV5"
	default:
		return "Quote (unknown version)"
	}
}

// nvidiaSignatureDetail returns the detail string for the nvidia_signature factor.
func nvidiaSignatureDetail(r *NvidiaVerifyResult) string {
	switch r.Format {
	case "EAT":
		return fmt.Sprintf("EAT: %d GPU cert chains and SPDM ECDSA P-384 signatures verified (arch: %s)", r.GPUCount, r.Arch)
	case "JWT":
		return fmt.Sprintf("JWT signature valid (%s)", r.Algorithm)
	default:
		return "signature valid"
	}
}

// nvidiaClaimsDetail returns the detail string for the nvidia_claims factor.
func nvidiaClaimsDetail(r *NvidiaVerifyResult) string {
	switch r.Format {
	case "EAT":
		return fmt.Sprintf("EAT: arch=%s, %d GPUs, nonce verified", r.Arch, r.GPUCount)
	case "JWT":
		return fmt.Sprintf("JWT claims valid (overall result: %t)", r.OverallResult)
	default:
		return "claims valid"
	}
}

// nvidiaClientNonceDetail returns the detail string for a passing nvidia_nonce_client_bound.
func nvidiaClientNonceDetail(r *NvidiaVerifyResult) string {
	switch r.Format {
	case "EAT":
		return fmt.Sprintf("EAT nonce matches client nonce (%d GPUs)", r.GPUCount)
	default:
		return "NVIDIA nonce matches client nonce"
	}
}

// buildMetadata extracts display metadata from raw into an ordered key-value
// map. Only non-empty values are included. The map is used by formatReport
// to render the metadata block between the header and Tier 1.
func buildMetadata(in *ReportInput) map[string]string {
	m := make(map[string]string)

	if in.Raw.TEEHardware != "" {
		m["hardware"] = in.Raw.TEEHardware
	}
	if in.Raw.UpstreamModel != "" {
		m["upstream"] = in.Raw.UpstreamModel
	}
	if in.Raw.AppName != "" {
		m["app"] = in.Raw.AppName
	}
	if in.Raw.ComposeHash != "" {
		m["compose_hash"] = in.Raw.ComposeHash
	}
	if in.Raw.OSImageHash != "" {
		m["os_image"] = in.Raw.OSImageHash
	}
	if in.Raw.DeviceID != "" {
		m["device"] = in.Raw.DeviceID
	}
	if in.TDX != nil && in.TDX.PPID != "" {
		m["ppid"] = in.TDX.PPID
	}
	if in.Raw.NonceSource != "" {
		m["nonce_source"] = in.Raw.NonceSource
	}
	if in.Raw.CandidatesAvail > 0 || in.Raw.CandidatesEval > 0 {
		m["candidates"] = fmt.Sprintf("%d/%d evaluated", in.Raw.CandidatesEval, in.Raw.CandidatesAvail)
	}
	if in.Raw.EventLogCount > 0 {
		m["event_log"] = fmt.Sprintf("%d entries", in.Raw.EventLogCount)
	}

	// Include full TDX measurement register values so operators can
	// identify golden values for allowlist policy configuration.
	if in.TDX != nil && in.TDX.ParseErr == nil {
		if v := hex.EncodeToString(in.TDX.MRSeam); v != "" {
			m["mrseam"] = v
		}
		if v := hex.EncodeToString(in.TDX.MRTD); v != "" {
			m["mrtd"] = v
		}
		for i, rtmr := range in.TDX.RTMRs {
			if v := hex.EncodeToString(rtmr[:]); v != "" {
				m[fmt.Sprintf("rtmr%d", i)] = v
			}
		}
	}

	// Include gateway CVM measurements when present (nearcloud).
	if in.GatewayTDX != nil && in.GatewayTDX.ParseErr == nil {
		if v := hex.EncodeToString(in.GatewayTDX.MRSeam); v != "" {
			m["gateway_mrseam"] = v
		}
		if v := hex.EncodeToString(in.GatewayTDX.MRTD); v != "" {
			m["gateway_mrtd"] = v
		}
		for i, rtmr := range in.GatewayTDX.RTMRs {
			if v := hex.EncodeToString(rtmr[:]); v != "" {
				m[fmt.Sprintf("gateway_rtmr%d", i)] = v
			}
		}
	}

	if len(m) == 0 {
		return nil
	}
	return m
}

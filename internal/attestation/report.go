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
	// NotApplicable means the factor does not apply to this provider's
	// attestation format. Distinct from Skip: NotApplicable factors are
	// excluded from the score denominator and never promoted to Fail.
	NotApplicable
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
	case NotApplicable:
		return "N/A"
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

// Factor name constants.
const (
	FactorNonceMatch           = "nonce_match"
	FactorTEEQuotePresent      = "tee_quote_present"
	FactorTEEQuoteStructure    = "tee_quote_structure"
	FactorTEECertChain         = "tee_cert_chain"
	FactorTEEQuoteSignature    = "tee_quote_signature"
	FactorTEEDebugDisabled     = "tee_debug_disabled"
	FactorTEEMeasurement       = "tee_measurement"
	FactorTEEHardwareConfig    = "tee_hardware_config"
	FactorTEEBootConfig        = "tee_boot_config"
	FactorSigningKeyPresent    = "signing_key_present"
	FactorResponseSchema       = "response_schema"
	FactorTEEReportData        = "tee_reportdata_binding"
	FactorIntelPCSCollateral   = "intel_pcs_collateral"
	FactorTEETCBCurrent        = "tee_tcb_current"
	FactorTEETCBNotRevoked     = "tee_tcb_not_revoked"
	FactorNvidiaPayloadPresent = "nvidia_payload_present"
	FactorNvidiaSignature      = "nvidia_signature"
	FactorNvidiaClaims         = "nvidia_claims"
	FactorNvidiaClientNonce    = "nvidia_nonce_client_bound"
	FactorNvidiaNRAS           = "nvidia_nras_verified"
	FactorE2EECapable          = "e2ee_capable"
	FactorE2EEUsable           = "e2ee_usable"
	FactorTLSKeyBinding        = "tls_key_binding"
	FactorCPUGPUChain          = "cpu_gpu_chain"
	FactorNVSwitchBinding      = "nvswitch_binding"
	FactorMeasuredWeights      = "measured_model_weights"
	FactorBuildTransparency    = "build_transparency_log"
	FactorComponentRecognition = "component_recognition"
	FactorProviderSigner       = "provider_signer_recognition"
	FactorComponentSignature   = "component_signature_recognition"
	FactorCPUIDRegistry        = "cpu_id_registry"
	FactorComposeBinding       = "compose_binding"
	FactorSigstoreVerify       = "sigstore_verification"
	FactorSigstoreCode         = "sigstore_code_verified"
	FactorEventLogIntegrity    = "event_log_integrity"
	FactorGWNonceMatch         = "gateway_nonce_match"
	FactorGWQuotePresent       = "gateway_tee_quote_present"
	FactorGWQuoteStructure     = "gateway_tee_quote_structure"
	FactorGWCertChain          = "gateway_tee_cert_chain"
	FactorGWQuoteSignature     = "gateway_tee_quote_signature"
	FactorGWDebugDisabled      = "gateway_tee_debug_disabled"
	FactorGWMeasurement        = "gateway_tee_measurement"
	FactorGWHardwareConfig     = "gateway_tee_hardware_config"
	FactorGWBootConfig         = "gateway_tee_boot_config"
	FactorGWReportData         = "gateway_tee_reportdata_binding"
	FactorGWComposeBinding     = "gateway_compose_binding"
	FactorGWCPUIDRegistry      = "gateway_cpu_id_registry"
	FactorGWEventLogIntegrity  = "gateway_event_log_integrity"
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
	Title              string            `json:"title,omitempty"` // header label; defaults to "Attestation Report"
	Provider           string            `json:"provider"`
	Model              string            `json:"model"`
	Timestamp          time.Time         `json:"timestamp"`
	Factors            []FactorResult    `json:"factors"`
	Passed             int               `json:"passed"`
	Failed             int               `json:"failed"`
	Skipped            int               `json:"skipped"`
	EnforcedFailed     int               `json:"enforced_failed"`
	AllowedFailed      int               `json:"allowed_failed"`
	NotApplicableCount int               `json:"not_applicable"`
	Metadata           map[string]string `json:"metadata,omitempty"`
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

// ReportDataBindingPassed returns true if the tee_reportdata_binding factor
// passed. Without this, a MITM can substitute the enclave public key and
// E2EE becomes security theater. E2EE must never be activated unless this
// returns true.
func (r *VerificationReport) ReportDataBindingPassed() bool {
	for _, f := range r.Factors {
		if f.Name == FactorTEEReportData {
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
		if r.Factors[i].Name == FactorE2EEUsable {
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
		if r.Factors[i].Name == FactorE2EEUsable {
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
	passed, failed, skipped, notApplicable := 0, 0, 0, 0
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
		case NotApplicable:
			notApplicable++
		}
	}
	r.Passed = passed
	r.Failed = failed
	r.Skipped = skipped
	r.EnforcedFailed = enforcedFailed
	r.AllowedFailed = allowedFailed
	r.NotApplicableCount = notApplicable
}

// DefaultAllowFail lists the factor names that are allowed to fail without
// blocking the proxy. Every factor in KnownFactors that is NOT in this list
// is enforced by default. This inversion is safer than a positive enforce
// list: any new factor added to KnownFactors is automatically enforced
// unless explicitly exempted here.
var DefaultAllowFail = []string{
	FactorTEEQuotePresent,
	FactorTEEQuoteStructure,
	FactorTEEHardwareConfig,
	FactorTEEBootConfig,
	FactorIntelPCSCollateral,
	FactorTEETCBCurrent,
	FactorNvidiaPayloadPresent,
	FactorNvidiaClaims,
	FactorNvidiaNRAS,
	FactorE2EECapable,
	FactorE2EEUsable,
	FactorResponseSchema,
	FactorTLSKeyBinding,
	FactorCPUGPUChain,
	FactorMeasuredWeights,
	FactorComponentRecognition,
	FactorCPUIDRegistry,
	// Gateway factors (nearcloud only).
	FactorGWQuotePresent,
	FactorGWQuoteStructure,
	FactorGWHardwareConfig,
	FactorGWBootConfig,
	FactorGWReportData,
	FactorGWCPUIDRegistry,
}

// NearcloudDefaultAllowFail is the nearcloud-specific default allow_fail list.
// It enforces more factors than the global DefaultAllowFail, reflecting the
// nearcloud provider's stronger attestation support.
var NearcloudDefaultAllowFail = []string{
	FactorTEEHardwareConfig,
	FactorTEEBootConfig,
	FactorCPUGPUChain,
	FactorMeasuredWeights,
	FactorComponentRecognition,
	FactorCPUIDRegistry,
	FactorResponseSchema,
	// Gateway factors (nearcloud only).
	FactorGWHardwareConfig,
	FactorGWBootConfig,
	FactorGWReportData,
	FactorGWCPUIDRegistry,
}

// NeardirectDefaultAllowFail is the neardirect-specific default allow_fail
// list. It enforces more factors than the global DefaultAllowFail, reflecting
// the neardirect provider's stronger attestation support.
var NeardirectDefaultAllowFail = []string{
	FactorTEEHardwareConfig,
	FactorTEEBootConfig,
	FactorCPUGPUChain,
	FactorMeasuredWeights,
	FactorComponentRecognition,
	FactorCPUIDRegistry,
	FactorResponseSchema,
}

// NanoGPTDefaultAllowFail is the nanogpt-specific default allow_fail list.
// NanoGPT currently exposes dstack-style evidence without consistently
// replayable nonce binding, NVIDIA, compose, supply-chain, or event-log
// integrity evidence, so only these known failing factors are allowed.
var NanoGPTDefaultAllowFail = []string{
	FactorNonceMatch,
	FactorTEEMeasurement,
	FactorTEEHardwareConfig,
	FactorTEEBootConfig,
	FactorResponseSchema,
	FactorTEEReportData,
	FactorNvidiaSignature,
	FactorNvidiaClientNonce,
	FactorNvidiaNRAS,
	FactorE2EEUsable,
	FactorTLSKeyBinding,
	FactorCPUGPUChain,
	FactorMeasuredWeights,
	FactorComponentRecognition,
	FactorCPUIDRegistry,
	FactorComposeBinding,
	FactorSigstoreVerify,
	FactorEventLogIntegrity,
}

// PhalaCloudDefaultAllowFail is the phalacloud-specific default allow_fail
// list. PhalaCloud currently routes to backends without consistently
// replayable nonce, NVIDIA, compose, supply-chain, or event-log integrity
// evidence, so only these known failing factors are allowed.
var PhalaCloudDefaultAllowFail = []string{
	FactorNonceMatch,
	FactorTEEMeasurement,
	FactorTEEHardwareConfig,
	FactorTEEBootConfig,
	FactorResponseSchema,
	FactorNvidiaSignature,
	FactorNvidiaClientNonce,
	FactorNvidiaNRAS,
	FactorE2EEUsable,
	FactorTLSKeyBinding,
	FactorCPUGPUChain,
	FactorMeasuredWeights,
	FactorBuildTransparency,
	FactorCPUIDRegistry,
	FactorComposeBinding,
	FactorSigstoreVerify,
	FactorEventLogIntegrity,
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
	FactorTEEHardwareConfig,
	FactorTEEBootConfig,
	FactorNvidiaSignature,
	FactorNvidiaNRAS,
	FactorTLSKeyBinding,
	FactorCPUGPUChain,
	FactorMeasuredWeights,
	FactorComponentRecognition,
	FactorCPUIDRegistry,
	FactorResponseSchema,
}

// TinfoilCloudDefaultAllowFail is the tinfoil_v3_cloud default allow_fail
// list.
// Tinfoil runs its own TEE stack (TDX or SEV-SNP) with Sigstore supply chain
// verification instead of compose-based binding.
//
// REPORTDATA binding and Sigstore code verification are enforced.
// cpu_id_registry is allowed to fail because Tinfoil does not participate in
// Proof of Cloud. intel_pcs_collateral is allowed because SEV-SNP uses AMD
// KDS instead of Intel PCS. SEV-SNP certificate-chain and quote-signature
// checks require hitting kdsintf.amd.com, which is often down or flaky for
// tinfoil_v3_cloud. NVIDIA GPU and CPU-GPU/NVSwitch binding factors are
// reported but currently allowed to fail by default, due to the hashing
// issue documented in docs/attestation_gaps/tinfoil_nvidia_json.md
// response_schema is allowed to fail while Tinfoil V3 attestation schema
// compatibility settles.
// tee_boot_config is enforced: hardware platform measurements (MRTD + RTMR0)
// must match the Sigstore-attested tinfoilsh/hardware-measurements registry
// for TDX enclaves.
var TinfoilCloudDefaultAllowFail = []string{
	FactorCPUIDRegistry,
	FactorIntelPCSCollateral,
	FactorTEECertChain,
	FactorTEEQuoteSignature,
	FactorNvidiaPayloadPresent,
	FactorNvidiaSignature,
	FactorNvidiaClaims,
	FactorCPUGPUChain,
	FactorNVSwitchBinding,
	FactorComponentRecognition,
	FactorResponseSchema,
}

// TinfoilDirectDefaultAllowFail is the tinfoil_v3_direct default allow_fail
// list. Direct inference attests per-model enclaves; NVSwitch binding is
// reported but currently allowed to fail by default. response_schema is
// allowed to fail while Tinfoil V3 attestation schema compatibility settles.
var TinfoilDirectDefaultAllowFail = []string{
	FactorCPUIDRegistry,
	FactorIntelPCSCollateral,
	FactorNVSwitchBinding,
	FactorComponentRecognition,
	FactorResponseSchema,
}

// KnownFactors is the complete set of factor names produced by BuildReport.
// Used by config validation to reject typos in the allow_fail list.
var KnownFactors = []string{
	FactorNonceMatch, FactorTEEQuotePresent, FactorTEEQuoteStructure, FactorTEECertChain,
	FactorTEEQuoteSignature, FactorTEEDebugDisabled,
	FactorTEEMeasurement, FactorTEEHardwareConfig, FactorTEEBootConfig,
	FactorSigningKeyPresent, FactorResponseSchema,
	FactorTEEReportData, FactorIntelPCSCollateral, FactorTEETCBCurrent,
	FactorTEETCBNotRevoked, FactorNvidiaPayloadPresent, FactorNvidiaSignature, FactorNvidiaClaims,
	FactorNvidiaClientNonce, FactorNvidiaNRAS, FactorE2EECapable, FactorE2EEUsable,
	FactorTLSKeyBinding, FactorCPUGPUChain, FactorNVSwitchBinding,
	FactorMeasuredWeights, FactorBuildTransparency, FactorComponentRecognition,
	FactorProviderSigner, FactorComponentSignature, FactorCPUIDRegistry,
	FactorComposeBinding, FactorSigstoreVerify, FactorSigstoreCode, FactorEventLogIntegrity,
	// Gateway factors (nearcloud only).
	FactorGWNonceMatch, FactorGWQuotePresent, FactorGWQuoteStructure,
	FactorGWCertChain, FactorGWQuoteSignature, FactorGWDebugDisabled,
	FactorGWMeasurement, FactorGWHardwareConfig, FactorGWBootConfig,
	FactorGWReportData, FactorGWComposeBinding, FactorGWCPUIDRegistry,
	FactorGWEventLogIntegrity,
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
	FactorIntelPCSCollateral,
	FactorTEETCBCurrent,
	FactorTEETCBNotRevoked,
	FactorNvidiaNRAS,
	FactorE2EEUsable,
	FactorBuildTransparency,
	FactorProviderSigner,
	FactorComponentSignature,
	FactorCPUIDRegistry,
	FactorSigstoreVerify,
	FactorSigstoreCode,
	FactorGWCPUIDRegistry,
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
	"ecdsa":       true,
	"ed25519":     true,
	"ml-kem-768":  true,
	"secp256k1":   true,
	"x25519-hpke": true,
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

// TinfoilComponentResult holds per-component Tinfoil Sigstore verification.
type TinfoilComponentResult struct {
	Repo             string
	SigstoreVerified bool
	SigstoreErr      error
}

// TinfoilSupplyChainResult holds the results of Tinfoil-specific Sigstore
// supply chain verification and code/hardware measurement comparison.
// Nil for non-Tinfoil providers.
type TinfoilSupplyChainResult struct {
	// ComponentRepos are the Tinfoil GitHub repositories whose Sigstore
	// release bundles were verified or attempted for this attestation.
	ComponentRepos []string
	Components     []TinfoilComponentResult

	// SigstoreVerified is true when the Sigstore DSSE bundle was fetched
	// and cryptographically verified for the provider's repo.
	SigstoreVerified bool
	SigstoreDetail   string
	SigstoreErr      error

	// CodeMatch is true when code measurements from the Sigstore predicate
	// match the live enclave measurements.
	CodeMatch       bool
	CodeMatchDetail string
	CodeMatchErr    error

	// HWMatch is the matched hardware measurement entry ID (TDX only).
	// Empty when not applicable (SEV-SNP) or when no match found.
	HWMatch    string
	HWMatchErr error

	// GPUHashBound is true when GPU evidence hash was verified in REPORTDATA.
	GPUHashBound bool

	// NVSwitchHashBound is true when NVSwitch evidence hash was verified in
	// REPORTDATA. Only set for multi-GPU Hopper configs with NVLink.
	NVSwitchHashBound bool

	// NVSwitchExpected is true when the GPU topology requires NVSwitch
	// evidence (8-GPU Hopper). When true and NVSwitchHashBound is false,
	// the NVSwitch evidence hash did not match the raw JSON bytes
	// (server-side bug), but the REPORTDATA hash was still verified using
	// the reported hash value.
	NVSwitchExpected bool

	// TDXPolicyErr is the combined error from Tinfoil-specific TDX policy checks.
	// Nil when platform is SEV-SNP or all checks pass.
	TDXPolicyErr    error
	TDXPolicyDetail string
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
	SEV        *SEVVerifyResult
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

	// TinfoilSC holds Tinfoil-specific Sigstore supply chain results.
	// Nil for non-Tinfoil providers.
	TinfoilSC *TinfoilSupplyChainResult

	// E2EETest is the result of a live E2EE test inference. Nil when
	// the provider is not E2EE-capable or the test was not attempted.
	E2EETest *E2EETestResult

	// E2EEConfigured is true when the provider has E2EE enabled in its
	// configuration. Used by the proxy path where E2EETest is not
	// populated at report-build time but the provider will use E2EE
	// for actual requests. When true and E2EETest is nil, e2ee_usable
	// reports "pending live test" instead of "not configured".
	E2EEConfigured bool

	// Inapplicable maps factor names to reasons they don't apply to this
	// provider's attestation format. Nil means all factors are applicable.
	Inapplicable InapplicableFactors

	// ProviderUsesTLSBinding declares that the provider performs live TLS
	// channel binding. When true, evalTLSKeyBinding fails closed if
	// TLSFingerprint is empty (instead of skipping for E2EE providers).
	ProviderUsesTLSBinding bool
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

	// Override inapplicable factors before Skip→Fail promotion.
	for i := range factors {
		if reason, ok := in.Inapplicable[factors[i].Name]; ok {
			factors[i].Status = NotApplicable
			factors[i].Detail = reason
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

	passed, failed, skipped, notApplicable := 0, 0, 0, 0
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
		case NotApplicable:
			notApplicable++
		}
	}

	return &VerificationReport{
		Provider:           in.Provider,
		Model:              in.Model,
		Timestamp:          time.Now(),
		Factors:            factors,
		Passed:             passed,
		Failed:             failed,
		Skipped:            skipped,
		EnforcedFailed:     enforcedFailed,
		AllowedFailed:      allowedFailed,
		NotApplicableCount: notApplicable,
		Metadata:           buildMetadata(in),
	}
}

// buildEvaluators returns the ordered list of factor evaluators. Gateway
// evaluators are appended only when includeGateway is true.
func buildEvaluators(includeGateway bool) []evaluatorFunc {
	evals := []evaluatorFunc{
		// Tier 1: Core Attestation
		evalNonceMatch,
		evalTEEQuotePresent,
		evalTEEParseDependent,
		evalTEEMeasurement,
		evalTEEHardwareConfig,
		evalTEEBootConfig,
		evalSigningKeyPresent,
		evalResponseSchema,
		// Tier 2: Binding & Crypto
		evalTEEReportDataBinding,
		evalIntelPCSCollateral,
		evalTEETCBCurrent,
		evalTEETCBNotRevoked,
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
		evalNVSwitchBinding,
		evalMeasuredModelWeights,
		evalBuildTransparencyLog,
		evalComponentRecognition,
		evalProviderSignerRecognition,
		evalComponentSignatureRecognition,
		evalCPUIDRegistry,
		evalComposeBinding,
		evalSigstoreVerification,
		evalSigstoreCodeVerified,
		evalEventLogIntegrity,
	}
	if includeGateway {
		evals = append(evals,
			evalGatewayNonceMatch,
			evalGatewayTDXQuotePresent,
			evalGatewayTDXParseDependent,
			evalGatewayTDXMeasurement,
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
		return factor(TierCore, FactorNonceMatch, Fail, "nonce field absent from attestation response")
	}
	if subtle.ConstantTimeCompare([]byte(in.Raw.Nonce), []byte(in.Nonce.Hex())) != 1 {
		return factor(TierCore, FactorNonceMatch, Fail, fmt.Sprintf("nonce mismatch: got %q, want %q", truncHex(in.Raw.Nonce), truncHex(in.Nonce.Hex())))
	}
	detail := fmt.Sprintf("nonce matches (%d hex chars)", len(in.Raw.Nonce))
	if in.Raw.NonceSource != "" {
		detail += fmt.Sprintf(" (%s-supplied)", in.Raw.NonceSource)
	}
	return factor(TierCore, FactorNonceMatch, Pass, detail)
}
func evalTEEQuotePresent(in *ReportInput) []FactorResult {
	if in.Raw.IntelQuote != "" {
		return factor(TierCore, FactorTEEQuotePresent, Pass, fmt.Sprintf("TDX quote present (%d hex chars)", len(in.Raw.IntelQuote)))
	}
	if len(in.Raw.SEVReportBytes) > 0 {
		return factor(TierCore, FactorTEEQuotePresent, Pass, fmt.Sprintf("SEV-SNP report present (%d bytes)", len(in.Raw.SEVReportBytes)))
	}
	return factor(TierCore, FactorTEEQuotePresent, Fail, "no TEE attestation evidence (no intel_quote or sev_report)")
}
func evalTEEParseDependent(in *ReportInput) []FactorResult {
	switch {
	case in.TDX != nil:
		return evalTDXParseDependent(in)
	case in.SEV != nil:
		return evalSEVParseDependent(in)
	default:
		return []FactorResult{
			{Tier: TierCore, Name: FactorTEEQuoteStructure, Status: Fail, Detail: "no TEE quote/report available to parse"},
			{Tier: TierCore, Name: FactorTEECertChain, Status: Fail, Detail: "no TEE quote/report available; cannot verify cert chain"},
			{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Fail, Detail: "no TEE quote/report available; cannot verify signature"},
			{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Fail, Detail: "no TEE quote/report available; cannot check debug flag"},
		}
	}
}

func evalTDXParseDependent(in *ReportInput) []FactorResult {
	if in.TDX.ParseErr != nil {
		return []FactorResult{
			{Tier: TierCore, Name: FactorTEEQuoteStructure, Status: Fail, Detail: fmt.Sprintf("TDX quote parse failed: %v", in.TDX.ParseErr)},
			{Tier: TierCore, Name: FactorTEECertChain, Status: Skip, Detail: "quote parse failed; cert chain not extracted"},
			{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Skip, Detail: "quote parse failed; signature not verified"},
			{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Skip, Detail: "quote parse failed; debug flag not checked"},
		}
	}

	results := []FactorResult{tdxQuoteStructure(in)}

	if in.TDX.CertChainErr != nil {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEECertChain, Status: Fail, Detail: fmt.Sprintf("cert chain verification failed: %v", in.TDX.CertChainErr)})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEECertChain, Status: Pass, Detail: "certificate chain valid (Intel root CA)"})
	}

	if in.TDX.SignatureErr != nil {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Fail, Detail: fmt.Sprintf("quote signature invalid: %v", in.TDX.SignatureErr)})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Pass, Detail: "quote signature verified"})
	}

	if in.TDX.DebugEnabled {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Fail, Detail: "TD_ATTRIBUTES debug bit is set — this is a debug enclave; do not trust for production"})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Pass, Detail: "debug bit is 0 (production enclave)"})
	}

	return results
}

func evalSEVParseDependent(in *ReportInput) []FactorResult {
	if in.SEV.ParseErr != nil {
		return []FactorResult{
			{Tier: TierCore, Name: FactorTEEQuoteStructure, Status: Fail, Detail: fmt.Sprintf("SEV-SNP report parse failed: %v", in.SEV.ParseErr)},
			{Tier: TierCore, Name: FactorTEECertChain, Status: Skip, Detail: "SEV-SNP report parse failed; cert chain not verified"},
			{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Skip, Detail: "SEV-SNP report parse failed; signature not verified"},
			{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Skip, Detail: "SEV-SNP report parse failed; debug flag not checked"},
		}
	}

	measHex := hex.EncodeToString(in.SEV.Measurement)
	results := []FactorResult{
		{Tier: TierCore, Name: FactorTEEQuoteStructure, Status: Pass,
			Detail: fmt.Sprintf("valid SEV-SNP report, measurement: %s...", prefixHex(measHex))},
	}

	switch {
	case in.SEV.CertChainErr != nil:
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEECertChain, Status: Fail,
			Detail: fmt.Sprintf("VCEK cert chain verification failed: %v", in.SEV.CertChainErr)})
	case in.SEV.OnlineVerified:
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEECertChain, Status: Pass,
			Detail: "certificate chain valid (AMD root CA)"})
	default:
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEECertChain, Status: Skip,
			Detail: "offline mode; VCEK cert chain not verified (requires AMD KDS)"})
	}

	switch {
	case in.SEV.SignatureErr != nil:
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Fail,
			Detail: fmt.Sprintf("SEV-SNP report signature invalid: %v", in.SEV.SignatureErr)})
	case in.SEV.OnlineVerified:
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Pass,
			Detail: "SEV-SNP report signature verified"})
	default:
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEQuoteSignature, Status: Skip,
			Detail: "offline mode; SEV-SNP report signature not verified (requires AMD KDS)"})
	}

	if in.SEV.DebugEnabled {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Fail,
			Detail: "SEV-SNP guest policy debug bit is set; do not trust for production"})
	} else {
		results = append(results, FactorResult{Tier: TierCore, Name: FactorTEEDebugDisabled, Status: Pass,
			Detail: "debug bit is 0 (production guest)"})
	}

	return results
}

// tdxQuoteStructure evaluates the tee_quote_structure factor — structural
// validity only. Measurement policy checks are handled by the dedicated
// tee_measurement, tee_hardware_config, and tee_boot_config factors.
// Precondition: in.TDX.ParseErr == nil.
func tdxQuoteStructure(in *ReportInput) FactorResult {
	mrtdHex := hex.EncodeToString(in.TDX.MRTD)

	detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(in.TDX))
	if len(mrtdHex) >= 16 {
		detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(in.TDX), mrtdHex[:16])
	}
	return FactorResult{Tier: TierCore, Name: FactorTEEQuoteStructure, Status: Pass, Detail: detail}
}

func evalTEEMeasurement(in *ReportInput) []FactorResult {
	// Tinfoil supply chain: code measurements verified via Sigstore predicate.
	if in.TinfoilSC != nil {
		if in.TinfoilSC.CodeMatch {
			return factor(TierCore, FactorTEEMeasurement, Pass, in.TinfoilSC.CodeMatchDetail)
		}
		if in.TinfoilSC.CodeMatchErr != nil {
			return factor(TierCore, FactorTEEMeasurement, Fail,
				fmt.Sprintf("Sigstore code measurement mismatch: %v", in.TinfoilSC.CodeMatchErr))
		}
		// Sigstore verification was attempted but code match not set — fall through to policy.
	}

	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		return evalTDXMeasurement(in)
	case in.SEV != nil && in.SEV.ParseErr == nil:
		return evalSEVMeasurement(in)
	default:
		return factor(TierCore, FactorTEEMeasurement, Skip, "no parseable TEE quote/report; cannot check measurements")
	}
}

func evalTDXMeasurement(in *ReportInput) []FactorResult {
	if !in.Policy.HasMRTDPolicy() && !in.Policy.HasMRSeamPolicy() {
		return factor(TierCore, FactorTEEMeasurement, Skip, "no MRSEAM/MRTD measurement policy configured")
	}

	mrtdHex := hex.EncodeToString(in.TDX.MRTD)
	mrSeamHex := hex.EncodeToString(in.TDX.MRSeam)

	if in.Policy.HasMRTDPolicy() && !containsAllowlist(in.Policy.MRTDAllow, mrtdHex) {
		return factor(TierCore, FactorTEEMeasurement, Fail,
			fmt.Sprintf("MRTD not in policy allowlist: %s...", prefixHex(mrtdHex)))
	}
	if in.Policy.HasMRSeamPolicy() && !containsAllowlist(in.Policy.MRSeamAllow, mrSeamHex) {
		return factor(TierCore, FactorTEEMeasurement, Fail,
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
	return factor(TierCore, FactorTEEMeasurement, Pass, matched+" policy matched")
}

func evalSEVMeasurement(in *ReportInput) []FactorResult {
	if !in.Policy.HasMRTDPolicy() {
		return factor(TierCore, FactorTEEMeasurement, Skip, "no measurement policy configured")
	}
	measHex := hex.EncodeToString(in.SEV.Measurement)
	if !containsAllowlist(in.Policy.MRTDAllow, measHex) {
		return factor(TierCore, FactorTEEMeasurement, Fail,
			fmt.Sprintf("SEV-SNP launch measurement not in policy allowlist: %s...", prefixHex(measHex)))
	}
	return factor(TierCore, FactorTEEMeasurement, Pass, "SEV-SNP launch measurement policy matched")
}

func evalTEEHardwareConfig(in *ReportInput) []FactorResult {
	// Tinfoil TDX policy checks (TD_ATTRIBUTES, XFAM, RTMR3, TEE_TCB_SVN, MR registers).
	if in.TinfoilSC != nil && in.TinfoilSC.TDXPolicyDetail != "" {
		if in.TinfoilSC.TDXPolicyErr != nil {
			return factor(TierCore, FactorTEEHardwareConfig, Fail,
				fmt.Sprintf("Tinfoil TDX policy: %v", in.TinfoilSC.TDXPolicyErr))
		}
		return factor(TierCore, FactorTEEHardwareConfig, Pass, in.TinfoilSC.TDXPolicyDetail)
	}

	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		return evalTDXHardwareConfig(in)
	case in.SEV != nil && in.SEV.ParseErr == nil:
		return evalSEVHardwareConfig(in)
	default:
		return factor(TierCore, FactorTEEHardwareConfig, Skip, "no parseable TEE quote/report; cannot check hardware config")
	}
}

func evalTDXHardwareConfig(in *ReportInput) []FactorResult {
	if !in.Policy.HasRTMRPolicy(0) {
		return factor(TierCore, FactorTEEHardwareConfig, Skip, "no RTMR0 measurement policy configured")
	}
	rtmrHex := hex.EncodeToString(in.TDX.RTMRs[0][:])
	if _, ok := in.Policy.RTMRAllow[0][rtmrHex]; !ok {
		return factor(TierCore, FactorTEEHardwareConfig, Fail,
			fmt.Sprintf("RTMR[0] not in policy allowlist: %s...", prefixHex(rtmrHex)))
	}
	return factor(TierCore, FactorTEEHardwareConfig, Pass, "RTMR0 policy matched")
}

func evalSEVHardwareConfig(in *ReportInput) []FactorResult {
	if in.SEV.PolicyErr != nil {
		return factor(TierCore, FactorTEEHardwareConfig, Fail,
			fmt.Sprintf("SEV-SNP guest policy validation failed: %v", in.SEV.PolicyErr))
	}
	return factor(TierCore, FactorTEEHardwareConfig, Pass,
		fmt.Sprintf("SEV-SNP guest policy valid (policy=0x%016x)", in.SEV.GuestPolicy))
}

func evalTEEBootConfig(in *ReportInput) []FactorResult {
	// Tinfoil TDX: hardware measurement match (MRTD + RTMR0).
	if in.TinfoilSC != nil && in.TDX != nil && in.TDX.ParseErr == nil {
		if in.TinfoilSC.HWMatch != "" {
			return factor(TierCore, FactorTEEBootConfig, Pass,
				fmt.Sprintf("hardware measurements matched entry %q", in.TinfoilSC.HWMatch))
		}
		if in.TinfoilSC.HWMatchErr != nil {
			return factor(TierCore, FactorTEEBootConfig, Fail,
				fmt.Sprintf("hardware measurement match: %v", in.TinfoilSC.HWMatchErr))
		}
	}

	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		return evalTDXBootConfig(in)
	case in.SEV != nil && in.SEV.ParseErr == nil:
		// SEV-SNP uses a single launch measurement (checked by tee_measurement)
		// rather than separate boot config registers. There is no additional
		// boot config to verify beyond what tee_measurement already covers.
		return factor(TierCore, FactorTEEBootConfig, Pass,
			"SEV-SNP boot config covered by launch measurement (tee_measurement)")
	default:
		return factor(TierCore, FactorTEEBootConfig, Skip, "no parseable TEE quote/report; cannot check boot config")
	}
}

func evalTDXBootConfig(in *ReportInput) []FactorResult {
	if !in.Policy.HasRTMRPolicy(1) && !in.Policy.HasRTMRPolicy(2) {
		return factor(TierCore, FactorTEEBootConfig, Skip, "no RTMR1/RTMR2 measurement policy configured")
	}
	for _, i := range []int{1, 2} {
		if !in.Policy.HasRTMRPolicy(i) {
			continue
		}
		rtmrHex := hex.EncodeToString(in.TDX.RTMRs[i][:])
		if _, ok := in.Policy.RTMRAllow[i][rtmrHex]; !ok {
			return factor(TierCore, FactorTEEBootConfig, Fail,
				fmt.Sprintf("RTMR[%d] not in policy allowlist: %s...", i, prefixHex(rtmrHex)))
		}
	}
	return factor(TierCore, FactorTEEBootConfig, Pass, "RTMR1/RTMR2 policy matched")
}
func evalSigningKeyPresent(in *ReportInput) []FactorResult {
	if in.Raw.SigningKey == "" {
		return factor(TierCore, FactorSigningKeyPresent, Fail, "signing_key field absent from attestation response")
	}
	return factor(TierCore, FactorSigningKeyPresent, Pass, fmt.Sprintf("enclave pubkey present (%s...)", in.Raw.SigningKey[:min(10, len(in.Raw.SigningKey))]))
}

func evalResponseSchema(in *ReportInput) []FactorResult {
	unknown := in.Raw.UnknownFields
	missing := in.Raw.MissingFields
	if len(unknown) == 0 && len(missing) == 0 {
		return factor(TierCore, FactorResponseSchema, Pass,
			"attestation response matches expected schema")
	}
	var parts []string
	if len(unknown) > 0 {
		parts = append(parts, fmt.Sprintf("unknown fields: %q", unknown))
	}
	if len(missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing fields: %q", missing))
	}
	return factor(TierCore, FactorResponseSchema, Fail, strings.Join(parts, "; "))
}

// ---------------------------------------------------------------------------
// Tier 2: Binding & Crypto evaluators
// ---------------------------------------------------------------------------

func evalTEEReportDataBinding(in *ReportInput) []FactorResult {
	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		return evalTDXReportDataBinding(in)
	case in.SEV != nil && in.SEV.ParseErr == nil:
		return evalSEVReportDataBinding(in)
	default:
		return factor(TierBinding, FactorTEEReportData, Fail,
			"no parseable TEE quote/report; REPORTDATA binding cannot be verified")
	}
}

func evalTDXReportDataBinding(in *ReportInput) []FactorResult {
	if in.Raw.SigningKey == "" {
		return factor(TierBinding, FactorTEEReportData, Fail, "enclave public key absent; REPORTDATA binding cannot be verified")
	}
	if in.TDX.ReportDataBindingErr != nil {
		return factor(TierBinding, FactorTEEReportData, Fail, fmt.Sprintf("REPORTDATA binding failed: %v", in.TDX.ReportDataBindingErr))
	}
	if in.TDX.ReportDataBindingDetail != "" {
		return factor(TierBinding, FactorTEEReportData, Pass, in.TDX.ReportDataBindingDetail)
	}
	return factor(TierBinding, FactorTEEReportData, Fail, "no REPORTDATA verifier configured for this provider")
}

func evalSEVReportDataBinding(in *ReportInput) []FactorResult {
	if in.Raw.SigningKey == "" {
		return factor(TierBinding, FactorTEEReportData, Fail, "enclave public key absent; REPORTDATA binding cannot be verified")
	}
	if in.SEV.ReportDataBindingErr != nil {
		return factor(TierBinding, FactorTEEReportData, Fail, fmt.Sprintf("REPORTDATA binding failed: %v", in.SEV.ReportDataBindingErr))
	}
	if in.SEV.ReportDataBindingDetail != "" {
		return factor(TierBinding, FactorTEEReportData, Pass, in.SEV.ReportDataBindingDetail)
	}
	return factor(TierBinding, FactorTEEReportData, Fail, "no REPORTDATA verifier configured for this provider")
}
func evalIntelPCSCollateral(in *ReportInput) []FactorResult {
	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		// TDX: check Intel PCS collateral.
	case in.SEV != nil:
		return factor(TierBinding, FactorIntelPCSCollateral, Skip,
			"SEV-SNP uses AMD KDS; Intel PCS not applicable")
	default:
		return factor(TierBinding, FactorIntelPCSCollateral, Skip, "no parseable TEE quote/report")
	}
	if in.TDX.TcbStatus != "" {
		return factor(TierBinding, FactorIntelPCSCollateral, Pass,
			fmt.Sprintf("Intel PCS collateral fetched (TCB status: %s)", in.TDX.TcbStatus))
	}
	if in.TDX.CollateralErr != nil {
		return factor(TierBinding, FactorIntelPCSCollateral, Skip,
			fmt.Sprintf("Intel PCS collateral fetch failed: %v", in.TDX.CollateralErr))
	}
	return factor(TierBinding, FactorIntelPCSCollateral, Skip, "offline mode; Intel PCS collateral not fetched")
}
func evalTEETCBCurrent(in *ReportInput) []FactorResult {
	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		return evalTDXTCBCurrent(in)
	case in.SEV != nil && in.SEV.ParseErr == nil:
		return evalSEVTCBCurrent(in)
	default:
		return factor(TierBinding, FactorTEETCBCurrent, Skip, "no parseable TEE quote/report; TCB not extracted")
	}
}

func evalTDXTCBCurrent(in *ReportInput) []FactorResult {
	if in.TDX.TcbStatus == pcs.TcbComponentStatusUpToDate {
		detail := "TCB is UpToDate per Intel PCS"
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (advisories: %s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		return factor(TierBinding, FactorTEETCBCurrent, Pass, detail)
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusSwHardeningNeeded || in.TDX.TcbStatus == pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded {
		detail := fmt.Sprintf("TCB status: %s — software/config mitigations required for known advisories", in.TDX.TcbStatus)
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		return factor(TierBinding, FactorTEETCBCurrent, Fail, detail)
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusOutOfDate || in.TDX.TcbStatus == pcs.TcbComponentStatusRevoked || in.TDX.TcbStatus == pcs.TcbComponentStatusOutOfDateConfigurationNeeded {
		detail := fmt.Sprintf("TCB status: %s — firmware has known vulnerabilities", in.TDX.TcbStatus)
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		return factor(TierBinding, FactorTEETCBCurrent, Fail, detail)
	}
	if in.TDX.CollateralErr != nil {
		svnHex := hex.EncodeToString(in.TDX.TeeTCBSVN)
		return factor(TierBinding, FactorTEETCBCurrent, Skip,
			fmt.Sprintf("TEE_TCB_SVN: %s (Intel PCS collateral fetch failed: %v)", svnHex, in.TDX.CollateralErr))
	}
	svnHex := hex.EncodeToString(in.TDX.TeeTCBSVN)
	return factor(TierBinding, FactorTEETCBCurrent, Skip,
		fmt.Sprintf("TEE_TCB_SVN: %s (offline; full check requires Intel PCS)", svnHex))
}

func evalSEVTCBCurrent(in *ReportInput) []FactorResult {
	if in.SEV.TCBErr != nil {
		return factor(TierBinding, FactorTEETCBCurrent, Fail,
			fmt.Sprintf("SEV-SNP TCB below minimum: %v", in.SEV.TCBErr))
	}
	tcb := in.SEV.CurrentTCB
	return factor(TierBinding, FactorTEETCBCurrent, Pass,
		fmt.Sprintf("SEV-SNP TCB meets minimums (bl=0x%02x tee=0x%02x snp=0x%02x ucode=0x%02x)",
			tcb.BlSpl, tcb.TeeSpl, tcb.SnpSpl, tcb.UcodeSpl))
}

func evalTEETCBNotRevoked(in *ReportInput) []FactorResult {
	switch {
	case in.TDX != nil && in.TDX.ParseErr == nil:
		return evalTDXTCBNotRevoked(in)
	case in.SEV != nil && in.SEV.ParseErr == nil:
		return evalSEVTCBNotRevoked(in)
	default:
		return factor(TierBinding, FactorTEETCBNotRevoked, Skip, "no parseable TEE quote/report")
	}
}

func evalTDXTCBNotRevoked(in *ReportInput) []FactorResult {
	if in.TDX.TcbStatus == "" {
		if in.TDX.CollateralErr != nil {
			return factor(TierBinding, FactorTEETCBNotRevoked, Skip,
				fmt.Sprintf("Intel PCS collateral fetch failed: %v", in.TDX.CollateralErr))
		}
		return factor(TierBinding, FactorTEETCBNotRevoked, Skip, "offline; Intel PCS collateral not fetched")
	}
	if in.TDX.TcbStatus == pcs.TcbComponentStatusRevoked {
		return factor(TierBinding, FactorTEETCBNotRevoked, Fail,
			"TCB status: Revoked — Intel has determined this firmware is fundamentally compromised")
	}
	return factor(TierBinding, FactorTEETCBNotRevoked, Pass,
		fmt.Sprintf("TCB status %s is not Revoked", in.TDX.TcbStatus))
}

func evalSEVTCBNotRevoked(in *ReportInput) []FactorResult {
	if in.SEV.TCBErr != nil {
		return factor(TierBinding, FactorTEETCBNotRevoked, Fail,
			fmt.Sprintf("SEV-SNP TCB validation failed: %v", in.SEV.TCBErr))
	}
	return factor(TierBinding, FactorTEETCBNotRevoked, Pass,
		"SEV-SNP TCB validated against minimum thresholds")
}
func evalNvidiaPayloadPresent(in *ReportInput) []FactorResult {
	if in.Raw.NvidiaPayload != "" {
		return factor(TierBinding, FactorNvidiaPayloadPresent, Pass, fmt.Sprintf("NVIDIA payload present (%d chars)", len(in.Raw.NvidiaPayload)))
	}
	if len(in.Raw.GPUEvidence) > 0 {
		return factor(TierBinding, FactorNvidiaPayloadPresent, Pass, fmt.Sprintf("GPU evidence present (%d GPUs, SPDM format)", len(in.Raw.GPUEvidence)))
	}
	return factor(TierBinding, FactorNvidiaPayloadPresent, Fail, "nvidia_payload field is absent from attestation response")
}
func evalNvidiaSignature(in *ReportInput) []FactorResult {
	if in.Nvidia == nil {
		if in.Raw.NvidiaPayload == "" && len(in.Raw.GPUEvidence) == 0 {
			return factor(TierBinding, FactorNvidiaSignature, Skip, "no NVIDIA payload to verify")
		}
		return factor(TierBinding, FactorNvidiaSignature, Fail, "NVIDIA verification was not attempted")
	}
	if in.Nvidia.SignatureErr != nil {
		return factor(TierBinding, FactorNvidiaSignature, Fail, fmt.Sprintf("signature invalid: %v", in.Nvidia.SignatureErr))
	}
	return factor(TierBinding, FactorNvidiaSignature, Pass, nvidiaSignatureDetail(in.Nvidia))
}
func evalNvidiaClaims(in *ReportInput) []FactorResult {
	if in.Nvidia == nil {
		if in.Raw.NvidiaPayload == "" && len(in.Raw.GPUEvidence) == 0 {
			return factor(TierBinding, FactorNvidiaClaims, Skip, "no NVIDIA payload to check")
		}
		return factor(TierBinding, FactorNvidiaClaims, Fail, "NVIDIA verification was not attempted")
	}
	if in.Nvidia.ClaimsErr != nil {
		return factor(TierBinding, FactorNvidiaClaims, Fail, fmt.Sprintf("claims invalid: %v", in.Nvidia.ClaimsErr))
	}
	return factor(TierBinding, FactorNvidiaClaims, Pass, nvidiaClaimsDetail(in.Nvidia))
}
func evalNvidiaClientNonceBound(in *ReportInput) []FactorResult {
	if in.Nvidia == nil {
		if in.Raw.NvidiaPayload == "" && len(in.Raw.GPUEvidence) == 0 {
			return factor(TierBinding, FactorNvidiaClientNonce, Skip, "no NVIDIA payload; nonce not checked")
		}
		return factor(TierBinding, FactorNvidiaClientNonce, Skip, "NVIDIA verification not attempted")
	}
	if in.Nvidia.Nonce == "" {
		return factor(TierBinding, FactorNvidiaClientNonce, Skip, "nonce field not found in NVIDIA payload")
	}
	if subtle.ConstantTimeCompare([]byte(in.Nvidia.Nonce), []byte(in.Nonce.Hex())) == 1 {
		return factor(TierBinding, FactorNvidiaClientNonce, Pass, nvidiaClientNonceDetail(in.Nvidia))
	}
	return factor(TierBinding, FactorNvidiaClientNonce, Fail, fmt.Sprintf(
		"NVIDIA nonce mismatch: got %q, want %q",
		truncHex(in.Nvidia.Nonce), truncHex(in.Nonce.Hex())))
}
func evalNvidiaNRASVerified(in *ReportInput) []FactorResult {
	if in.NvidiaNRAS == nil {
		if in.Raw.NvidiaPayload == "" || in.Raw.NvidiaPayload[0] != '{' {
			return factor(TierBinding, FactorNvidiaNRAS, Skip, "no EAT payload; NRAS not applicable")
		}
		return factor(TierBinding, FactorNvidiaNRAS, Skip, "offline mode; NRAS verification skipped")
	}
	if in.NvidiaNRAS.SignatureErr != nil {
		return factor(TierBinding, FactorNvidiaNRAS, Fail,
			fmt.Sprintf("NRAS JWT signature invalid: %v", in.NvidiaNRAS.SignatureErr))
	}
	if in.NvidiaNRAS.ClaimsErr != nil {
		return factor(TierBinding, FactorNvidiaNRAS, Fail,
			fmt.Sprintf("NRAS JWT claims invalid: %v", in.NvidiaNRAS.ClaimsErr))
	}
	if !in.NvidiaNRAS.OverallResult {
		return factor(TierBinding, FactorNvidiaNRAS, Fail, nrasDiagDetail(in.NvidiaNRAS))
	}
	return factor(TierBinding, FactorNvidiaNRAS, Pass, "NRAS: true (JWT verified)")
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
		return factor(TierBinding, FactorE2EECapable, Fail, "enclave public key absent; E2EE key exchange not possible")
	case in.Raw.SigningAlgo == "ml-kem-768":
		// ML-KEM-768 post-quantum key (1184 bytes, base64-encoded).
		b, err := base64.StdEncoding.DecodeString(in.Raw.SigningKey)
		if err != nil {
			return factor(TierBinding, FactorE2EECapable, Fail, fmt.Sprintf("ML-KEM-768 public key invalid base64: %v", err))
		}
		if len(b) != 1184 {
			return factor(TierBinding, FactorE2EECapable, Fail, fmt.Sprintf("ML-KEM-768 public key wrong size: %d bytes, want 1184", len(b)))
		}
		return factor(TierBinding, FactorE2EECapable, Pass, "ML-KEM-768 public key valid (1184 bytes); post-quantum E2EE key exchange possible")
	// x25519-hpke must precede ed25519: both are 64 hex chars, but the
	// ed25519 branch uses a length-based fallback (len == 64) that would
	// incorrectly match X25519 keys when SigningAlgo is absent.
	case in.Raw.SigningAlgo == "x25519-hpke":
		// X25519 HPKE key (32 bytes = 64 hex chars).
		if _, err := hex.DecodeString(in.Raw.SigningKey); err != nil {
			return factor(TierBinding, FactorE2EECapable, Fail, fmt.Sprintf("enclave X25519 HPKE key invalid hex: %v", err))
		}
		if len(in.Raw.SigningKey) != 64 {
			return factor(TierBinding, FactorE2EECapable, Fail, fmt.Sprintf("enclave X25519 HPKE key wrong size: %d hex chars, want 64", len(in.Raw.SigningKey)))
		}
		return factor(TierBinding, FactorE2EECapable, Pass, "X25519 HPKE public key valid (32 bytes); EHBP E2EE key exchange possible")
	case in.Raw.SigningAlgo == "ed25519" || len(in.Raw.SigningKey) == 64:
		// Ed25519 key (64 hex chars).
		if err := validateEd25519Hex(in.Raw.SigningKey); err != nil {
			return factor(TierBinding, FactorE2EECapable, Fail, fmt.Sprintf("enclave ed25519 public key invalid: %v", err))
		}
		return factor(TierBinding, FactorE2EECapable, Pass, "enclave ed25519 public key valid; E2EE key exchange possible (ed25519)")
	default:
		// secp256k1 key (130 hex chars, uncompressed).
		if err := validateSecp256k1Hex(in.Raw.SigningKey); err != nil {
			return factor(TierBinding, FactorE2EECapable, Fail, fmt.Sprintf("enclave public key invalid: %v", err))
		}
		detail := "enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible"
		if in.Raw.SigningAlgo != "" {
			detail += fmt.Sprintf(" (%s)", in.Raw.SigningAlgo)
		}
		return factor(TierBinding, FactorE2EECapable, Pass, detail)
	}
}

func evalE2EEUsable(in *ReportInput) []FactorResult {
	if in.E2EETest == nil {
		if in.E2EEConfigured {
			return []FactorResult{{Tier: TierBinding, Name: FactorE2EEUsable, Status: Skip, Detail: "E2EE configured; pending live test", Deferred: true}}
		}
		return factor(TierBinding, FactorE2EEUsable, Skip, "E2EE not configured for this provider")
	}
	if in.E2EETest.NoAPIKey {
		env := in.E2EETest.APIKeyEnv
		if env == "" {
			env = "<unknown>"
		}
		return factor(TierBinding, FactorE2EEUsable, Skip, fmt.Sprintf("API key required ($%s)", env))
	}
	if in.E2EETest.Err != nil {
		return factor(TierBinding, FactorE2EEUsable, Fail, in.E2EETest.Err.Error())
	}
	if in.E2EETest.Attempted {
		detail := in.E2EETest.Detail
		if detail == "" {
			detail = "E2EE test inference succeeded"
		}
		return factor(TierBinding, FactorE2EEUsable, Pass, detail)
	}
	// Not attempted but no error — offline or other skip.
	detail := in.E2EETest.Detail
	if detail == "" {
		detail = "E2EE test not attempted"
	}
	return factor(TierBinding, FactorE2EEUsable, Skip, detail)
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
		return factor(TierSupplyChain, FactorTLSKeyBinding, Pass,
			fmt.Sprintf("TLS certificate SPKI bound to attestation (%s)", fpPreview))
	case in.ProviderUsesTLSBinding:
		// Provider declares live TLS channel binding but the attestation
		// has no TLSFingerprint. This is a hard failure — a provider that
		// should bind TLS must not silently skip it.
		return factor(TierSupplyChain, FactorTLSKeyBinding, Fail,
			"provider declares TLS binding but attestation has no TLS fingerprint")
	case in.Raw.SigningKey != "":
		return factor(TierSupplyChain, FactorTLSKeyBinding, Skip,
			"provider uses E2EE key exchange; TLS binding not applicable")
	default:
		return factor(TierSupplyChain, FactorTLSKeyBinding, Fail,
			"no TLS certificate binding in attestation")
	}
}
func evalCPUGPUChain(in *ReportInput) []FactorResult {
	if in.TinfoilSC != nil && in.TinfoilSC.GPUHashBound {
		return factor(TierSupplyChain, FactorCPUGPUChain, Pass,
			"GPU evidence hash verified in REPORTDATA")
	}
	return factor(TierSupplyChain, FactorCPUGPUChain, Fail, "CPU-GPU attestation not bound")
}
func evalNVSwitchBinding(in *ReportInput) []FactorResult {
	if in.TinfoilSC == nil {
		return factor(TierSupplyChain, FactorNVSwitchBinding, Skip,
			"Tinfoil supply chain not verified")
	}
	if !in.TinfoilSC.GPUHashBound {
		return factor(TierSupplyChain, FactorNVSwitchBinding, Skip,
			"no GPU evidence; NVSwitch check not applicable")
	}
	if in.TinfoilSC.NVSwitchHashBound {
		return factor(TierSupplyChain, FactorNVSwitchBinding, Pass,
			"NVSwitch evidence hash verified in REPORTDATA")
	}
	if in.TinfoilSC.NVSwitchExpected {
		// NVSwitch was expected (8-GPU Hopper) but the evidence hash did
		// not match the raw JSON bytes. This is a server-side bug (JSON
		// re-encoding), but the REPORTDATA hash was still verified using
		// the reported hash value. Fail closed for the NVSwitch binding
		// factor since the evidence hash binding is broken.
		return factor(TierSupplyChain, FactorNVSwitchBinding, Fail,
			"NVSwitch evidence hash mismatch (server-side JSON re-encoding bug)")
	}
	// GPUHashBound but no NVSwitch — topology doesn't require it (< 8 GPUs
	// or Blackwell-only). This is a successful verification outcome: the
	// GPU topology was validated and NVSwitch is correctly absent.
	return factor(TierSupplyChain, FactorNVSwitchBinding, Pass,
		"NVSwitch not required for this GPU topology (verified absent)")
}
func evalMeasuredModelWeights(in *ReportInput) []FactorResult {
	// Tinfoil: dm-verity root hash is part of the Sigstore-verified code
	// measurement. If Sigstore + code measurements pass, model weights are
	// transitively authenticated via the dm-verity chain.
	if in.TinfoilSC != nil && in.TinfoilSC.SigstoreVerified && in.TinfoilSC.CodeMatch {
		return factor(TierSupplyChain, FactorMeasuredWeights, Pass,
			"model weights transitively authenticated via Sigstore + dm-verity code measurements")
	}
	return factor(TierSupplyChain, FactorMeasuredWeights, Fail, "no model weight hashes")
}
func evalBuildTransparencyLog(in *ReportInput) []FactorResult {
	scPolicy := in.SupplyChainPolicy

	if in.TinfoilSC != nil {
		return []FactorResult{tinfoilBuildTransparencyResult(in.TinfoilSC)}
	}

	if len(in.Rekor) == 0 {
		return []FactorResult{buildTransparencyNoRekor(in, scPolicy)}
	}

	return []FactorResult{rekorProvenanceResult(in, scPolicy)}
}

func tinfoilBuildTransparencyResult(sc *TinfoilSupplyChainResult) FactorResult {
	f := FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency}
	if sc.SigstoreErr != nil {
		f.Status = Fail
		f.Detail = fmt.Sprintf("Tinfoil Sigstore supply chain verification failed: %v", sc.SigstoreErr)
		return f
	}
	if !sc.SigstoreVerified {
		f.Status = Fail
		f.Detail = "Tinfoil Sigstore DSSE bundle not verified"
		return f
	}
	f.Status = Pass
	if sc.SigstoreDetail != "" {
		f.Detail = sc.SigstoreDetail
	} else {
		f.Detail = "Tinfoil Sigstore DSSE bundle verified"
	}
	return f
}

// checkComponentRepoPolicy validates compose model and gateway component repos
// against the supply chain policy. Returns (result, true) on policy violation.
func checkComponentRepoPolicy(in *ReportInput, scPolicy *SupplyChainPolicy) (FactorResult, bool) {
	fail := FactorResult{Tier: TierSupplyChain, Name: FactorComponentRecognition, Status: Fail}

	if len(in.ImageRepos) == 0 {
		fail.Detail = "no attested model component repositories extracted from compose"
		return fail, true
	}
	for _, repo := range in.ImageRepos {
		if !scPolicy.AllowedInModel(repo) {
			fail.Detail = fmt.Sprintf("model component %q not recognized for provider/tier (%s)",
				repo, strings.Join(scPolicy.ModelRepoNames(), ", "))
			return fail, true
		}
	}
	if scPolicy.HasGatewayImages() {
		if len(in.GatewayImageRepos) == 0 {
			fail.Detail = "no attested gateway component repositories extracted from compose"
			return fail, true
		}
		for _, repo := range in.GatewayImageRepos {
			if !scPolicy.AllowedInGateway(repo) {
				fail.Detail = fmt.Sprintf("gateway component %q not recognized for provider/tier (%s)",
					repo, strings.Join(scPolicy.GatewayRepoNames(), ", "))
				return fail, true
			}
		}
	} else if len(in.GatewayImageRepos) > 0 {
		fail.Detail = fmt.Sprintf("provider %q has no gateway components in policy but %d gateway component repos were extracted",
			in.Provider, len(in.GatewayImageRepos))
		return fail, true
	}
	return FactorResult{}, false
}

// buildTransparencyNoRekor handles the build_transparency_log factor when
// no Rekor provenance is available.
func buildTransparencyNoRekor(in *ReportInput, scPolicy *SupplyChainPolicy) FactorResult {
	if scPolicy != nil {
		if !scPolicy.HasSignedComponents() {
			return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: NotApplicable,
				Detail: "all configured components are compose-binding-only; no transparency log required"}
		}
		return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
			Detail: "no Rekor provenance fetched for attested component digests"}
	}
	if in.Raw.ComposeHash != "" {
		hashPreview := in.Raw.ComposeHash
		if len(hashPreview) > 8 {
			hashPreview = hashPreview[:8] + "..."
		}
		return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Skip,
			Detail: fmt.Sprintf("compose hash present (%s) but no Rekor provenance fetched", hashPreview)}
	}
	return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
		Detail: "no build transparency log"}
}

// rekorEntryKind is the classification of a single Rekor provenance entry.
type rekorEntryKind int

const (
	rekorFulcio      rekorEntryKind = iota // Fulcio-signed provenance
	rekorSigstore                          // Sigstore presence only
	rekorComposeOnly                       // Compose-bound component; no Rekor proof expected
	rekorFailed                            // policy violation or unexpected signer
)

// classifyRekorEntry classifies a single Rekor entry against the supply chain
// policy. On rekorFailed, failDetail is the error message. On rekorFulcio,
// commitDetail is populated for the first verified entry.
func classifyRekorEntry(r *RekorProvenance, img *ImageProvenance, imageRepo string, scPolicy *SupplyChainPolicy) (kind rekorEntryKind, failDetail string) {
	if img != nil && img.Provenance == ComposeBindingOnly {
		return rekorComposeOnly, ""
	}
	if r.Err != nil {
		return rekorFailed, fmt.Sprintf("component %q: Rekor provenance fetch failed: %v", imageRepo, r.Err)
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
				return rekorFailed, fmt.Sprintf("component %q: unexpected signing key fingerprint %s (expected %s)",
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
		if !r.HasCert {
			return rekorSigstore, ""
		}
		if r.OIDCIssuer != "https://token.actions.githubusercontent.com" {
			return rekorFailed, "unexpected OIDC issuer: " + r.OIDCIssuer
		}
		return rekorFulcio, ""
	}
}

// rekorProvenanceResult verifies Rekor provenance entries against the supply
// chain policy.
func rekorProvenanceResult(in *ReportInput, scPolicy *SupplyChainPolicy) FactorResult {
	var fulcioVerified int
	var sigstorePresent int
	var setVerified int
	var inclusionVerified int
	var composeOnly int
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
			return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail, Detail: failDetail}
		case rekorComposeOnly:
			composeOnly++
		case rekorFulcio:
			if r.SETErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
					Detail: fmt.Sprintf("component %q: Rekor SET verification failed: %v", imageRepo, r.SETErr)}
			}
			if r.InclusionErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
					Detail: fmt.Sprintf("component %q: Rekor inclusion proof verification failed: %v", imageRepo, r.InclusionErr)}
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
				return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
					Detail: fmt.Sprintf("component %q: Rekor SET verification failed for Sigstore entry: %v", imageRepo, r.SETErr)}
			}
			if !r.SETVerified {
				return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
					Detail: fmt.Sprintf("component %q: Rekor SET verification did not succeed for Sigstore entry", imageRepo)}
			}
			if r.InclusionErr != nil {
				return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
					Detail: fmt.Sprintf("component %q: Rekor inclusion proof verification failed for Sigstore entry: %v", imageRepo, r.InclusionErr)}
			}
			if !r.InclusionVerified {
				return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: Fail,
					Detail: fmt.Sprintf("component %q: Rekor inclusion proof verification did not succeed for Sigstore entry", imageRepo)}
			}
			setVerified++
			inclusionVerified++
			sigstorePresent++
		}
	}
	if fulcioVerified+sigstorePresent == 0 && composeOnly > 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency, Status: NotApplicable,
			Detail: fmt.Sprintf("%d compose-binding-only component(s); no transparency log required", composeOnly)}
	}

	return formatBuildTransparencyResult(scPolicy, fulcioVerified, sigstorePresent, setVerified, inclusionVerified, len(in.Rekor), detail)
}

// verifyFulcioEntry checks a single Rekor entry against a FulcioSigned policy.
// Returns (detail, true) on failure.
func verifyFulcioEntry(r *RekorProvenance, img *ImageProvenance, imageRepo string) (string, bool) {
	if r.SignatureErr != nil && !img.NoDSSE {
		return fmt.Sprintf("component %q: DSSE envelope signature verification failed: %v", imageRepo, r.SignatureErr), true
	}
	if !r.HasCert && r.HasNonFulcioCert {
		return fmt.Sprintf("component %q: expected Fulcio certificate but entry has non-Fulcio X.509 cert (no OIDC issuer OID)", imageRepo), true
	}
	if !r.HasCert {
		return fmt.Sprintf("component %q: expected Fulcio certificate but entry has raw key", imageRepo), true
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(strings.TrimSpace(r.OIDCIssuer))),
		[]byte(strings.ToLower(strings.TrimSpace(img.OIDCIssuer))),
	) != 1 {
		return fmt.Sprintf("component %q: unexpected OIDC issuer %q (expected %q)", imageRepo, r.OIDCIssuer, img.OIDCIssuer), true
	}
	if len(img.OIDCIdentities) > 0 {
		if !containsFoldCT(strings.TrimSpace(r.SubjectURI), img.OIDCIdentities) {
			return fmt.Sprintf("component %q: unexpected OIDC identity %q (expected one of %v)", imageRepo, r.SubjectURI, img.OIDCIdentities), true
		}
	} else if img.OIDCIdentity != "" && subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(strings.TrimSpace(r.SubjectURI))),
		[]byte(strings.ToLower(strings.TrimSpace(img.OIDCIdentity))),
	) != 1 {
		return fmt.Sprintf("component %q: unexpected OIDC identity %q (expected %q)", imageRepo, r.SubjectURI, img.OIDCIdentity), true
	}
	repoID := strings.TrimSpace(r.SourceRepo)
	repoURL := strings.TrimSpace(r.SourceRepoURL)
	if !containsFold(repoID, img.SourceRepos) && !containsFold(repoURL, img.SourceRepos) {
		return fmt.Sprintf("component %q: unexpected source repo %q (expected %v)", imageRepo, repoID, img.SourceRepos), true
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
	f := FactorResult{Tier: TierSupplyChain, Name: FactorBuildTransparency}
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
		f.Detail = fmt.Sprintf("%d component(s) verified by Fulcio provenance; %d present in Sigstore (%s%s)",
			fulcioVerified, sigstorePresent, detail, logVerify)
	case scPolicy != nil && fulcioVerified > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d component(s) verified by Fulcio provenance (%s%s)", fulcioVerified, detail, logVerify)
	case scPolicy != nil && sigstorePresent > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d component(s) present in Sigstore (no Fulcio provenance%s)", sigstorePresent, logVerify)
	case fulcioVerified > 0:
		f.Status = Pass
		f.Detail = fmt.Sprintf("%d/%d component(s) have Sigstore build provenance (%s%s)", fulcioVerified, rekorCount, detail, logVerify)
	default:
		f.Status = Skip
		f.Detail = "all components signed with raw keys (no Fulcio build provenance)"
	}
	return f
}

func evalComponentRecognition(in *ReportInput) []FactorResult {
	switch {
	case in.TinfoilSC != nil:
		return []FactorResult{evalTinfoilComponentRecognition(in.TinfoilSC)}
	case in.SupplyChainPolicy != nil:
		return []FactorResult{evalComposeComponentRecognition(in)}
	default:
		return factor(TierSupplyChain, FactorComponentRecognition, NotApplicable,
			"provider has no component supply chain policy")
	}
}

func evalComposeComponentRecognition(in *ReportInput) FactorResult {
	if f, done := checkComponentRepoPolicy(in, in.SupplyChainPolicy); done {
		return f
	}
	f := FactorResult{Tier: TierSupplyChain, Name: FactorComponentRecognition, Status: Pass}
	f.Detail = fmt.Sprintf("%d model component(s) recognized", len(in.ImageRepos))
	if len(in.GatewayImageRepos) > 0 {
		f.Detail += fmt.Sprintf("; %d gateway component(s) recognized", len(in.GatewayImageRepos))
	}
	return f
}

func evalTinfoilComponentRecognition(sc *TinfoilSupplyChainResult) FactorResult {
	repos := tinfoilComponentRepos(sc)
	if len(repos) == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentRecognition, Status: Fail,
			Detail: "no Tinfoil supply chain component repos recorded"}
	}
	for _, repo := range repos {
		if !isTinfoilRecognizedComponent(repo) {
			return FactorResult{Tier: TierSupplyChain, Name: FactorComponentRecognition, Status: Fail,
				Detail: fmt.Sprintf("Tinfoil component repo %q not recognized", repo)}
		}
	}
	return FactorResult{Tier: TierSupplyChain, Name: FactorComponentRecognition, Status: Pass,
		Detail: fmt.Sprintf("%d Tinfoil component repo(s) recognized (%s)",
			len(repos), strings.Join(repos, ", "))}
}

func evalProviderSignerRecognition(in *ReportInput) []FactorResult {
	switch {
	case in.TinfoilSC != nil:
		return []FactorResult{evalTinfoilProviderSignerRecognition(in.TinfoilSC)}
	case in.SupplyChainPolicy != nil:
		return []FactorResult{evalComposeProviderSignerRecognition(in)}
	default:
		return factor(TierSupplyChain, FactorProviderSigner, NotApplicable,
			"provider has no signer supply chain policy")
	}
}

func evalTinfoilProviderSignerRecognition(sc *TinfoilSupplyChainResult) FactorResult {
	repos := tinfoilComponentRepos(sc)
	if len(repos) == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
			Detail: "no Tinfoil signer component repos recorded"}
	}
	for _, repo := range repos {
		if !isTinfoilProviderTrustedSignerRepo(repo) {
			return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
				Detail: fmt.Sprintf("Tinfoil repo %q is not in provider-wide trusted signer namespace", repo)}
		}
	}
	if repo, err := tinfoilComponentVerificationErr(sc); err != nil {
		return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
			Detail: fmt.Sprintf("Tinfoil signer for %q not verified: %v", repo, err)}
	}
	if !tinfoilComponentsVerified(sc) {
		return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
			Detail: "Tinfoil signer not verified"}
	}
	return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Pass,
		Detail: "Tinfoil signer recognized for " + strings.Join(repos, ", ")}
}

func evalComposeProviderSignerRecognition(in *ReportInput) FactorResult {
	scPolicy := in.SupplyChainPolicy
	if !scPolicy.HasSignedComponents() {
		return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: NotApplicable,
			Detail: "no signed components expected by supply chain policy"}
	}
	if len(in.Rekor) == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
			Detail: "no Rekor provenance available for provider signer recognition"}
	}
	checked := 0
	for i := range in.Rekor {
		r := &in.Rekor[i]
		repo, failure := componentRepoForDigest(in, r, FactorProviderSigner)
		if failure != nil {
			return *failure
		}
		img := scPolicy.Lookup(repo)
		if img != nil && img.Provenance == ComposeBindingOnly {
			continue
		}
		if img == nil {
			img = scPolicy.LookupBySignature(r)
		}
		checked++
		if img == nil {
			return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
				Detail: fmt.Sprintf("component %q has no provider-wide signer policy", repo)}
		}
		if !scPolicy.TrustedProviderSigner(img) {
			return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail,
				Detail: fmt.Sprintf("component %q signer is not trusted provider-wide", repo)}
		}
		if detail, failed := verifyComponentSignature(r, img, repo, true); failed {
			return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Fail, Detail: detail}
		}
	}
	if checked == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: NotApplicable,
			Detail: "no signed components present in attested compose"}
	}
	return FactorResult{Tier: TierSupplyChain, Name: FactorProviderSigner, Status: Pass,
		Detail: fmt.Sprintf("%d component signer(s) recognized provider-wide", checked)}
}

func evalComponentSignatureRecognition(in *ReportInput) []FactorResult {
	switch {
	case in.TinfoilSC != nil:
		return []FactorResult{evalTinfoilComponentSignatureRecognition(in.TinfoilSC)}
	case in.SupplyChainPolicy != nil:
		return []FactorResult{evalComposeComponentSignatureRecognition(in)}
	default:
		return factor(TierSupplyChain, FactorComponentSignature, NotApplicable,
			"provider has no component signature policy")
	}
}

func evalTinfoilComponentSignatureRecognition(sc *TinfoilSupplyChainResult) FactorResult {
	repos := tinfoilComponentRepos(sc)
	if len(repos) == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail,
			Detail: "no Tinfoil component signature policy target recorded"}
	}
	for _, repo := range repos {
		if !isTinfoilRecognizedComponent(repo) {
			return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail,
				Detail: fmt.Sprintf("Tinfoil component %q has no recognized signature policy", repo)}
		}
	}
	if repo, err := tinfoilComponentVerificationErr(sc); err != nil {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail,
			Detail: fmt.Sprintf("Tinfoil component %q signature not verified: %v", repo, err)}
	}
	if !tinfoilComponentsVerified(sc) {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail,
			Detail: "Tinfoil component signature not verified"}
	}
	return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Pass,
		Detail: "Tinfoil component signature policy matched for " + strings.Join(repos, ", ")}
}

func evalComposeComponentSignatureRecognition(in *ReportInput) FactorResult {
	scPolicy := in.SupplyChainPolicy
	if !scPolicy.HasSignedComponents() {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: NotApplicable,
			Detail: "no signed components expected by supply chain policy"}
	}
	if len(in.Rekor) == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail,
			Detail: "no Rekor provenance available for component signature recognition"}
	}
	checked := 0
	for i := range in.Rekor {
		r := &in.Rekor[i]
		repo, failure := componentRepoForDigest(in, r, FactorComponentSignature)
		if failure != nil {
			return *failure
		}
		img := scPolicy.Lookup(repo)
		if img != nil && img.Provenance == ComposeBindingOnly {
			continue
		}
		if img == nil {
			img = scPolicy.LookupBySignature(r)
		}
		checked++
		if img == nil {
			return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail,
				Detail: fmt.Sprintf("component %q has no component-specific signature policy", repo)}
		}
		if detail, failed := verifyComponentSignature(r, img, repo, false); failed {
			return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Fail, Detail: detail}
		}
	}
	if checked == 0 {
		return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: NotApplicable,
			Detail: "no signed components present in attested compose"}
	}
	return FactorResult{Tier: TierSupplyChain, Name: FactorComponentSignature, Status: Pass,
		Detail: fmt.Sprintf("%d component signature policy match(es)", checked)}
}

func componentRepoForDigest(in *ReportInput, r *RekorProvenance, factorName string) (string, *FactorResult) {
	repo := strings.TrimSpace(in.DigestToRepo[r.Digest])
	if repo != "" {
		return repo, nil
	}
	return "", &FactorResult{Tier: TierSupplyChain, Name: factorName, Status: Fail,
		Detail: fmt.Sprintf("component digest %q has no associated component repo name", r.Digest)}
}

func verifyComponentSignature(r *RekorProvenance, img *ImageProvenance, repo string, requireProviderSigner bool) (string, bool) {
	if r.Err != nil {
		return fmt.Sprintf("component %q: Rekor provenance fetch failed: %v", repo, r.Err), true
	}
	switch img.Provenance {
	case FulcioSigned:
		return verifyFulcioEntry(r, img, repo)
	case SigstorePresent:
		if img.KeyFingerprint == "" {
			if requireProviderSigner {
				return fmt.Sprintf("component %q: Sigstore-present policy has no provider-wide key or signer identity", repo), true
			}
			return "", false
		}
		if r.KeyFingerprint == "" {
			return fmt.Sprintf("component %q: missing signing key fingerprint", repo), true
		}
		fpGot, errG := hex.DecodeString(r.KeyFingerprint)
		fpWant, errW := hex.DecodeString(img.KeyFingerprint)
		if errG != nil || errW != nil || subtle.ConstantTimeCompare(fpGot, fpWant) != 1 {
			return fmt.Sprintf("component %q: unexpected signing key fingerprint %s (expected %s)",
				repo, truncHex(r.KeyFingerprint), truncHex(img.KeyFingerprint)), true
		}
		return "", false
	default:
		return "", false
	}
}

func isTinfoilRecognizedComponent(repo string) bool {
	repo = strings.ToLower(strings.TrimSpace(repo))
	return repo == "tinfoilsh/hardware-measurements" ||
		repo == "tinfoilsh/confidential-model-router" ||
		strings.HasPrefix(repo, "tinfoilsh/confidential-")
}

func isTinfoilProviderTrustedSignerRepo(repo string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(repo)), "tinfoilsh/")
}

func tinfoilComponentRepos(sc *TinfoilSupplyChainResult) []string {
	if len(sc.Components) == 0 {
		return sc.ComponentRepos
	}
	repos := make([]string, 0, len(sc.Components))
	for _, component := range sc.Components {
		repos = append(repos, component.Repo)
	}
	return repos
}

func tinfoilComponentsVerified(sc *TinfoilSupplyChainResult) bool {
	if len(sc.Components) == 0 {
		return sc.SigstoreVerified
	}
	for _, component := range sc.Components {
		if !component.SigstoreVerified {
			return false
		}
	}
	return true
}

func tinfoilComponentVerificationErr(sc *TinfoilSupplyChainResult) (string, error) {
	if len(sc.Components) == 0 {
		return "", sc.SigstoreErr
	}
	for _, component := range sc.Components {
		if component.SigstoreErr != nil {
			return component.Repo, component.SigstoreErr
		}
	}
	return "", nil
}

func evalCPUIDRegistry(in *ReportInput) []FactorResult {
	if in.PoC != nil {
		switch {
		case in.PoC.Registered:
			return factor(TierSupplyChain, FactorCPUIDRegistry, Pass,
				fmt.Sprintf("Proof of Cloud: registered (%s)", in.PoC.Label))
		case in.PoC.Err != nil:
			return factor(TierSupplyChain, FactorCPUIDRegistry, Skip,
				fmt.Sprintf("Proof of Cloud query failed: %v", in.PoC.Err))
		default:
			return factor(TierSupplyChain, FactorCPUIDRegistry, Fail,
				"hardware not found in Proof of Cloud registry; paste intel_quote from --capture at proofofcloud.org to verify")
		}
	}
	if in.TDX != nil && in.TDX.PPID != "" {
		return factor(TierSupplyChain, FactorCPUIDRegistry, Skip,
			fmt.Sprintf("PPID extracted (%s...) but offline; use default mode to check Proof of Cloud",
				in.TDX.PPID[:min(8, len(in.TDX.PPID))]))
	}
	if in.Raw.DeviceID != "" {
		idPreview := in.Raw.DeviceID
		if len(idPreview) > 8 {
			idPreview = idPreview[:8] + "..."
		}
		return factor(TierSupplyChain, FactorCPUIDRegistry, Skip,
			fmt.Sprintf("device ID present (%s) but no registry to verify against", idPreview))
	}
	return factor(TierSupplyChain, FactorCPUIDRegistry, Fail, "no CPU ID registry check")
}
func evalComposeBinding(in *ReportInput) []FactorResult {
	switch {
	case in.Compose == nil || !in.Compose.Checked:
		return factor(TierSupplyChain, FactorComposeBinding, Skip, "no app_compose in attestation response")
	case in.Compose.Err != nil:
		return factor(TierSupplyChain, FactorComposeBinding, Fail, fmt.Sprintf("compose binding failed: %v", in.Compose.Err))
	default:
		return factor(TierSupplyChain, FactorComposeBinding, Pass, "sha256(app_compose) matches MRConfigID")
	}
}
func evalSigstoreVerification(in *ReportInput) []FactorResult {
	if len(in.Sigstore) == 0 {
		return factor(TierSupplyChain, FactorSigstoreVerify, Skip, "no component digests to verify")
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
		return factor(TierSupplyChain, FactorSigstoreVerify, Fail,
			fmt.Sprintf("Sigstore check failed for sha256:%s (%s)", r.Digest[:min(16, len(r.Digest))], failDetail))
	}

	inSigstore := len(in.Sigstore) - composeOnly
	if composeOnly > 0 {
		return factor(TierSupplyChain, FactorSigstoreVerify, Pass,
			fmt.Sprintf("%d component digest(s) found in Sigstore transparency log; %d not Sigstore-signed (compose-pinned)", inSigstore, composeOnly))
	}
	return factor(TierSupplyChain, FactorSigstoreVerify, Pass,
		fmt.Sprintf("%d component digest(s) found in Sigstore transparency log", len(in.Sigstore)))
}
func evalSigstoreCodeVerified(in *ReportInput) []FactorResult {
	if in.TinfoilSC == nil {
		return factor(TierSupplyChain, FactorSigstoreCode, Skip,
			"Tinfoil supply chain verification not performed")
	}
	if in.TinfoilSC.SigstoreErr != nil {
		return factor(TierSupplyChain, FactorSigstoreCode, Fail,
			fmt.Sprintf("Sigstore verification failed: %v", in.TinfoilSC.SigstoreErr))
	}
	if !in.TinfoilSC.SigstoreVerified {
		return factor(TierSupplyChain, FactorSigstoreCode, Fail,
			"Sigstore DSSE bundle not verified")
	}
	if in.TinfoilSC.CodeMatchErr != nil {
		return factor(TierSupplyChain, FactorSigstoreCode, Fail,
			fmt.Sprintf("code measurement mismatch: %v", in.TinfoilSC.CodeMatchErr))
	}
	if !in.TinfoilSC.CodeMatch {
		return factor(TierSupplyChain, FactorSigstoreCode, Fail,
			"Sigstore verified but code measurements not compared")
	}
	detail := "Sigstore DSSE bundle verified, code measurements match"
	if in.TinfoilSC.SigstoreDetail != "" {
		detail = in.TinfoilSC.SigstoreDetail
	}
	return factor(TierSupplyChain, FactorSigstoreCode, Pass, detail)
}

func evalEventLogIntegrity(in *ReportInput) []FactorResult {
	if len(in.Raw.EventLog) == 0 {
		return factor(TierSupplyChain, FactorEventLogIntegrity, Skip, "no event log entries in attestation response")
	}
	if in.TDX == nil || in.TDX.ParseErr != nil {
		return factor(TierSupplyChain, FactorEventLogIntegrity, Skip, "no parseable TDX quote; cannot compare RTMRs")
	}

	replayed, err := ReplayEventLog(in.Raw.EventLog)
	if err != nil {
		return factor(TierSupplyChain, FactorEventLogIntegrity, Fail, fmt.Sprintf("event log replay failed: %v", err))
	}

	for i := range 4 {
		if replayed[i] != in.TDX.RTMRs[i] {
			return factor(TierSupplyChain, FactorEventLogIntegrity, Fail,
				fmt.Sprintf("RTMR[%d] mismatch: replayed %s, quote %s",
					i, hex.EncodeToString(replayed[i][:])[:16]+"...",
					hex.EncodeToString(in.TDX.RTMRs[i][:])[:16]+"..."))
		}
	}

	return factor(TierSupplyChain, FactorEventLogIntegrity, Pass,
		fmt.Sprintf("event log replayed (%d entries), all 4 RTMRs match quote", len(in.Raw.EventLog)))
}

// ---------------------------------------------------------------------------
// Tier 4: Gateway Attestation evaluators (nearcloud only)
// ---------------------------------------------------------------------------

func evalGatewayNonceMatch(in *ReportInput) []FactorResult {
	switch {
	case in.GatewayNonceHex == "":
		return factor(TierGateway, FactorGWNonceMatch, Fail, "gateway request_nonce absent")
	case subtle.ConstantTimeCompare([]byte(in.GatewayNonceHex), []byte(in.GatewayNonce.Hex())) == 1:
		return factor(TierGateway, FactorGWNonceMatch, Pass, fmt.Sprintf("gateway nonce matches (%d hex chars)", len(in.GatewayNonceHex)))
	default:
		return factor(TierGateway, FactorGWNonceMatch, Fail, fmt.Sprintf("gateway nonce mismatch: got %q, want %q", truncHex(in.GatewayNonceHex), truncHex(in.GatewayNonce.Hex())))
	}
}
func evalGatewayTDXQuotePresent(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil {
		return factor(TierGateway, FactorGWQuotePresent, Fail, "gateway TDX quote not available")
	}
	return factor(TierGateway, FactorGWQuotePresent, Pass,
		fmt.Sprintf("gateway TDX quote present (%d hex chars)", len(in.Raw.GatewayIntelQuote)))
}

// Precondition: in.GatewayTDX != nil (guaranteed by buildEvaluators).
func evalGatewayTDXParseDependent(in *ReportInput) []FactorResult {
	if in.GatewayTDX.ParseErr != nil {
		return []FactorResult{
			{Tier: TierGateway, Name: FactorGWQuoteStructure, Status: Fail, Detail: fmt.Sprintf("gateway TDX quote parse failed: %v", in.GatewayTDX.ParseErr)},
			{Tier: TierGateway, Name: FactorGWCertChain, Status: Skip, Detail: "gateway quote parse failed; cert chain not extracted"},
			{Tier: TierGateway, Name: FactorGWQuoteSignature, Status: Skip, Detail: "gateway quote parse failed; signature not verified"},
			{Tier: TierGateway, Name: FactorGWDebugDisabled, Status: Skip, Detail: "gateway quote parse failed; debug flag not checked"},
		}
	}

	results := make([]FactorResult, 0, 4)
	results = append(results, gatewayTDXQuoteStructure(in))

	// gateway_tee_cert_chain
	if in.GatewayTDX.CertChainErr != nil {
		results = append(results, FactorResult{Tier: TierGateway, Name: FactorGWCertChain, Status: Fail, Detail: fmt.Sprintf("gateway cert chain verification failed: %v", in.GatewayTDX.CertChainErr)})
	} else {
		results = append(results, FactorResult{Tier: TierGateway, Name: FactorGWCertChain, Status: Pass, Detail: "gateway certificate chain valid (Intel root CA)"})
	}

	// gateway_tee_quote_signature
	if in.GatewayTDX.SignatureErr != nil {
		results = append(results, FactorResult{Tier: TierGateway, Name: FactorGWQuoteSignature, Status: Fail, Detail: fmt.Sprintf("gateway quote signature invalid: %v", in.GatewayTDX.SignatureErr)})
	} else {
		results = append(results, FactorResult{Tier: TierGateway, Name: FactorGWQuoteSignature, Status: Pass, Detail: "gateway quote signature verified"})
	}

	// gateway_tee_debug_disabled
	if in.GatewayTDX.DebugEnabled {
		results = append(results, FactorResult{Tier: TierGateway, Name: FactorGWDebugDisabled, Status: Fail, Detail: "gateway TD_ATTRIBUTES debug bit is set — debug enclave"})
	} else {
		results = append(results, FactorResult{Tier: TierGateway, Name: FactorGWDebugDisabled, Status: Pass, Detail: "gateway debug bit is 0 (production enclave)"})
	}

	return results
}

// gatewayTDXQuoteStructure evaluates the gateway_tee_quote_structure factor —
// structural validity only. Measurement policy checks are handled by the
// dedicated gateway_tee_measurement, gateway_tee_hardware_config, and
// gateway_tee_boot_config factors.
// Precondition: in.GatewayTDX.ParseErr == nil.
func gatewayTDXQuoteStructure(in *ReportInput) FactorResult {
	mrtdHex := hex.EncodeToString(in.GatewayTDX.MRTD)

	detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(in.GatewayTDX))
	if len(mrtdHex) >= 16 {
		detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(in.GatewayTDX), mrtdHex[:16])
	}
	return FactorResult{Tier: TierGateway, Name: FactorGWQuoteStructure, Status: Pass, Detail: detail}
}

// evalGatewayTDXMeasurement checks gateway MRSEAM and MRTD against the
// gateway measurement policy allowlists. Skips when no policy is configured.
func evalGatewayTDXMeasurement(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil || in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, FactorGWMeasurement, Skip, "no parseable gateway TDX quote; cannot check MRSEAM/MRTD")
	}
	gp := in.GatewayPolicy
	if !gp.HasMRTDPolicy() && !gp.HasMRSeamPolicy() {
		return factor(TierGateway, FactorGWMeasurement, Skip, "no gateway MRSEAM/MRTD measurement policy configured")
	}

	mrtdHex := hex.EncodeToString(in.GatewayTDX.MRTD)
	mrSeamHex := hex.EncodeToString(in.GatewayTDX.MRSeam)

	if gp.HasMRTDPolicy() && !containsAllowlist(gp.MRTDAllow, mrtdHex) {
		return factor(TierGateway, FactorGWMeasurement, Fail,
			fmt.Sprintf("gateway MRTD not in policy allowlist: %s...", prefixHex(mrtdHex)))
	}
	if gp.HasMRSeamPolicy() && !containsAllowlist(gp.MRSeamAllow, mrSeamHex) {
		return factor(TierGateway, FactorGWMeasurement, Fail,
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
	return factor(TierGateway, FactorGWMeasurement, Pass, matched+" policy matched")
}

// evalGatewayTDXHardwareConfig checks gateway RTMR0 against the gateway
// measurement policy allowlists. Skips when no RTMR0 policy is configured.
func evalGatewayTDXHardwareConfig(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil || in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, FactorGWHardwareConfig, Skip, "no parseable gateway TDX quote; cannot check RTMR0")
	}
	gp := in.GatewayPolicy
	if !gp.HasRTMRPolicy(0) {
		return factor(TierGateway, FactorGWHardwareConfig, Skip, "no gateway RTMR0 measurement policy configured")
	}
	rtmrHex := hex.EncodeToString(in.GatewayTDX.RTMRs[0][:])
	if _, ok := gp.RTMRAllow[0][rtmrHex]; !ok {
		return factor(TierGateway, FactorGWHardwareConfig, Fail,
			fmt.Sprintf("gateway RTMR[0] not in policy allowlist: %s...", prefixHex(rtmrHex)))
	}
	return factor(TierGateway, FactorGWHardwareConfig, Pass, "gateway RTMR0 policy matched")
}

// evalGatewayTDXBootConfig checks gateway RTMR1 and RTMR2 against the
// gateway measurement policy allowlists. Skips when neither is configured.
func evalGatewayTDXBootConfig(in *ReportInput) []FactorResult {
	if in.GatewayTDX == nil || in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, FactorGWBootConfig, Skip, "no parseable gateway TDX quote; cannot check RTMR1/RTMR2")
	}
	gp := in.GatewayPolicy
	if !gp.HasRTMRPolicy(1) && !gp.HasRTMRPolicy(2) {
		return factor(TierGateway, FactorGWBootConfig, Skip, "no gateway RTMR1/RTMR2 measurement policy configured")
	}
	for _, i := range []int{1, 2} {
		if !gp.HasRTMRPolicy(i) {
			continue
		}
		rtmrHex := hex.EncodeToString(in.GatewayTDX.RTMRs[i][:])
		if _, ok := gp.RTMRAllow[i][rtmrHex]; !ok {
			return factor(TierGateway, FactorGWBootConfig, Fail,
				fmt.Sprintf("gateway RTMR[%d] not in gateway policy allowlist: %s...", i, prefixHex(rtmrHex)))
		}
	}
	return factor(TierGateway, FactorGWBootConfig, Pass, "gateway RTMR1/RTMR2 policy matched")
}
func evalGatewayTDXReportDataBinding(in *ReportInput) []FactorResult {
	switch {
	case in.GatewayTDX.ParseErr != nil:
		return factor(TierGateway, FactorGWReportData, Fail,
			"gateway TDX quote parse failed; REPORTDATA binding cannot be verified")
	case in.GatewayTDX.ReportDataBindingErr != nil:
		return factor(TierGateway, FactorGWReportData, Fail,
			fmt.Sprintf("gateway REPORTDATA binding failed: %v", in.GatewayTDX.ReportDataBindingErr))
	case in.GatewayTDX.ReportDataBindingDetail != "":
		return factor(TierGateway, FactorGWReportData, Pass,
			in.GatewayTDX.ReportDataBindingDetail)
	default:
		return factor(TierGateway, FactorGWReportData, Fail,
			"no gateway REPORTDATA verifier ran")
	}
}
func evalGatewayComposeBinding(in *ReportInput) []FactorResult {
	switch {
	case in.GatewayCompose == nil || !in.GatewayCompose.Checked:
		return factor(TierGateway, FactorGWComposeBinding, Skip, "no gateway app_compose in attestation response")
	case in.GatewayCompose.Err != nil:
		return factor(TierGateway, FactorGWComposeBinding, Fail, fmt.Sprintf("gateway compose binding failed: %v", in.GatewayCompose.Err))
	default:
		return factor(TierGateway, FactorGWComposeBinding, Pass, "gateway sha256(app_compose) matches MRConfigID")
	}
}
func evalGatewayCPUIDRegistry(in *ReportInput) []FactorResult {
	if in.GatewayPoC != nil {
		switch {
		case in.GatewayPoC.Registered:
			return factor(TierGateway, FactorGWCPUIDRegistry, Pass,
				fmt.Sprintf("gateway Proof of Cloud: registered (%s)", in.GatewayPoC.Label))
		case in.GatewayPoC.Err != nil:
			return factor(TierGateway, FactorGWCPUIDRegistry, Skip,
				fmt.Sprintf("gateway Proof of Cloud query failed: %v", in.GatewayPoC.Err))
		default:
			return factor(TierGateway, FactorGWCPUIDRegistry, Fail,
				"gateway hardware not found in Proof of Cloud registry; paste gateway intel_quote from --capture at proofofcloud.org to verify")
		}
	}
	if in.GatewayTDX != nil && in.GatewayTDX.PPID != "" {
		return factor(TierGateway, FactorGWCPUIDRegistry, Skip,
			fmt.Sprintf("gateway PPID extracted (%s...) but offline; use default mode to check Proof of Cloud",
				in.GatewayTDX.PPID[:min(8, len(in.GatewayTDX.PPID))]))
	}
	return factor(TierGateway, FactorGWCPUIDRegistry, Skip,
		"gateway CPU ID registry check not available")
}
func evalGatewayEventLogIntegrity(in *ReportInput) []FactorResult {
	if len(in.GatewayEventLog) == 0 {
		return factor(TierGateway, FactorGWEventLogIntegrity, Skip, "no gateway event log entries in attestation response")
	}
	if in.GatewayTDX.ParseErr != nil {
		return factor(TierGateway, FactorGWEventLogIntegrity, Skip, "gateway TDX quote not parseable; cannot compare RTMRs")
	}

	replayed, err := ReplayEventLog(in.GatewayEventLog)
	if err != nil {
		return factor(TierGateway, FactorGWEventLogIntegrity, Fail, fmt.Sprintf("gateway event log replay failed: %v", err))
	}

	for i := range 4 {
		if replayed[i] != in.GatewayTDX.RTMRs[i] {
			return factor(TierGateway, FactorGWEventLogIntegrity, Fail,
				fmt.Sprintf("gateway RTMR[%d] mismatch: replayed %s, quote %s",
					i, hex.EncodeToString(replayed[i][:])[:16]+"...",
					hex.EncodeToString(in.GatewayTDX.RTMRs[i][:])[:16]+"..."))
		}
	}

	return factor(TierGateway, FactorGWEventLogIntegrity, Pass,
		fmt.Sprintf("gateway event log replayed (%d entries), all 4 RTMRs match quote", len(in.GatewayEventLog)))
}

// ---------------------------------------------------------------------------
// Supply chain policy types and helpers (unchanged)
// ---------------------------------------------------------------------------

// ProvenanceType describes the expected level of Sigstore/Rekor evidence for
// a supply-chain component.
type ProvenanceType int

const (
	// FulcioSigned means the component must have a Fulcio-issued certificate in
	// Rekor with a matching OIDC issuer and source repository.
	FulcioSigned ProvenanceType = iota
	// SigstorePresent means the component has an entry in the Sigstore
	// transparency log but specific signer identity is not checked (raw-key
	// signatures or third-party Fulcio certs such as alpine or datadog/agent).
	SigstorePresent
	// ComposeBindingOnly means the component is not expected to be in Sigstore.
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
	OIDCIdentities []string       // optional allowlist of SAN URIs; if set, any matching identity is accepted
	SourceRepos    []string       // required when Provenance == FulcioSigned (repo ID and/or URL)
	NoDSSE         bool           // true = DSSE envelope lacks signatures; skip DSSE check
	// ProviderSignerTrusted marks this image's signer as trusted provider-wide.
	// FulcioSigned entries with source repo policy and SigstorePresent entries
	// with a key fingerprint are trusted provider-wide by default.
	ProviderSignerTrusted bool
}

// SupplyChainPolicy defines the allowed container image repos for a provider.
type SupplyChainPolicy struct {
	Images []ImageProvenance
}

// TrustedProviderSigner reports whether img has a signer policy strong enough
// to be treated as provider-wide trust.
func (p *SupplyChainPolicy) TrustedProviderSigner(img *ImageProvenance) bool {
	if img == nil {
		return false
	}
	if img.ProviderSignerTrusted {
		return true
	}
	switch img.Provenance {
	case FulcioSigned:
		return img.OIDCIssuer != "" && (img.OIDCIdentity != "" || len(img.OIDCIdentities) > 0) && len(img.SourceRepos) > 0
	case SigstorePresent:
		return img.KeyFingerprint != ""
	default:
		return false
	}
}

// HasSignedComponents reports whether any component in the policy expects
// transparency-log signature evidence.
func (p *SupplyChainPolicy) HasSignedComponents() bool {
	for i := range p.Images {
		if p.Images[i].Provenance != ComposeBindingOnly {
			return true
		}
	}
	return false
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

// LookupBySignature returns the first policy entry whose component-specific
// signature policy matches r. It is used for repo renames where the component
// name is not yet recognized but the signer/source policy is known.
func (p *SupplyChainPolicy) LookupBySignature(r *RekorProvenance) *ImageProvenance {
	for i := range p.Images {
		img := &p.Images[i]
		if img.Provenance == ComposeBindingOnly {
			continue
		}
		if img.Provenance == SigstorePresent && img.KeyFingerprint == "" {
			continue
		}
		if _, failed := verifyComponentSignature(r, img, img.Repo, false); !failed {
			return img
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

func containsFoldCT(value string, allowed []string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false
	}
	for _, entry := range allowed {
		e := strings.ToLower(strings.TrimSpace(entry))
		if subtle.ConstantTimeCompare([]byte(v), []byte(e)) == 1 {
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

	// Include SEV-SNP measurement metadata.
	if in.SEV != nil && in.SEV.ParseErr == nil {
		m["sev_measurement"] = hex.EncodeToString(in.SEV.Measurement)
		m["sev_guest_policy"] = fmt.Sprintf("0x%016x", in.SEV.GuestPolicy)
		tcb := in.SEV.CurrentTCB
		m["sev_tcb"] = fmt.Sprintf("bl=0x%02x tee=0x%02x snp=0x%02x ucode=0x%02x",
			tcb.BlSpl, tcb.TeeSpl, tcb.SnpSpl, tcb.UcodeSpl)
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

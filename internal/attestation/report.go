package attestation

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

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

// FactorResult records the outcome of one verification factor.
type FactorResult struct {
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Enforced bool   `json:"enforced"` // from policy config
}

// VerificationReport holds the factor-by-factor results of an attestation
// verification run. Produced by BuildReport.
type VerificationReport struct {
	Provider  string            `json:"provider"`
	Model     string            `json:"model"`
	Timestamp time.Time         `json:"timestamp"`
	Factors   []FactorResult    `json:"factors"`
	Passed    int               `json:"passed"`
	Failed    int               `json:"failed"`
	Skipped   int               `json:"skipped"`
	Metadata  map[string]string `json:"metadata,omitempty"`
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

// DefaultEnforced lists the factor names that block the proxy on failure.
// These are the minimum checks required for E2EE security. See the plan for
// rationale; notably tdx_reportdata_binding is critical — without it, a MITM
// can substitute the signing key and intercept all E2EE traffic.
var DefaultEnforced = []string{
	"nonce_match",
	"tdx_debug_disabled",
	"signing_key_present",
	"tdx_reportdata_binding",
}

// KnownFactors is the complete set of factor names produced by BuildReport.
// Used by config validation to reject typos in the enforce policy.
var KnownFactors = []string{
	"nonce_match", "tdx_quote_present", "tdx_quote_structure", "tdx_cert_chain",
	"tdx_quote_signature", "tdx_debug_disabled", "signing_key_present",
	"tdx_reportdata_binding", "intel_pcs_collateral", "tdx_tcb_current",
	"nvidia_payload_present", "nvidia_signature", "nvidia_claims", "nvidia_nonce_match",
	"nvidia_nras_verified", "e2ee_capable", "tls_key_binding", "cpu_gpu_chain",
	"measured_model_weights", "build_transparency_log", "cpu_id_registry",
}

// BuildReport runs all 21 verification factors against raw and returns a
// complete VerificationReport. The enforced parameter controls which factor
// names result in Enforced=true. Pass DefaultEnforced for production use.
//
// TDX quote verification (factors 3-6, 8, 10) uses the parsed quote from
// VerifyTDXQuote. NVIDIA verification (factors 12-15) uses VerifyNVIDIAPayload
// and VerifyNVIDIANRAS. Tier 3 factors (17-21) always Fail because no vendor
// currently provides the required supply-chain data.
func BuildReport(provider, model string, raw *RawAttestation, nonce Nonce, enforced []string, tdxResult *TDXVerifyResult, nvidiaResult *NvidiaVerifyResult, nrasResult *NvidiaVerifyResult, pocResult *PoCResult) *VerificationReport {
	enforcedSet := make(map[string]bool, len(enforced))
	for _, name := range enforced {
		enforcedSet[name] = true
	}

	factors := make([]FactorResult, 0, 21)

	addFactor := func(name string, status Status, detail string) {
		factors = append(factors, FactorResult{
			Name:     name,
			Status:   status,
			Detail:   detail,
			Enforced: enforcedSet[name],
		})
	}

	// --- Tier 1: Core Attestation ---

	// Factor 1: nonce_match
	if raw.Nonce == "" {
		addFactor("nonce_match", Fail, "nonce field absent from attestation response")
	} else if subtle.ConstantTimeCompare([]byte(raw.Nonce), []byte(nonce.Hex())) == 1 {
		detail := fmt.Sprintf("nonce matches (%d hex chars)", len(raw.Nonce))
		if raw.NonceSource != "" {
			detail += fmt.Sprintf(" (%s-supplied)", raw.NonceSource)
		}
		addFactor("nonce_match", Pass, detail)
	} else {
		addFactor("nonce_match", Fail, fmt.Sprintf("nonce mismatch: got %q, want %q", raw.Nonce, nonce.Hex()))
	}

	// Factor 2: tdx_quote_present
	if raw.IntelQuote == "" {
		addFactor("tdx_quote_present", Fail, "intel_quote field is absent from attestation response")
	} else {
		// Base64 length → approximate raw bytes
		addFactor("tdx_quote_present", Pass, fmt.Sprintf("TDX quote present (%d hex chars)", len(raw.IntelQuote)))
	}

	// Factors 3–6, 8, 10 come from TDX quote parsing.
	// tdxResult is nil when the quote is absent or could not be decoded for
	// a network/decode reason prior to parsing.
	if tdxResult == nil {
		// All TDX parse/verify factors are Fail because we have no quote to check.
		addFactor("tdx_quote_structure", Fail, "no TDX quote available to parse")
		addFactor("tdx_cert_chain", Fail, "no TDX quote available; cannot verify cert chain")
		addFactor("tdx_quote_signature", Fail, "no TDX quote available; cannot verify signature")
		addFactor("tdx_debug_disabled", Fail, "no TDX quote available; cannot check debug flag")
	} else {
		// Factor 3: tdx_quote_structure
		if tdxResult.ParseErr != nil {
			addFactor("tdx_quote_structure", Fail, fmt.Sprintf("TDX quote parse failed: %v", tdxResult.ParseErr))
		} else {
			detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(tdxResult))
			if len(tdxResult.MRTD) > 0 {
				detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(tdxResult), hex.EncodeToString(tdxResult.MRTD)[:16])
			}
			addFactor("tdx_quote_structure", Pass, detail)
		}

		// Factor 4: tdx_cert_chain
		if tdxResult.ParseErr != nil {
			addFactor("tdx_cert_chain", Skip, "quote parse failed; cert chain not extracted")
		} else if tdxResult.CertChainErr != nil {
			addFactor("tdx_cert_chain", Fail, fmt.Sprintf("cert chain verification failed: %v", tdxResult.CertChainErr))
		} else {
			addFactor("tdx_cert_chain", Pass, "certificate chain valid (Intel root CA)")
		}

		// Factor 5: tdx_quote_signature
		if tdxResult.ParseErr != nil {
			addFactor("tdx_quote_signature", Skip, "quote parse failed; signature not verified")
		} else if tdxResult.SignatureErr != nil {
			addFactor("tdx_quote_signature", Fail, fmt.Sprintf("quote signature invalid: %v", tdxResult.SignatureErr))
		} else {
			addFactor("tdx_quote_signature", Pass, "quote signature verified")
		}

		// Factor 6: tdx_debug_disabled
		if tdxResult.ParseErr != nil {
			addFactor("tdx_debug_disabled", Skip, "quote parse failed; debug flag not checked")
		} else if tdxResult.DebugEnabled {
			addFactor("tdx_debug_disabled", Fail, "TD_ATTRIBUTES debug bit is set — this is a debug enclave; do not trust for production")
		} else {
			addFactor("tdx_debug_disabled", Pass, "debug bit is 0 (production enclave)")
		}
	}

	// Factor 7: signing_key_present
	if raw.SigningKey == "" {
		addFactor("signing_key_present", Fail, "signing_key field absent from attestation response")
	} else {
		addFactor("signing_key_present", Pass, fmt.Sprintf("signing key present (%s...)", raw.SigningKey[:min(10, len(raw.SigningKey))]))
	}

	// --- Tier 2: Binding & Crypto ---

	// Factor 8: tdx_reportdata_binding
	// REPORTDATA (64 bytes) must bind the signing key to the nonce so a MITM
	// cannot swap the key while leaving the quote intact. Without this check,
	// E2EE is security theater.
	if tdxResult == nil || tdxResult.ParseErr != nil {
		addFactor("tdx_reportdata_binding", Fail, "no parseable TDX quote; REPORTDATA binding cannot be verified")
	} else if raw.SigningKey == "" {
		addFactor("tdx_reportdata_binding", Fail, "signing_key absent; REPORTDATA binding cannot be verified")
	} else if tdxResult.ReportDataBindingErr != nil {
		addFactor("tdx_reportdata_binding", Fail, fmt.Sprintf("REPORTDATA does not bind signing key: %v", tdxResult.ReportDataBindingErr))
	} else {
		addFactor("tdx_reportdata_binding", Pass, fmt.Sprintf("REPORTDATA binds signing key via Ethereum address (%s)", hex.EncodeToString(tdxResult.ReportData[:20])))
	}

	// Factor 9: intel_pcs_collateral
	if tdxResult == nil || tdxResult.ParseErr != nil {
		addFactor("intel_pcs_collateral", Skip, "no parseable TDX quote")
	} else if tdxResult.TcbStatus != "" {
		addFactor("intel_pcs_collateral", Pass,
			fmt.Sprintf("Intel PCS collateral fetched (TCB status: %s)", tdxResult.TcbStatus))
	} else if tdxResult.CollateralErr != nil {
		addFactor("intel_pcs_collateral", Skip,
			fmt.Sprintf("Intel PCS collateral fetch failed: %v", tdxResult.CollateralErr))
	} else {
		addFactor("intel_pcs_collateral", Skip,
			"offline mode; Intel PCS collateral not fetched")
	}

	// Factor 10: tdx_tcb_current
	if tdxResult == nil || tdxResult.ParseErr != nil {
		addFactor("tdx_tcb_current", Skip, "no parseable TDX quote; TCB SVN not extracted")
	} else if tdxResult.TcbStatus == pcs.TcbComponentStatusUpToDate {
		detail := "TCB is UpToDate per Intel PCS"
		if len(tdxResult.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (advisories: %s)", strings.Join(tdxResult.AdvisoryIDs, ", "))
		}
		addFactor("tdx_tcb_current", Pass, detail)
	} else if tdxResult.TcbStatus == pcs.TcbComponentStatusSwHardeningNeeded || tdxResult.TcbStatus == pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded {
		detail := fmt.Sprintf("TCB status: %s", tdxResult.TcbStatus)
		if len(tdxResult.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (advisories: %s)", strings.Join(tdxResult.AdvisoryIDs, ", "))
		}
		addFactor("tdx_tcb_current", Pass, detail)
	} else if tdxResult.TcbStatus == pcs.TcbComponentStatusOutOfDate || tdxResult.TcbStatus == pcs.TcbComponentStatusRevoked || tdxResult.TcbStatus == pcs.TcbComponentStatusOutOfDateConfigurationNeeded {
		detail := fmt.Sprintf("TCB status: %s — firmware has known vulnerabilities", tdxResult.TcbStatus)
		if len(tdxResult.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(tdxResult.AdvisoryIDs, ", "))
		}
		addFactor("tdx_tcb_current", Fail, detail)
	} else if tdxResult.CollateralErr != nil {
		svnHex := hex.EncodeToString(tdxResult.TeeTCBSVN)
		addFactor("tdx_tcb_current", Skip,
			fmt.Sprintf("TEE_TCB_SVN: %s (Intel PCS collateral fetch failed: %v)", svnHex, tdxResult.CollateralErr))
	} else {
		svnHex := hex.EncodeToString(tdxResult.TeeTCBSVN)
		addFactor("tdx_tcb_current", Skip,
			fmt.Sprintf("TEE_TCB_SVN: %s (offline; full check requires Intel PCS)", svnHex))
	}

	// Factor 11: nvidia_payload_present
	if raw.NvidiaPayload == "" {
		addFactor("nvidia_payload_present", Fail, "nvidia_payload field is absent from attestation response")
	} else {
		addFactor("nvidia_payload_present", Pass, fmt.Sprintf("NVIDIA payload present (%d chars)", len(raw.NvidiaPayload)))
	}

	// Factor 12: nvidia_signature
	if nvidiaResult == nil {
		if raw.NvidiaPayload == "" {
			addFactor("nvidia_signature", Skip, "no NVIDIA payload to verify")
		} else {
			addFactor("nvidia_signature", Fail, "NVIDIA verification was not attempted")
		}
	} else if nvidiaResult.SignatureErr != nil {
		addFactor("nvidia_signature", Fail, fmt.Sprintf("signature invalid: %v", nvidiaResult.SignatureErr))
	} else {
		addFactor("nvidia_signature", Pass, nvidiaSignatureDetail(nvidiaResult))
	}

	// Factor 13: nvidia_claims
	if nvidiaResult == nil {
		if raw.NvidiaPayload == "" {
			addFactor("nvidia_claims", Skip, "no NVIDIA payload to check")
		} else {
			addFactor("nvidia_claims", Fail, "NVIDIA verification was not attempted")
		}
	} else if nvidiaResult.ClaimsErr != nil {
		addFactor("nvidia_claims", Fail, fmt.Sprintf("claims invalid: %v", nvidiaResult.ClaimsErr))
	} else {
		addFactor("nvidia_claims", Pass, nvidiaClaimsDetail(nvidiaResult))
	}

	// Factor 14: nvidia_nonce_match
	if nvidiaResult == nil {
		if raw.NvidiaPayload == "" {
			addFactor("nvidia_nonce_match", Skip, "no NVIDIA payload; nonce not checked")
		} else {
			addFactor("nvidia_nonce_match", Skip, "NVIDIA verification not attempted")
		}
	} else if nvidiaResult.Nonce == "" {
		addFactor("nvidia_nonce_match", Skip, "nonce field not found in NVIDIA payload")
	} else if subtle.ConstantTimeCompare([]byte(nvidiaResult.Nonce), []byte(nonce.Hex())) == 1 {
		addFactor("nvidia_nonce_match", Pass, nvidiaNonceDetail(nvidiaResult))
	} else {
		addFactor("nvidia_nonce_match", Fail, fmt.Sprintf("nonce mismatch in NVIDIA payload: got %q, want %q", nvidiaResult.Nonce, nonce.Hex()))
	}

	// Factor 15: nvidia_nras_verified
	if nrasResult == nil {
		if raw.NvidiaPayload == "" || raw.NvidiaPayload[0] != '{' {
			addFactor("nvidia_nras_verified", Skip, "no EAT payload; NRAS not applicable")
		} else {
			addFactor("nvidia_nras_verified", Skip, "offline mode; NRAS verification skipped")
		}
	} else if nrasResult.SignatureErr != nil {
		addFactor("nvidia_nras_verified", Fail,
			fmt.Sprintf("NRAS JWT signature invalid: %v", nrasResult.SignatureErr))
	} else if nrasResult.ClaimsErr != nil {
		addFactor("nvidia_nras_verified", Fail,
			fmt.Sprintf("NRAS JWT claims invalid: %v", nrasResult.ClaimsErr))
	} else if !nrasResult.OverallResult {
		addFactor("nvidia_nras_verified", Fail, "NRAS result: false")
	} else {
		addFactor("nvidia_nras_verified", Pass, "NRAS: true (JWT verified)")
	}

	// Factor 16: e2ee_capable
	if raw.SigningKey == "" {
		addFactor("e2ee_capable", Fail, "signing_key absent; E2EE key exchange not possible")
	} else {
		s := &Session{}
		if err := s.SetModelKey(raw.SigningKey); err != nil {
			addFactor("e2ee_capable", Fail, fmt.Sprintf("signing_key is not a valid secp256k1 public key: %v", err))
		} else {
			detail := "signing key is valid secp256k1 uncompressed point; E2EE key exchange possible"
			if raw.SigningAlgo != "" {
				detail += fmt.Sprintf(" (%s)", raw.SigningAlgo)
			}
			addFactor("e2ee_capable", Pass, detail)
		}
	}

	// --- Tier 3: Supply Chain & Channel Integrity ---
	// These represent the Tinfoil gold standard. Both Venice and NEAR are
	// expected to fail all of these today. The detail strings explain what is
	// missing and why it matters for users evaluating vendor security posture.

	addFactor("tls_key_binding", Fail,
		"no TLS key in attestation")

	addFactor("cpu_gpu_chain", Fail,
		"CPU-GPU attestation not bound")

	addFactor("measured_model_weights", Fail,
		"no model weight hashes")

	if raw.ComposeHash != "" {
		hashPreview := raw.ComposeHash
		if len(hashPreview) > 8 {
			hashPreview = hashPreview[:8] + "..."
		}
		addFactor("build_transparency_log", Skip,
			fmt.Sprintf("compose hash present (%s) but not an independent transparency log", hashPreview))
	} else {
		addFactor("build_transparency_log", Fail,
			"no build transparency log")
	}

	if pocResult != nil && pocResult.Registered {
		addFactor("cpu_id_registry", Pass,
			fmt.Sprintf("Proof of Cloud: registered (%s)", pocResult.Label))
	} else if pocResult != nil && pocResult.Err != nil {
		addFactor("cpu_id_registry", Skip,
			fmt.Sprintf("Proof of Cloud query failed: %v", pocResult.Err))
	} else if pocResult != nil && !pocResult.Registered {
		addFactor("cpu_id_registry", Fail,
			"hardware not found in Proof of Cloud registry; paste intel_quote from --save-dir at proofofcloud.org to verify")
	} else if tdxResult != nil && tdxResult.PPID != "" {
		addFactor("cpu_id_registry", Skip,
			fmt.Sprintf("PPID extracted (%s...) but offline; use default mode to check Proof of Cloud",
				tdxResult.PPID[:min(8, len(tdxResult.PPID))]))
	} else if raw.DeviceID != "" {
		idPreview := raw.DeviceID
		if len(idPreview) > 8 {
			idPreview = idPreview[:8] + "..."
		}
		addFactor("cpu_id_registry", Skip,
			fmt.Sprintf("device ID present (%s) but no registry to verify against", idPreview))
	} else {
		addFactor("cpu_id_registry", Fail,
			"no CPU ID registry check")
	}

	// Tally results.
	passed, failed, skipped := 0, 0, 0
	for _, f := range factors {
		switch f.Status {
		case Pass:
			passed++
		case Fail:
			failed++
		case Skip:
			skipped++
		}
	}

	metadata := buildMetadata(raw, tdxResult)

	return &VerificationReport{
		Provider:  provider,
		Model:     model,
		Timestamp: time.Now(),
		Factors:   factors,
		Passed:    passed,
		Failed:    failed,
		Skipped:   skipped,
		Metadata:  metadata,
	}
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

// nvidiaNonceDetail returns the detail string for a passing nvidia_nonce_match.
func nvidiaNonceDetail(r *NvidiaVerifyResult) string {
	switch r.Format {
	case "EAT":
		return fmt.Sprintf("EAT nonce + %d GPU SPDM requester nonces match submitted nonce", r.GPUCount)
	default:
		return "nonce in NVIDIA payload matches submitted nonce"
	}
}

// buildMetadata extracts display metadata from raw into an ordered key-value
// map. Only non-empty values are included. The map is used by formatReport
// to render the metadata block between the header and Tier 1.
func buildMetadata(raw *RawAttestation, tdxResult *TDXVerifyResult) map[string]string {
	m := make(map[string]string)

	if raw.TEEHardware != "" {
		m["hardware"] = raw.TEEHardware
	}
	if raw.UpstreamModel != "" {
		m["upstream"] = raw.UpstreamModel
	}
	if raw.AppName != "" {
		m["app"] = raw.AppName
	}
	if raw.ComposeHash != "" {
		m["compose_hash"] = raw.ComposeHash
	}
	if raw.OSImageHash != "" {
		m["os_image"] = raw.OSImageHash
	}
	if raw.DeviceID != "" {
		m["device"] = raw.DeviceID
	}
	if tdxResult != nil && tdxResult.PPID != "" {
		m["ppid"] = tdxResult.PPID
	}
	if raw.NonceSource != "" {
		m["nonce_source"] = raw.NonceSource
	}
	if raw.CandidatesAvail > 0 || raw.CandidatesEval > 0 {
		m["candidates"] = fmt.Sprintf("%d/%d evaluated", raw.CandidatesEval, raw.CandidatesAvail)
	}
	if raw.EventLogCount > 0 {
		m["event_log"] = fmt.Sprintf("%d entries", raw.EventLogCount)
	}

	if len(m) == 0 {
		return nil
	}
	return m
}

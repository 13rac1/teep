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
// can substitute the enclave public key and intercept all E2EE traffic.
var DefaultEnforced = []string{
	"nonce_match",
	"tdx_cert_chain",
	"tdx_quote_signature",
	"tdx_debug_disabled",
	"signing_key_present",
	"tdx_reportdata_binding",
	"compose_binding",
	"nvidia_signature",
	"nvidia_nonce_match",
	"build_transparency_log",
	"sigstore_verification",
	"event_log_integrity",
	// Gateway factors (nearcloud only).
	"gateway_tdx_cert_chain",
	"gateway_tdx_quote_signature",
	"gateway_tdx_debug_disabled",
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
	"compose_binding", "sigstore_verification", "event_log_integrity",
	// Gateway factors (nearcloud only).
	"gateway_nonce_match", "gateway_tdx_quote_present", "gateway_tdx_quote_structure",
	"gateway_tdx_cert_chain", "gateway_tdx_quote_signature", "gateway_tdx_debug_disabled",
	"gateway_compose_binding",
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
	Provider     string
	Model        string
	Raw          *RawAttestation
	Nonce        Nonce
	Enforced     []string
	Policy       MeasurementPolicy
	ImageRepos   []string
	DigestToRepo map[string]string // digest hex → normalized image repo, for policy checks

	TDX        *TDXVerifyResult
	Nvidia     *NvidiaVerifyResult
	NvidiaNRAS *NvidiaVerifyResult
	PoC        *PoCResult
	Compose    *ComposeBindingResult
	Sigstore   []SigstoreResult
	Rekor      []RekorProvenance

	// Gateway fields — only populated for nearcloud provider.
	GatewayTDX      *TDXVerifyResult
	GatewayNonceHex string // echoed request_nonce from gateway response
	GatewayNonce    Nonce  // nonce we sent to the gateway
	GatewayCompose  *ComposeBindingResult
}

// BuildReport runs verification factors against the input and returns a
// complete VerificationReport. The Enforced field controls which factor names
// result in Enforced=true. Pass DefaultEnforced for production use.
// Base factors: 24 (all providers). Gateway factors: +7 (nearcloud only).
func BuildReport(in *ReportInput) *VerificationReport {
	enforcedSet := make(map[string]bool, len(in.Enforced))
	for _, name := range in.Enforced {
		enforcedSet[name] = true
	}

	factors := make([]FactorResult, 0, 31)

	addFactor := func(tier, name string, status Status, detail string) {
		factors = append(factors, FactorResult{
			Name:     name,
			Status:   status,
			Detail:   detail,
			Enforced: enforcedSet[name],
			Tier:     tier,
		})
	}

	// --- Tier 1: Core Attestation ---

	// Factor 1: nonce_match
	if in.Raw.Nonce == "" { //nolint:gocritic // ifElseChain: conditions compare different fields
		addFactor(TierCore, "nonce_match", Fail, "nonce field absent from attestation response")
	} else if subtle.ConstantTimeCompare([]byte(in.Raw.Nonce), []byte(in.Nonce.Hex())) == 1 {
		detail := fmt.Sprintf("nonce matches (%d hex chars)", len(in.Raw.Nonce))
		if in.Raw.NonceSource != "" {
			detail += fmt.Sprintf(" (%s-supplied)", in.Raw.NonceSource)
		}
		addFactor(TierCore, "nonce_match", Pass, detail)
	} else {
		addFactor(TierCore, "nonce_match", Fail, fmt.Sprintf("nonce mismatch: got %q, want %q", in.Raw.Nonce, in.Nonce.Hex()))
	}

	// Factor 2: tdx_quote_present
	if in.Raw.IntelQuote == "" {
		addFactor(TierCore, "tdx_quote_present", Fail, "intel_quote field is absent from attestation response")
	} else {
		// Base64 length → approximate raw bytes
		addFactor(TierCore, "tdx_quote_present", Pass, fmt.Sprintf("TDX quote present (%d hex chars)", len(in.Raw.IntelQuote)))
	}

	// Factors 3–6, 8, 10 come from TDX quote parsing.
	// in.TDX is nil when the quote is absent or could not be decoded for
	// a network/decode reason prior to parsing.
	if in.TDX == nil {
		// All TDX parse/verify factors are Fail because we have no quote to check.
		addFactor(TierCore, "tdx_quote_structure", Fail, "no TDX quote available to parse")
		addFactor(TierCore, "tdx_cert_chain", Fail, "no TDX quote available; cannot verify cert chain")
		addFactor(TierCore, "tdx_quote_signature", Fail, "no TDX quote available; cannot verify signature")
		addFactor(TierCore, "tdx_debug_disabled", Fail, "no TDX quote available; cannot check debug flag")
	} else {
		// Factor 3: tdx_quote_structure
		if in.TDX.ParseErr != nil {
			addFactor(TierCore, "tdx_quote_structure", Fail, fmt.Sprintf("TDX quote parse failed: %v", in.TDX.ParseErr))
		} else {
			mrtdHex := hex.EncodeToString(in.TDX.MRTD)
			mrSeamHex := hex.EncodeToString(in.TDX.MRSeam)

			detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(in.TDX))
			if len(mrtdHex) >= 16 {
				detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(in.TDX), mrtdHex[:16])
			}

			switch {
			case in.Policy.HasMRTDPolicy() && !containsAllowlist(in.Policy.MRTDAllow, mrtdHex):
				addFactor(TierCore, "tdx_quote_structure", Fail, fmt.Sprintf("MRTD not in policy allowlist: %s...", prefixHex(mrtdHex)))
			case in.Policy.HasMRSeamPolicy() && !containsAllowlist(in.Policy.MRSeamAllow, mrSeamHex):
				addFactor(TierCore, "tdx_quote_structure", Fail, fmt.Sprintf("MRSEAM not in policy allowlist: %s...", prefixHex(mrSeamHex)))
			case in.Policy.HasMRTDPolicy() && in.Policy.HasMRSeamPolicy():
				addFactor(TierCore, "tdx_quote_structure", Pass, detail+" (MRTD/MRSEAM policy matched)")
			case in.Policy.HasMRTDPolicy():
				addFactor(TierCore, "tdx_quote_structure", Pass, detail+" (MRTD policy matched)")
			case in.Policy.HasMRSeamPolicy():
				addFactor(TierCore, "tdx_quote_structure", Pass, detail+" (MRSEAM policy matched)")
			default:
				addFactor(TierCore, "tdx_quote_structure", Pass, detail)
			}
		}

		// Factor 4: tdx_cert_chain
		if in.TDX.ParseErr != nil { //nolint:gocritic // ifElseChain: conditions compare different fields
			addFactor(TierCore, "tdx_cert_chain", Skip, "quote parse failed; cert chain not extracted")
		} else if in.TDX.CertChainErr != nil {
			addFactor(TierCore, "tdx_cert_chain", Fail, fmt.Sprintf("cert chain verification failed: %v", in.TDX.CertChainErr))
		} else {
			addFactor(TierCore, "tdx_cert_chain", Pass, "certificate chain valid (Intel root CA)")
		}

		// Factor 5: tdx_quote_signature
		if in.TDX.ParseErr != nil { //nolint:gocritic // ifElseChain: conditions compare different fields
			addFactor(TierCore, "tdx_quote_signature", Skip, "quote parse failed; signature not verified")
		} else if in.TDX.SignatureErr != nil {
			addFactor(TierCore, "tdx_quote_signature", Fail, fmt.Sprintf("quote signature invalid: %v", in.TDX.SignatureErr))
		} else {
			addFactor(TierCore, "tdx_quote_signature", Pass, "quote signature verified")
		}

		// Factor 6: tdx_debug_disabled
		if in.TDX.ParseErr != nil { //nolint:gocritic // ifElseChain: conditions compare different fields
			addFactor(TierCore, "tdx_debug_disabled", Skip, "quote parse failed; debug flag not checked")
		} else if in.TDX.DebugEnabled {
			addFactor(TierCore, "tdx_debug_disabled", Fail, "TD_ATTRIBUTES debug bit is set — this is a debug enclave; do not trust for production")
		} else {
			addFactor(TierCore, "tdx_debug_disabled", Pass, "debug bit is 0 (production enclave)")
		}
	}

	// Factor 7: signing_key_present
	// The API field is called "signing_key" but it's an ECDH public key used
	// for key exchange, not for signing.
	if in.Raw.SigningKey == "" {
		addFactor(TierCore, "signing_key_present", Fail, "signing_key field absent from attestation response")
	} else {
		addFactor(TierCore, "signing_key_present", Pass, fmt.Sprintf("enclave pubkey present (%s...)", in.Raw.SigningKey[:min(10, len(in.Raw.SigningKey))]))
	}

	// --- Tier 2: Binding & Crypto ---

	// Factor 8: tdx_reportdata_binding
	// REPORTDATA (64 bytes) must bind the enclave public key to the nonce so a
	// MITM cannot swap the key while leaving the quote intact. Without this
	// check, E2EE is security theater.
	if in.TDX == nil || in.TDX.ParseErr != nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		addFactor(TierBinding, "tdx_reportdata_binding", Fail, "no parseable TDX quote; REPORTDATA binding cannot be verified")
	} else if in.Raw.SigningKey == "" {
		addFactor(TierBinding, "tdx_reportdata_binding", Fail, "enclave public key absent; REPORTDATA binding cannot be verified")
	} else if in.TDX.ReportDataBindingErr != nil {
		addFactor(TierBinding, "tdx_reportdata_binding", Fail, fmt.Sprintf("REPORTDATA does not bind enclave public key: %v", in.TDX.ReportDataBindingErr))
	} else if in.TDX.ReportDataBindingDetail != "" {
		addFactor(TierBinding, "tdx_reportdata_binding", Pass, in.TDX.ReportDataBindingDetail)
	} else {
		addFactor(TierBinding, "tdx_reportdata_binding", Skip, "no REPORTDATA verifier configured for this provider")
	}

	// Factor 9: intel_pcs_collateral
	if in.TDX == nil || in.TDX.ParseErr != nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		addFactor(TierBinding, "intel_pcs_collateral", Skip, "no parseable TDX quote")
	} else if in.TDX.TcbStatus != "" {
		addFactor(TierBinding, "intel_pcs_collateral", Pass,
			fmt.Sprintf("Intel PCS collateral fetched (TCB status: %s)", in.TDX.TcbStatus))
	} else if in.TDX.CollateralErr != nil {
		addFactor(TierBinding, "intel_pcs_collateral", Skip,
			fmt.Sprintf("Intel PCS collateral fetch failed: %v", in.TDX.CollateralErr))
	} else {
		addFactor(TierBinding, "intel_pcs_collateral", Skip,
			"offline mode; Intel PCS collateral not fetched")
	}

	// Factor 10: tdx_tcb_current
	if in.TDX == nil || in.TDX.ParseErr != nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		addFactor(TierBinding, "tdx_tcb_current", Skip, "no parseable TDX quote; TCB SVN not extracted")
	} else if in.TDX.TcbStatus == pcs.TcbComponentStatusUpToDate {
		detail := "TCB is UpToDate per Intel PCS"
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (advisories: %s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		addFactor(TierBinding, "tdx_tcb_current", Pass, detail)
	} else if in.TDX.TcbStatus == pcs.TcbComponentStatusSwHardeningNeeded || in.TDX.TcbStatus == pcs.TcbComponentStatusConfigurationAndSWHardeningNeeded {
		// F-17: SWHardeningNeeded / ConfigurationAndSWHardeningNeeded indicate that known
		// firmware vulnerabilities require software mitigations. Treat as Fail so operators
		// see the advisory; tdx_tcb_current is not in DefaultEnforced so this does not
		// block the proxy unless explicitly configured.
		detail := fmt.Sprintf("TCB status: %s — software/config mitigations required for known advisories", in.TDX.TcbStatus)
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		addFactor(TierBinding, "tdx_tcb_current", Fail, detail)
	} else if in.TDX.TcbStatus == pcs.TcbComponentStatusOutOfDate || in.TDX.TcbStatus == pcs.TcbComponentStatusRevoked || in.TDX.TcbStatus == pcs.TcbComponentStatusOutOfDateConfigurationNeeded {
		detail := fmt.Sprintf("TCB status: %s — firmware has known vulnerabilities", in.TDX.TcbStatus)
		if len(in.TDX.AdvisoryIDs) > 0 {
			detail += fmt.Sprintf(" (%s)", strings.Join(in.TDX.AdvisoryIDs, ", "))
		}
		addFactor(TierBinding, "tdx_tcb_current", Fail, detail)
	} else if in.TDX.CollateralErr != nil {
		svnHex := hex.EncodeToString(in.TDX.TeeTCBSVN)
		addFactor(TierBinding, "tdx_tcb_current", Skip,
			fmt.Sprintf("TEE_TCB_SVN: %s (Intel PCS collateral fetch failed: %v)", svnHex, in.TDX.CollateralErr))
	} else {
		svnHex := hex.EncodeToString(in.TDX.TeeTCBSVN)
		addFactor(TierBinding, "tdx_tcb_current", Skip,
			fmt.Sprintf("TEE_TCB_SVN: %s (offline; full check requires Intel PCS)", svnHex))
	}

	// Factor 11: nvidia_payload_present
	if in.Raw.NvidiaPayload == "" {
		addFactor(TierBinding, "nvidia_payload_present", Fail, "nvidia_payload field is absent from attestation response")
	} else {
		addFactor(TierBinding, "nvidia_payload_present", Pass, fmt.Sprintf("NVIDIA payload present (%d chars)", len(in.Raw.NvidiaPayload)))
	}

	// Factor 12: nvidia_signature
	if in.Nvidia == nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		if in.Raw.NvidiaPayload == "" {
			addFactor(TierBinding, "nvidia_signature", Skip, "no NVIDIA payload to verify")
		} else {
			addFactor(TierBinding, "nvidia_signature", Fail, "NVIDIA verification was not attempted")
		}
	} else if in.Nvidia.SignatureErr != nil {
		addFactor(TierBinding, "nvidia_signature", Fail, fmt.Sprintf("signature invalid: %v", in.Nvidia.SignatureErr))
	} else {
		addFactor(TierBinding, "nvidia_signature", Pass, nvidiaSignatureDetail(in.Nvidia))
	}

	// Factor 13: nvidia_claims
	if in.Nvidia == nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		if in.Raw.NvidiaPayload == "" {
			addFactor(TierBinding, "nvidia_claims", Skip, "no NVIDIA payload to check")
		} else {
			addFactor(TierBinding, "nvidia_claims", Fail, "NVIDIA verification was not attempted")
		}
	} else if in.Nvidia.ClaimsErr != nil {
		addFactor(TierBinding, "nvidia_claims", Fail, fmt.Sprintf("claims invalid: %v", in.Nvidia.ClaimsErr))
	} else {
		addFactor(TierBinding, "nvidia_claims", Pass, nvidiaClaimsDetail(in.Nvidia))
	}

	// Factor 14: nvidia_nonce_match
	if in.Nvidia == nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		if in.Raw.NvidiaPayload == "" {
			addFactor(TierBinding, "nvidia_nonce_match", Skip, "no NVIDIA payload; nonce not checked")
		} else {
			addFactor(TierBinding, "nvidia_nonce_match", Skip, "NVIDIA verification not attempted")
		}
	} else if in.Nvidia.Nonce == "" {
		addFactor(TierBinding, "nvidia_nonce_match", Skip, "nonce field not found in NVIDIA payload")
	} else if subtle.ConstantTimeCompare([]byte(in.Nvidia.Nonce), []byte(in.Nonce.Hex())) == 1 {
		addFactor(TierBinding, "nvidia_nonce_match", Pass, nvidiaNonceDetail(in.Nvidia))
	} else {
		addFactor(TierBinding, "nvidia_nonce_match", Fail, fmt.Sprintf("nonce mismatch in NVIDIA payload: got %q, want %q", in.Nvidia.Nonce, in.Nonce.Hex()))
	}

	// Factor 15: nvidia_nras_verified
	if in.NvidiaNRAS == nil { //nolint:gocritic // ifElseChain: conditions compare different fields
		if in.Raw.NvidiaPayload == "" || in.Raw.NvidiaPayload[0] != '{' {
			addFactor(TierBinding, "nvidia_nras_verified", Skip, "no EAT payload; NRAS not applicable")
		} else {
			addFactor(TierBinding, "nvidia_nras_verified", Skip, "offline mode; NRAS verification skipped")
		}
	} else if in.NvidiaNRAS.SignatureErr != nil {
		addFactor(TierBinding, "nvidia_nras_verified", Fail,
			fmt.Sprintf("NRAS JWT signature invalid: %v", in.NvidiaNRAS.SignatureErr))
	} else if in.NvidiaNRAS.ClaimsErr != nil {
		addFactor(TierBinding, "nvidia_nras_verified", Fail,
			fmt.Sprintf("NRAS JWT claims invalid: %v", in.NvidiaNRAS.ClaimsErr))
	} else if !in.NvidiaNRAS.OverallResult {
		addFactor(TierBinding, "nvidia_nras_verified", Fail, "NRAS result: false")
	} else {
		addFactor(TierBinding, "nvidia_nras_verified", Pass, "NRAS: true (JWT verified)")
	}

	// Factor 16: e2ee_capable
	if in.Raw.SigningKey == "" {
		addFactor(TierBinding, "e2ee_capable", Fail, "enclave public key absent; E2EE key exchange not possible")
	} else {
		s := &Session{}
		if err := s.SetModelKey(in.Raw.SigningKey); err != nil {
			addFactor(TierBinding, "e2ee_capable", Fail, fmt.Sprintf("enclave public key is not a valid secp256k1 point: %v", err))
		} else {
			detail := "enclave public key is valid secp256k1 uncompressed point; E2EE key exchange possible"
			if in.Raw.SigningAlgo != "" {
				detail += fmt.Sprintf(" (%s)", in.Raw.SigningAlgo)
			}
			addFactor(TierBinding, "e2ee_capable", Pass, detail)
		}
	}

	// --- Tier 3: Supply Chain & Channel Integrity ---
	// These represent the Tinfoil gold standard. Both Venice and NEAR are
	// expected to fail all of these today. The detail strings explain what is
	// missing and why it matters for users evaluating vendor security posture.

	switch {
	case in.Raw.TLSFingerprint != "":
		fpPreview := in.Raw.TLSFingerprint
		if len(fpPreview) > 16 {
			fpPreview = fpPreview[:16] + "..."
		}
		addFactor(TierSupplyChain, "tls_key_binding", Pass,
			fmt.Sprintf("TLS certificate SPKI bound to attestation (%s)", fpPreview))
	case in.Raw.SigningKey != "":
		addFactor(TierSupplyChain, "tls_key_binding", Skip,
			"provider uses E2EE key exchange; TLS binding not applicable")
	default:
		addFactor(TierSupplyChain, "tls_key_binding", Fail,
			"no TLS certificate binding in attestation")
	}

	addFactor(TierSupplyChain, "cpu_gpu_chain", Fail,
		"CPU-GPU attestation not bound")

	addFactor(TierSupplyChain, "measured_model_weights", Fail,
		"no model weight hashes")

	scPolicy := supplyChainPolicyForProvider(in.Provider)
	if scPolicy != nil {
		if len(in.ImageRepos) == 0 {
			addFactor(TierSupplyChain, "build_transparency_log", Fail,
				"No attested image repositories extracted from compose")
			goto buildTransparencyDone
		}
		for _, repo := range in.ImageRepos {
			if !containsFold(repo, scPolicy.AllowedImageRepos) {
				addFactor(TierSupplyChain, "build_transparency_log", Fail,
					fmt.Sprintf("Container allowlist policy: image repository %q is not in allowlist (%s)",
						repo, strings.Join(scPolicy.AllowedImageRepos, ", ")))
				goto buildTransparencyDone
			}
		}
	}

	if len(in.Rekor) == 0 {
		if scPolicy != nil {
			addFactor(TierSupplyChain, "build_transparency_log", Fail,
				"Container check: no Rekor provenance fetched for attested image digests")
			goto buildTransparencyDone
		}
		if in.Raw.ComposeHash != "" {
			hashPreview := in.Raw.ComposeHash
			if len(hashPreview) > 8 {
				hashPreview = hashPreview[:8] + "..."
			}
			addFactor(TierSupplyChain, "build_transparency_log", Skip,
				fmt.Sprintf("compose hash present (%s) but no Rekor provenance fetched", hashPreview))
		} else {
			addFactor(TierSupplyChain, "build_transparency_log", Fail,
				"no build transparency log")
		}
	} else {
		var verified int
		var fallbackOnly int
		var detail string
		var failed bool
		for i := range in.Rekor {
			r := &in.Rekor[i]
			if r.Err != nil {
				fallbackOnly++
				continue
			}
			if !r.HasCert {
				fallbackOnly++
				continue // third-party image — skip, don't fail
			}

			if scPolicy != nil {
				if !containsFold(r.OIDCIssuer, scPolicy.AllowedOIDCIssuers) {
					failed = true
					detail = "Container signer checks: unexpected OIDC issuer: " + r.OIDCIssuer
					break
				}

				repoID := strings.TrimSpace(r.SourceRepo)
				repoURL := strings.TrimSpace(r.SourceRepoURL)
				if !containsFold(repoID, scPolicy.AllowedSourceRepos) &&
					!containsFold(repoURL, scPolicy.AllowedSourceRepos) {
					failed = true
					detail = fmt.Sprintf("Container signer check: unexpected Sigstore signer identity (repo=%q repo_url=%q)", repoID, repoURL)
					break
				}
			} else if r.OIDCIssuer != "https://token.actions.githubusercontent.com" {
				failed = true
				detail = "unexpected OIDC issuer: " + r.OIDCIssuer
				break
			}
			verified++
			if detail == "" {
				repo := r.SourceRepo
				commit := r.SourceCommit
				if len(commit) > 7 {
					commit = commit[:7]
				}
				detail = fmt.Sprintf("%s@%s, %s", repo, commit, r.RunnerEnv)
			}
		}
		switch {
		case failed:
			addFactor(TierSupplyChain, "build_transparency_log", Fail, detail)
		case scPolicy != nil && verified > 0 && fallbackOnly > 0:
			addFactor(TierSupplyChain, "build_transparency_log", Pass,
				fmt.Sprintf("Container policy check: %d image(s) have acceptable Rekor signer provenance; %d image(s) rely on repository allowlist + Sigstore presence", verified, fallbackOnly))
		case scPolicy != nil && verified == 0 && fallbackOnly > 0:
			addFactor(TierSupplyChain, "build_transparency_log", Pass,
				fmt.Sprintf("Container policy check: no Fulcio provenance for %d image(s); repository allowlist + Sigstore presence accepted", fallbackOnly))
		case verified > 0:
			addFactor(TierSupplyChain, "build_transparency_log", Pass,
				fmt.Sprintf("%d/%d image(s) have Sigstore build provenance (%s)", verified, len(in.Rekor), detail))
		default:
			addFactor(TierSupplyChain, "build_transparency_log", Skip,
				"all images signed with raw keys (no Fulcio build provenance)")
		}
	}
buildTransparencyDone:

	if in.PoC != nil && in.PoC.Registered { //nolint:gocritic // ifElseChain: conditions compare different fields
		addFactor(TierSupplyChain, "cpu_id_registry", Pass,
			fmt.Sprintf("Proof of Cloud: registered (%s)", in.PoC.Label))
	} else if in.PoC != nil && in.PoC.Err != nil {
		addFactor(TierSupplyChain, "cpu_id_registry", Skip,
			fmt.Sprintf("Proof of Cloud query failed: %v", in.PoC.Err))
	} else if in.PoC != nil && !in.PoC.Registered {
		addFactor(TierSupplyChain, "cpu_id_registry", Fail,
			"hardware not found in Proof of Cloud registry; paste intel_quote from --save-dir at proofofcloud.org to verify")
	} else if in.TDX != nil && in.TDX.PPID != "" {
		addFactor(TierSupplyChain, "cpu_id_registry", Skip,
			fmt.Sprintf("PPID extracted (%s...) but offline; use default mode to check Proof of Cloud",
				in.TDX.PPID[:min(8, len(in.TDX.PPID))]))
	} else if in.Raw.DeviceID != "" {
		idPreview := in.Raw.DeviceID
		if len(idPreview) > 8 {
			idPreview = idPreview[:8] + "..."
		}
		addFactor(TierSupplyChain, "cpu_id_registry", Skip,
			fmt.Sprintf("device ID present (%s) but no registry to verify against", idPreview))
	} else {
		addFactor(TierSupplyChain, "cpu_id_registry", Fail,
			"no CPU ID registry check")
	}

	// Factor 22: compose_binding
	switch {
	case in.Compose == nil || !in.Compose.Checked:
		addFactor(TierSupplyChain, "compose_binding", Skip, "no app_compose in attestation response")
	case in.Compose.Err != nil:
		addFactor(TierSupplyChain, "compose_binding", Fail, fmt.Sprintf("compose binding failed: %v", in.Compose.Err))
	default:
		addFactor(TierSupplyChain, "compose_binding", Pass, "sha256(app_compose) matches MRConfigID")
	}

	// Factor 23: sigstore_verification
	if len(in.Sigstore) == 0 {
		addFactor(TierSupplyChain, "sigstore_verification", Skip, "no image digests to verify")
	} else {
		sigsPolicy := supplyChainPolicyForProvider(in.Provider)
		allOK := true
		var failDigest string
		var failDetail string
		var allowlisted int
		for _, r := range in.Sigstore {
			if r.OK {
				continue
			}
			// A 404 for an explicitly allowlisted image is acceptable: its
			// digest is pinned in the attested compose manifest (bound to
			// MRConfigID), and the repo is covered by the provider supply
			// chain policy. Not every image is signed with Sigstore.
			if sigsPolicy != nil && len(in.DigestToRepo) > 0 {
				repo := in.DigestToRepo[r.Digest]
				if containsFold(repo, sigsPolicy.AllowedImageRepos) {
					allowlisted++
					continue
				}
			}
			allOK = false
			failDigest = r.Digest
			if r.Err != nil {
				failDetail = r.Err.Error()
			} else {
				failDetail = fmt.Sprintf("HTTP %d", r.Status)
			}
			break
		}
		inRekor := len(in.Sigstore) - allowlisted
		switch {
		case !allOK:
			addFactor(TierSupplyChain, "sigstore_verification", Fail,
				fmt.Sprintf("Sigstore check failed for sha256:%s (%s)", failDigest[:min(16, len(failDigest))], failDetail))
		case allowlisted > 0:
			addFactor(TierSupplyChain, "sigstore_verification", Pass,
				fmt.Sprintf("%d image digest(s) found in Sigstore transparency log; %d allowlisted (not Sigstore-signed)", inRekor, allowlisted))
		default:
			addFactor(TierSupplyChain, "sigstore_verification", Pass,
				fmt.Sprintf("%d image digest(s) found in Sigstore transparency log", len(in.Sigstore)))
		}
	}

	// Factor 24: event_log_integrity
	if len(in.Raw.EventLog) == 0 { //nolint:gocritic // ifElseChain: conditions compare different fields
		addFactor(TierSupplyChain, "event_log_integrity", Skip, "no event log entries in attestation response")
	} else if in.TDX == nil || in.TDX.ParseErr != nil {
		addFactor(TierSupplyChain, "event_log_integrity", Skip, "no parseable TDX quote; cannot compare RTMRs")
	} else {
		replayed, err := ReplayEventLog(in.Raw.EventLog)
		if err != nil {
			addFactor(TierSupplyChain, "event_log_integrity", Fail, fmt.Sprintf("event log replay failed: %v", err))
		} else {
			mismatch := false
			var detail string
			for i := range 4 {
				if replayed[i] != in.TDX.RTMRs[i] {
					mismatch = true
					detail = fmt.Sprintf("RTMR[%d] mismatch: replayed %s, quote %s",
						i, hex.EncodeToString(replayed[i][:])[:16]+"...",
						hex.EncodeToString(in.TDX.RTMRs[i][:])[:16]+"...")
					break
				}
			}
			if mismatch {
				addFactor(TierSupplyChain, "event_log_integrity", Fail, detail)
			} else {
				for i := range 4 {
					if !in.Policy.HasRTMRPolicy(i) {
						continue
					}
					rtmrHex := hex.EncodeToString(in.TDX.RTMRs[i][:])
					if _, ok := in.Policy.RTMRAllow[i][rtmrHex]; !ok {
						addFactor(TierSupplyChain, "event_log_integrity", Fail,
							fmt.Sprintf("RTMR[%d] not in policy allowlist: %s...", i, prefixHex(rtmrHex)))
						goto eventLogDone
					}
				}
				addFactor(TierSupplyChain, "event_log_integrity", Pass,
					fmt.Sprintf("event log replayed (%d entries), all 4 RTMRs match quote", len(in.Raw.EventLog)))
			}
		}
	eventLogDone:
	}

	// --- Tier 4: Gateway Attestation (nearcloud only) ---

	if in.GatewayTDX != nil {
		// Factor 25: gateway_nonce_match
		switch {
		case in.GatewayNonceHex == "":
			addFactor(TierGateway, "gateway_nonce_match", Fail, "gateway request_nonce absent")
		case subtle.ConstantTimeCompare([]byte(in.GatewayNonceHex), []byte(in.GatewayNonce.Hex())) == 1:
			addFactor(TierGateway, "gateway_nonce_match", Pass, fmt.Sprintf("gateway nonce matches (%d hex chars)", len(in.GatewayNonceHex)))
		default:
			addFactor(TierGateway, "gateway_nonce_match", Fail, fmt.Sprintf("gateway nonce mismatch: got %q, want %q", in.GatewayNonceHex, in.GatewayNonce.Hex()))
		}

		// Factor 26: gateway_tdx_quote_present
		addFactor(TierGateway, "gateway_tdx_quote_present", Pass, "gateway TDX quote present and parsed")

		// Factors 27–29 from TDX verification result.
		if in.GatewayTDX.ParseErr != nil {
			addFactor(TierGateway, "gateway_tdx_quote_structure", Fail, fmt.Sprintf("gateway TDX quote parse failed: %v", in.GatewayTDX.ParseErr))
			addFactor(TierGateway, "gateway_tdx_cert_chain", Skip, "gateway quote parse failed; cert chain not extracted")
			addFactor(TierGateway, "gateway_tdx_quote_signature", Skip, "gateway quote parse failed; signature not verified")
			addFactor(TierGateway, "gateway_tdx_debug_disabled", Skip, "gateway quote parse failed; debug flag not checked")
		} else {
			mrtdHex := hex.EncodeToString(in.GatewayTDX.MRTD)
			detail := fmt.Sprintf("valid %s structure", tdxQuoteVersion(in.GatewayTDX))
			if len(mrtdHex) >= 16 {
				detail = fmt.Sprintf("valid %s, MRTD: %s...", tdxQuoteVersion(in.GatewayTDX), mrtdHex[:16])
			}
			addFactor(TierGateway, "gateway_tdx_quote_structure", Pass, detail)

			if in.GatewayTDX.CertChainErr != nil {
				addFactor(TierGateway, "gateway_tdx_cert_chain", Fail, fmt.Sprintf("gateway cert chain verification failed: %v", in.GatewayTDX.CertChainErr))
			} else {
				addFactor(TierGateway, "gateway_tdx_cert_chain", Pass, "gateway certificate chain valid (Intel root CA)")
			}

			if in.GatewayTDX.SignatureErr != nil {
				addFactor(TierGateway, "gateway_tdx_quote_signature", Fail, fmt.Sprintf("gateway quote signature invalid: %v", in.GatewayTDX.SignatureErr))
			} else {
				addFactor(TierGateway, "gateway_tdx_quote_signature", Pass, "gateway quote signature verified")
			}

			if in.GatewayTDX.DebugEnabled {
				addFactor(TierGateway, "gateway_tdx_debug_disabled", Fail, "gateway TD_ATTRIBUTES debug bit is set — debug enclave")
			} else {
				addFactor(TierGateway, "gateway_tdx_debug_disabled", Pass, "gateway debug bit is 0 (production enclave)")
			}
		}

		// Factor 30: gateway_compose_binding
		switch {
		case in.GatewayCompose == nil || !in.GatewayCompose.Checked:
			addFactor(TierGateway, "gateway_compose_binding", Skip, "no gateway app_compose in attestation response")
		case in.GatewayCompose.Err != nil:
			addFactor(TierGateway, "gateway_compose_binding", Fail, fmt.Sprintf("gateway compose binding failed: %v", in.GatewayCompose.Err))
		default:
			addFactor(TierGateway, "gateway_compose_binding", Pass, "gateway sha256(app_compose) matches MRConfigID")
		}
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

	metadata := buildMetadata(in)

	return &VerificationReport{
		Provider:  in.Provider,
		Model:     in.Model,
		Timestamp: time.Now(),
		Factors:   factors,
		Passed:    passed,
		Failed:    failed,
		Skipped:   skipped,
		Metadata:  metadata,
	}
}

type supplyChainPolicy struct {
	AllowedImageRepos  []string
	AllowedOIDCIssuers []string
	AllowedSourceRepos []string
}

func supplyChainPolicyForProvider(provider string) *supplyChainPolicy {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "nearai", "nearcloud":
		return &supplyChainPolicy{
			// Exact image names currently attested in NearAI compose.
			AllowedImageRepos: []string{
				"datadog/agent",
				"certbot/dns-cloudflare",
				"nearaidev/compose-manager",
			},
			AllowedOIDCIssuers: []string{"https://token.actions.githubusercontent.com"},
			// Exact Fulcio identities currently observed for NearAI-owned images.
			AllowedSourceRepos: []string{
				"nearai/compose-manager",
				"https://github.com/nearai/compose-manager",
			},
		}
	default:
		return nil
	}
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

	if len(m) == 0 {
		return nil
	}
	return m
}

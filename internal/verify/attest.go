package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/multi"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/tinfoil"
)

// fetchAttestation fetches raw attestation data from the provider with timing log.
func fetchAttestation(ctx context.Context, attester provider.Attester, providerName, modelName string, nonce attestation.Nonce) (*attestation.RawAttestation, error) {
	slog.Debug("attestation fetch starting", "provider", providerName, "model", modelName)
	fetchStart := time.Now()
	raw, err := attester.FetchAttestation(ctx, modelName, nonce)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation from %s model %s: %w", providerName, modelName, err)
	}
	slog.Debug("attestation fetch complete", "provider", providerName, "elapsed", time.Since(fetchStart))
	return raw, nil
}

// verifyTDX runs TDX quote verification and report data binding.
// Returns nil if no intel_quote is present.
func verifyTDX(ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce, providerName string, verifier attestation.TDXVerifier) *attestation.TDXVerifyResult {
	if raw.IntelQuote == "" {
		return nil
	}
	slog.Debug("TDX verification starting", "quote_len", len(raw.IntelQuote))
	tdxStart := time.Now()
	tdxResult := verifier(ctx, raw.IntelQuote)
	if rdVerifier := newReportDataVerifier(providerName); rdVerifier != nil && tdxResult.ParseErr == nil {
		detail, err := rdVerifier.VerifyReportData(tdxResult.ReportData, raw, nonce)
		if errors.Is(err, multi.ErrNoVerifier) {
			slog.Debug("no REPORTDATA verifier for backend format", "format", raw.BackendFormat)
		} else {
			tdxResult.ReportDataBindingErr = err
			tdxResult.ReportDataBindingDetail = detail
		}
	}
	slog.Debug("TDX verification complete", "elapsed", time.Since(tdxStart))
	return tdxResult
}

// verifySEV runs SEV-SNP report verification and report data binding.
// Returns nil if no SEV report is present.
func verifySEV(ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce, providerName string, verifier attestation.SEVVerifier) *attestation.SEVVerifyResult {
	if len(raw.SEVReportBytes) == 0 {
		return nil
	}
	slog.Debug("SEV-SNP verification starting", "report_len", len(raw.SEVReportBytes))
	sevStart := time.Now()
	sevResult := verifier(ctx, raw.SEVReportBytes)
	if rdVerifier := newReportDataVerifier(providerName); rdVerifier != nil && sevResult.ParseErr == nil {
		detail, err := rdVerifier.VerifyReportData(sevResult.ReportData, raw, nonce)
		if errors.Is(err, multi.ErrNoVerifier) {
			slog.Debug("no REPORTDATA verifier for backend format", "format", raw.BackendFormat)
		} else {
			sevResult.ReportDataBindingErr = err
			sevResult.ReportDataBindingDetail = detail
		}
	}
	slog.Debug("SEV-SNP verification complete", "elapsed", time.Since(sevStart))
	return sevResult
}

// verifyNVIDIA runs NVIDIA EAT and NRAS verification.
// Returns nil for either if not applicable.
func verifyNVIDIA(
	ctx context.Context,
	raw *attestation.RawAttestation,
	nonce attestation.Nonce,
	client *http.Client,
	offline bool,
	nv *attestation.NVIDIAVerifier,
	nrasJWTOpts ...jwt.ParserOption,
) (eat, nras *attestation.NvidiaVerifyResult) {
	if raw.NvidiaPayload != "" {
		slog.DebugContext(ctx, "NVIDIA verification starting", "payload_len", len(raw.NvidiaPayload))
		nvidiaStart := time.Now()
		eat = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce)
		slog.DebugContext(ctx, "NVIDIA verification complete", "elapsed", time.Since(nvidiaStart))
	} else if len(raw.GPUEvidence) > 0 {
		serverNonce, err := attestation.ParseNonce(raw.GPUVerificationNonce())
		if err != nil {
			slog.Error("parse server nonce for GPU verification", "err", err)
			eat = &attestation.NvidiaVerifyResult{
				SignatureErr: fmt.Errorf("parse server nonce: %w", err),
			}
			return eat, nil
		}
		slog.DebugContext(ctx, "NVIDIA GPU direct verification starting", "gpus", len(raw.GPUEvidence))
		nvidiaStart := time.Now()
		eat = attestation.VerifyNVIDIAGPUDirect(ctx, raw.GPUEvidence, serverNonce)
		slog.DebugContext(ctx, "NVIDIA GPU direct verification complete", "elapsed", time.Since(nvidiaStart))
	}
	if !offline && raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting")
		nrasStart := time.Now()
		nras = nv.VerifyNRAS(ctx, raw.NvidiaPayload, client, nrasJWTOpts...)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete", "elapsed", time.Since(nrasStart))
	} else if !offline && len(raw.GPUEvidence) > 0 {
		eatJSON := attestation.GPUEvidenceToEAT(raw.GPUEvidence, raw.Nonce)
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting (synthesized EAT)")
		nrasStart := time.Now()
		nras = nv.VerifyNRAS(ctx, eatJSON, client, nrasJWTOpts...)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete (synthesized EAT)", "elapsed", time.Since(nrasStart))
	}
	return eat, nras
}

func nrasJWTParserOptions(verificationTime time.Time) []jwt.ParserOption {
	if verificationTime.IsZero() {
		return nil
	}
	return []jwt.ParserOption{
		jwt.WithTimeFunc(func() time.Time { return verificationTime }),
		jwt.WithLeeway(10 * time.Second),
	}
}

// checkPoC runs a Proof of Cloud check for the given intel_quote.
// Returns nil if offline or quote is empty.
func checkPoC(ctx context.Context, quote string, client *http.Client, offline bool, verificationTime time.Time) *attestation.PoCResult {
	if offline || quote == "" {
		return nil
	}
	slog.Debug("Proof of Cloud check starting")
	pocStart := time.Now()
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, client).
		WithVerificationTime(verificationTime)
	result := poc.CheckQuote(ctx, quote)
	slog.Debug("Proof of Cloud check complete", "elapsed", time.Since(pocStart),
		"registered", result != nil && result.Registered)
	return result
}

// verifyNearcloudGateway verifies gateway TDX, compose binding, and PoC for
// providers that populate GatewayIntelQuote (nearcloud).
func verifyNearcloudGateway(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
	client *http.Client, offline bool, verifier attestation.TDXVerifier, verificationTime time.Time,
) (tdx *attestation.TDXVerifyResult, compose *attestation.ComposeBindingResult, poc *attestation.PoCResult) {
	if raw.GatewayIntelQuote == "" {
		return nil, nil, nil
	}
	slog.Debug("gateway TDX verification starting", "quote_len", len(raw.GatewayIntelQuote))
	tdx = verifier(ctx, raw.GatewayIntelQuote)
	if tdx.ParseErr == nil {
		detail, rdErr := nearcloud.GatewayReportDataVerifier{}.VerifyReportData(
			tdx.ReportData, raw, nonce)
		tdx.ReportDataBindingErr = rdErr
		tdx.ReportDataBindingDetail = detail
	}
	if raw.GatewayAppCompose != "" && tdx.ParseErr == nil {
		compose = &attestation.ComposeBindingResult{Checked: true}
		compose.Err = attestation.VerifyComposeBinding(raw.GatewayAppCompose, tdx.MRConfigID)
	}
	poc = checkPoC(ctx, raw.GatewayIntelQuote, client, offline, verificationTime)
	slog.Debug("gateway TDX verification complete")
	return tdx, compose, poc
}

// checkSigstore checks sigstore digests and fetches Rekor provenance for matches.
func checkSigstore(
	ctx context.Context,
	digests []string,
	digestToRepo map[string]string,
	scPolicy *attestation.SupplyChainPolicy,
	client *http.Client,
	offline bool,
) ([]attestation.SigstoreResult, []attestation.RekorProvenance) {
	if len(digests) == 0 || offline {
		return nil, nil
	}
	rc := attestation.NewRekorClient(client)
	sigstoreResults := rc.CheckSigstoreDigests(ctx, digests)
	for _, r := range sigstoreResults {
		switch {
		case r.OK:
			slog.Info("Sigstore check passed", "digest", "sha256:"+r.Digest[:min(16, len(r.Digest))]+"...", "status", r.Status)
		case r.Err != nil:
			slog.Warn("Sigstore check failed", "digest", "sha256:"+r.Digest[:min(16, len(r.Digest))]+"...", "err", r.Err)
		default:
			slog.Warn("Sigstore check failed", "digest", "sha256:"+r.Digest[:min(16, len(r.Digest))]+"...", "status", r.Status)
		}
	}
	var okDigests []string
	for _, sr := range sigstoreResults {
		if sr.OK {
			slog.Info("fetching Rekor provenance", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...")
			okDigests = append(okDigests, sr.Digest)
		}
	}
	if len(okDigests) == 0 {
		return sigstoreResults, nil
	}
	rekorResults := rc.FetchRekorProvenancesForPolicy(ctx, okDigests, digestToRepo, scPolicy)
	for i := range rekorResults {
		prov := &rekorResults[i]
		d := okDigests[i]
		switch {
		case prov.Err != nil:
			slog.Warn("Rekor provenance fetch failed", "digest", "sha256:"+d[:min(16, len(d))]+"...", "err", prov.Err)
		case prov.HasCert:
			slog.Info("Rekor provenance found",
				"digest", "sha256:"+d[:min(16, len(d))]+"...",
				"issuer", prov.OIDCIssuer,
				"repo", prov.SourceRepo,
				"commit", prov.SourceCommit[:min(7, len(prov.SourceCommit))],
				"runner", prov.RunnerEnv,
			)
		default:
			slog.Info("Rekor entry has raw public key (no Fulcio provenance)", "digest", "sha256:"+d[:min(16, len(d))]+"...")
		}
	}
	return sigstoreResults, rekorResults
}

// verifyTinfoilSupplyChain performs Tinfoil-specific Sigstore supply chain
// verification and code/hardware measurement comparison. Returns nil for
// non-Tinfoil providers.
//
// providerName determines which Sigstore repo to verify against:
// tinfoil_v3_cloud attests the router enclave (confidential-model-router),
// while tinfoil_v3_direct attests per-model inference enclaves.
func verifyTinfoilSupplyChain(
	ctx context.Context,
	raw *attestation.RawAttestation,
	tdxResult *attestation.TDXVerifyResult,
	sevResult *attestation.SEVVerifyResult,
	providerName, modelName string,
	policy attestation.MeasurementPolicy,
	offline bool,
	client *http.Client,
) *attestation.TinfoilSupplyChainResult {
	if raw.BackendFormat != attestation.FormatTinfoil {
		return nil
	}
	// Use the repo from the proxy discovery endpoint if available (direct
	// provider), otherwise fall back to RepoForProvider. The proxy endpoint
	// returns the correct repo name which may differ from the convention
	// (e.g. "glm-5-2" → "tinfoilsh/confidential-glm5-2" not "confidential-glm-5-2").
	sigstoreRepo := raw.TinfoilRepo
	if sigstoreRepo == "" {
		sigstoreRepo = tinfoil.RepoForProvider(providerName, modelName)
	}
	if sigstoreRepo == "" {
		return &attestation.TinfoilSupplyChainResult{
			SigstoreErr: fmt.Errorf("no Tinfoil Sigstore repo for provider %q model %q", providerName, modelName),
		}
	}
	slog.Debug("Tinfoil supply chain verification starting", "repo", sigstoreRepo)
	start := time.Now()
	result := &attestation.TinfoilSupplyChainResult{ComponentRepos: []string{sigstoreRepo}}

	// Check GPU hash bound from REPORTDATA verification detail.
	bindingDetail := ""
	if tdxResult != nil {
		bindingDetail = tdxResult.ReportDataBindingDetail
	} else if sevResult != nil {
		bindingDetail = sevResult.ReportDataBindingDetail
	}
	result.GPUHashBound = strings.Contains(bindingDetail, "gpu_bound=true")
	result.NVSwitchHashBound = strings.Contains(bindingDetail, "nvswitch_bound=true")
	result.NVSwitchExpected = strings.Contains(bindingDetail, "nvswitch_bound=")

	// TDX policy checks.
	if tdxResult != nil && tdxResult.ParseErr == nil {
		pol := tinfoil.CheckTDXPolicy(tdxResult, policy.MRSeamAllow)
		result.TDXPolicyErr = pol.Err()
		if result.TDXPolicyErr == nil {
			result.TDXPolicyDetail = "Tinfoil TDX policy: TD_ATTRIBUTES, XFAM, MR_SEAM, MR registers, RTMR3, TEE_TCB_SVN all pass"
		} else {
			result.TDXPolicyDetail = fmt.Sprintf("Tinfoil TDX policy checks failed: %v", result.TDXPolicyErr)
		}
	}

	if offline {
		slog.Debug("Tinfoil supply chain: skipping Sigstore fetch (offline mode)")
		return result
	}

	// Sigstore DSSE bundle verification.
	if client == nil {
		client = config.NewAttestationClient(offline)
	}
	sv := tinfoil.NewSigstoreVerifier(client)
	predicateBytes, predicateType, err := sv.FetchAndVerify(ctx, sigstoreRepo)
	if err != nil {
		result.SigstoreErr = err
		result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: sigstoreRepo, SigstoreErr: err})
		slog.WarnContext(ctx, "Tinfoil Sigstore verification failed",
			"repo", sigstoreRepo, "err", err)
		return result
	}
	result.SigstoreVerified = true
	result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: sigstoreRepo, SigstoreVerified: true})
	result.SigstoreDetail = fmt.Sprintf("Sigstore DSSE verified for %s (predicate: %s)", sigstoreRepo, predicateType)

	// Parse code measurements from the verified predicate.
	if predicateType != tinfoil.PredicateMultiPlatform {
		result.CodeMatchErr = fmt.Errorf("unexpected predicate type %q, want %q", predicateType, tinfoil.PredicateMultiPlatform)
		return result
	}
	codeMeasurements, err := tinfoil.ParseMultiPlatformPredicate(predicateBytes)
	if err != nil {
		result.CodeMatchErr = fmt.Errorf("parse multi-platform predicate: %w", err)
		return result
	}

	// Build enclave measurements and compare.
	switch {
	case tdxResult != nil && tdxResult.ParseErr == nil:
		enclave := tinfoil.EnclaveMeasurementsFromTDX(tdxResult)
		if err := tinfoil.CompareMultiPlatformTDX(codeMeasurements, enclave); err != nil {
			result.CodeMatchErr = err
		} else {
			result.CodeMatch = true
			result.CodeMatchDetail = fmt.Sprintf("TDX code measurements match Sigstore predicate (RTMR1=%s..., RTMR2=%s...)",
				truncTo(codeMeasurements.RTMR1, 16), truncTo(codeMeasurements.RTMR2, 16))
		}

		// Hardware measurement match (TDX only).
		result.ComponentRepos = append(result.ComponentRepos, "tinfoilsh/hardware-measurements")
		hwPredBytes, hwPredType, hwErr := sv.FetchAndVerify(ctx, "tinfoilsh/hardware-measurements")
		switch {
		case hwErr != nil:
			result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: "tinfoilsh/hardware-measurements", SigstoreErr: hwErr})
			result.HWMatchErr = fmt.Errorf("fetch hardware measurements: %w", hwErr)
		case hwPredType != tinfoil.PredicateHardwareMeasurements:
			result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: "tinfoilsh/hardware-measurements", SigstoreErr: fmt.Errorf("unexpected hardware predicate type %q", hwPredType)})
			result.HWMatchErr = fmt.Errorf("unexpected hardware predicate type %q", hwPredType)
		default:
			result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: "tinfoilsh/hardware-measurements", SigstoreVerified: true})
			entries, parseErr := tinfoil.ParseHardwareMeasurements(hwPredBytes)
			if parseErr != nil {
				result.HWMatchErr = fmt.Errorf("parse hardware measurements: %w", parseErr)
			} else if matchID, matchErr := tinfoil.MatchHardwareMeasurements(entries, enclave); matchErr != nil {
				result.HWMatchErr = matchErr
			} else {
				result.HWMatch = matchID
			}
		}

	case sevResult != nil && sevResult.ParseErr == nil:
		enclave := tinfoil.EnclaveMeasurementsFromSEV(sevResult)
		if err := tinfoil.CompareMultiPlatformSEVSNP(codeMeasurements, enclave); err != nil {
			result.CodeMatchErr = err
		} else {
			result.CodeMatch = true
			result.CodeMatchDetail = fmt.Sprintf("SEV-SNP code measurement matches Sigstore predicate (%s...)",
				truncTo(codeMeasurements.SNPMeasurement, 16))
		}

	default:
		result.CodeMatchErr = errors.New("no parseable TDX or SEV-SNP result for code measurement comparison")
	}

	slog.Debug("Tinfoil supply chain verification complete", "elapsed", time.Since(start))
	return result
}

// truncTo returns the first n characters of s, or s itself if shorter.
func truncTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

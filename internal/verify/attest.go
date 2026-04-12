package verify

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/nearcloud"
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
		tdxResult.ReportDataBindingErr = err
		tdxResult.ReportDataBindingDetail = detail
	}
	slog.Debug("TDX verification complete", "elapsed", time.Since(tdxStart))
	return tdxResult
}

// verifyNVIDIA runs NVIDIA EAT and NRAS verification.
// Returns nil for either if not applicable.
func verifyNVIDIA(ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce, client *http.Client, offline bool) (eat, nras *attestation.NvidiaVerifyResult) {
	if raw.NvidiaPayload != "" {
		slog.DebugContext(ctx, "NVIDIA verification starting", "payload_len", len(raw.NvidiaPayload))
		nvidiaStart := time.Now()
		eat = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, nonce)
		slog.DebugContext(ctx, "NVIDIA verification complete", "elapsed", time.Since(nvidiaStart))
	} else if len(raw.GPUEvidence) > 0 {
		serverNonce, err := attestation.ParseNonce(raw.Nonce)
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
		nras = attestation.VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete", "elapsed", time.Since(nrasStart))
	} else if !offline && len(raw.GPUEvidence) > 0 {
		eatJSON := attestation.GPUEvidenceToEAT(raw.GPUEvidence, raw.Nonce)
		slog.DebugContext(ctx, "NVIDIA NRAS verification starting (synthesized EAT)")
		nrasStart := time.Now()
		nras = attestation.VerifyNVIDIANRAS(ctx, eatJSON, client)
		slog.DebugContext(ctx, "NVIDIA NRAS verification complete (synthesized EAT)", "elapsed", time.Since(nrasStart))
	}
	return eat, nras
}

// checkPoC runs a Proof of Cloud check for the given intel_quote.
// Returns nil if offline or quote is empty.
func checkPoC(ctx context.Context, quote string, client *http.Client, offline bool) *attestation.PoCResult {
	if offline || quote == "" {
		return nil
	}
	slog.Debug("Proof of Cloud check starting")
	pocStart := time.Now()
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, client)
	result := poc.CheckQuote(ctx, quote)
	slog.Debug("Proof of Cloud check complete", "elapsed", time.Since(pocStart),
		"registered", result != nil && result.Registered)
	return result
}

// verifyNearcloudGateway verifies gateway TDX, compose binding, and PoC for
// providers that populate GatewayIntelQuote (nearcloud).
func verifyNearcloudGateway(
	ctx context.Context, raw *attestation.RawAttestation, nonce attestation.Nonce,
	client *http.Client, offline bool, verifier attestation.TDXVerifier,
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
	poc = checkPoC(ctx, raw.GatewayIntelQuote, client, offline)
	slog.Debug("gateway TDX verification complete")
	return tdx, compose, poc
}

// checkSigstore checks sigstore digests and fetches Rekor provenance for matches.
func checkSigstore(ctx context.Context, digests []string, client *http.Client, offline bool) ([]attestation.SigstoreResult, []attestation.RekorProvenance) {
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
	var rekorResults []attestation.RekorProvenance
	for _, sr := range sigstoreResults {
		if !sr.OK {
			continue
		}
		slog.Info("fetching Rekor provenance", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...")
		prov := rc.FetchRekorProvenance(ctx, sr.Digest)
		switch {
		case prov.Err != nil:
			slog.Warn("Rekor provenance fetch failed", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...", "err", prov.Err)
		case prov.HasCert:
			slog.Info("Rekor provenance found",
				"digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...",
				"issuer", prov.OIDCIssuer,
				"repo", prov.SourceRepo,
				"commit", prov.SourceCommit[:min(7, len(prov.SourceCommit))],
				"runner", prov.RunnerEnv,
			)
		default:
			slog.Info("Rekor entry has raw public key (no Fulcio provenance)", "digest", "sha256:"+sr.Digest[:min(16, len(sr.Digest))]+"...")
		}
		rekorResults = append(rekorResults, prov)
	}
	return sigstoreResults, rekorResults
}

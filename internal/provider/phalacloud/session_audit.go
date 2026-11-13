package phalacloud

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/chutes"
	"github.com/google/go-tdx-guest/pcs"
)

// SessionAuditor verifies the evidence of an attested session (ACI/1 §9.2
// step 4, the deep audit) before teep pins the session. Every check is
// enforced; a session that fails one is not pinned:
//
//  1. the TDX quote: structure, Intel certificate chain, signature, debug
//     off, and online a TCB that is UpToDate (not revoked);
//  2. MRTD and MRSEAM: the Phala model CVM against the dstack base list,
//     a Chutes instance against the Chutes list;
//  3. REPORTDATA with the format's scheme and the session's own nonce;
//  4. the channel binding and, for the Phala model CVM, the identity name
//     the key and the address of the evidence (sessionEvidenceOf);
//  5. the GPU evidence, verified locally with the session's nonce;
//  6. for the Phala model CVM, the compose binding (MRConfigID) and the
//     event-log replay of the quote's RTMRs.
//
// teep has no policy for the RTMR values, the compose content or the
// images of the Phala model CVM, and sends no Sigstore, Proof of Cloud or
// NRAS request for a session.
type SessionAuditor struct {
	// TDX verifies a quote; online it fetches Intel PCS collateral.
	TDX attestation.TDXVerifier
	// Offline skips the TCB check, which needs Intel PCS collateral.
	Offline bool
}

// Audit returns nil when every check passes for s, a full session record.
func (a SessionAuditor) Audit(ctx context.Context, s *aci.Session) error {
	ev, err := sessionEvidenceOf(ctx, s)
	if err != nil {
		return err
	}
	for _, path := range ev.unknown {
		s.Unknown = append(s.Unknown, "evidence."+path)
	}
	return a.auditEvidence(ctx, s, ev)
}

func (a SessionAuditor) auditEvidence(ctx context.Context, s *aci.Session, ev *sessionEvidence) error {
	tdx := a.TDX(ctx, ev.raw.IntelQuote)
	if err := a.checkQuote(tdx); err != nil {
		return err
	}
	if err := checkSessionMeasurements(tdx, sessionMeasurementPolicy(s)); err != nil {
		return err
	}
	if _, err := ev.reportData.VerifyReportData(tdx.ReportData, ev.raw, ev.nonce); err != nil {
		return fmt.Errorf("REPORTDATA: %w", err)
	}
	if err := checkSessionGPU(ctx, ev); err != nil {
		return err
	}
	if s.VerifierID == verifierPhalaDirect {
		return checkModelCVMIntegrity(ev.raw, tdx)
	}
	return nil
}

func (a SessionAuditor) checkQuote(tdx *attestation.TDXVerifyResult) error {
	switch {
	case tdx == nil:
		return errors.New("TDX quote not verified")
	case tdx.ParseErr != nil:
		return fmt.Errorf("TDX quote: %w", tdx.ParseErr)
	case tdx.CertChainErr != nil:
		return fmt.Errorf("TDX quote certificate chain: %w", tdx.CertChainErr)
	case tdx.SignatureErr != nil:
		return fmt.Errorf("TDX quote signature: %w", tdx.SignatureErr)
	case tdx.DebugEnabled:
		return errors.New("TDX quote has debug enabled")
	}
	if a.Offline {
		return nil
	}
	if tdx.CollateralErr != nil {
		return fmt.Errorf("TDX collateral: %w", tdx.CollateralErr)
	}
	if tdx.TcbStatus != pcs.TcbComponentStatusUpToDate {
		return fmt.Errorf("TDX TCB status is %q, not UpToDate", tdx.TcbStatus)
	}
	return nil
}

// sessionMeasurementPolicy is the MRTD and MRSEAM policy of the session's
// upstream: the Phala model CVM runs dstack, a Chutes instance sek8s.
func sessionMeasurementPolicy(s *aci.Session) attestation.MeasurementPolicy {
	if s.VerifierID == verifierChutes {
		return chutes.DefaultMeasurementPolicy()
	}
	return attestation.DstackBaseMeasurementPolicy()
}

func checkSessionMeasurements(tdx *attestation.TDXVerifyResult, policy attestation.MeasurementPolicy) error {
	if !policy.HasMRTDPolicy() || !policy.HasMRSeamPolicy() {
		return errors.New("no MRTD and MRSEAM policy")
	}
	if _, ok := policy.MRTDAllow[hex.EncodeToString(tdx.MRTD)]; !ok {
		return fmt.Errorf("MRTD %s is not allowed", hex.EncodeToString(tdx.MRTD))
	}
	if _, ok := policy.MRSeamAllow[hex.EncodeToString(tdx.MRSeam)]; !ok {
		return fmt.Errorf("MRSEAM %s is not allowed", hex.EncodeToString(tdx.MRSeam))
	}
	return nil
}

// checkSessionGPU verifies the GPU evidence locally, without NRAS. The
// Phala model CVM carries an NVIDIA payload that answers the session nonce;
// a Chutes instance carries SPDM evidence that answers the requester nonce
// derived from the session nonce and its key (chutes.GPURequesterNonce).
func checkSessionGPU(ctx context.Context, ev *sessionEvidence) error {
	var result *attestation.NvidiaVerifyResult
	switch {
	case ev.raw.NvidiaPayload != "":
		result = attestation.VerifyNVIDIAPayload(ctx, ev.raw.NvidiaPayload, ev.nonce)
	case len(ev.raw.GPUEvidence) > 0:
		requester, err := chutes.GPURequesterNonce(ev.nonce, ev.raw.SigningKey)
		if err != nil {
			return fmt.Errorf("GPU evidence: %w", err)
		}
		result = attestation.VerifyNVIDIAGPUDirect(ctx, ev.raw.GPUEvidence, ev.nonce, requester)
	default:
		return errors.New("session has no GPU evidence")
	}
	switch {
	case result.SignatureErr != nil:
		return fmt.Errorf("GPU evidence: %w", result.SignatureErr)
	case result.ClaimsErr != nil:
		return fmt.Errorf("GPU evidence claims: %w", result.ClaimsErr)
	case result.GPUCount == 0:
		return errors.New("GPU evidence lists no GPU")
	case subtle.ConstantTimeCompare([]byte(result.Nonce), []byte(ev.nonce.Hex())) != 1:
		return errors.New("GPU evidence does not answer the session nonce")
	}
	return nil
}

// checkModelCVMIntegrity requires the quote's MRConfigID to bind the app
// compose, and the event log to reproduce RTMR0-3 of the quote.
func checkModelCVMIntegrity(raw *attestation.RawAttestation, tdx *attestation.TDXVerifyResult) error {
	if err := attestation.VerifyComposeBinding(raw.AppCompose, tdx.MRConfigID); err != nil {
		return fmt.Errorf("compose binding: %w", err)
	}
	rtmrs, err := attestation.ReplayEventLog(raw.EventLog)
	if err != nil {
		return fmt.Errorf("event log: %w", err)
	}
	for i := range rtmrs {
		if subtle.ConstantTimeCompare(rtmrs[i][:], tdx.RTMRs[i][:]) != 1 {
			return fmt.Errorf("event log does not reproduce RTMR%d of the quote", i)
		}
	}
	return nil
}

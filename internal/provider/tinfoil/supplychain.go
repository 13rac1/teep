package tinfoil

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/13rac1/teep/internal/attestation"
)

// VerifySupplyChain checks a Tinfoil enclave's quote against its signed
// releases: the code release for RTMR1 and RTMR2 (TDX) or the launch
// measurement (SEV-SNP), and, for TDX, the platform release for MRTD and
// RTMR0. repo is the code repo the caller expects; the release the enclave
// names in its collateral must be in it.
//
// now is the time freshness witnesses are checked against; zero means the wall
// clock. With client nil (offline) it runs only the checks that need no
// network: the GPU binding flags and the TDX policy.
func VerifySupplyChain(
	ctx context.Context,
	client *http.Client,
	raw *attestation.RawAttestation,
	repo string,
	tdx *attestation.TDXVerifyResult,
	sev *attestation.SEVVerifyResult,
	mrSeamAllow map[string]struct{},
	now time.Time,
) *attestation.TinfoilSupplyChainResult {
	result := &attestation.TinfoilSupplyChainResult{}
	if now.IsZero() {
		now = time.Now()
	}

	bindingDetail := ""
	if tdx != nil {
		bindingDetail = tdx.ReportDataBindingDetail
	} else if sev != nil {
		bindingDetail = sev.ReportDataBindingDetail
	}
	result.GPUHashBound = strings.Contains(bindingDetail, "gpu_bound=true")
	result.NVSwitchHashBound = strings.Contains(bindingDetail, "nvswitch_bound=true")
	result.NVSwitchExpected = strings.Contains(bindingDetail, "nvswitch_bound=")

	tdxOK := tdx != nil && tdx.ParseErr == nil
	if tdxOK {
		pol := CheckTDXPolicy(tdx, mrSeamAllow)
		result.TDXPolicyErr = pol.Err()
		if result.TDXPolicyErr == nil {
			result.TDXPolicyDetail = "Tinfoil TDX policy: TD_ATTRIBUTES, XFAM, MR_SEAM, MR registers, RTMR3, TEE_TCB_SVN all pass"
		} else {
			result.TDXPolicyDetail = fmt.Sprintf("Tinfoil TDX policy checks failed: %v", result.TDXPolicyErr)
		}
	}
	if client == nil {
		return result
	}
	sv := NewSigstoreVerifier(client)

	code := raw.TinfoilCodeRelease
	predicateBytes, predicateType, signer, err := verifyNamedRelease(ctx, sv, code, "code", repo, now)
	if err != nil {
		result.SigstoreErr = err
		result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: repo, SigstoreErr: err})
		return result
	}
	result.SigstoreVerified = true
	result.Components = append(result.Components, attestation.TinfoilComponentResult{
		Repo: repo, SigstoreVerified: true, OIDCIssuer: signer.OIDCIssuer, SAN: signer.SAN,
	})
	result.SigstoreDetail = fmt.Sprintf("Sigstore DSSE verified for %s@%s, witnessed fresh (predicate: %s)",
		repo, code.Tag, predicateType)

	if predicateType != PredicateMultiPlatform {
		result.CodeMatchErr = fmt.Errorf("unexpected predicate type %q, want %q", predicateType, PredicateMultiPlatform)
		return result
	}
	codeMeasurements, err := ParseMultiPlatformPredicate(predicateBytes)
	if err != nil {
		result.CodeMatchErr = fmt.Errorf("parse multi-platform predicate: %w", err)
		return result
	}

	switch {
	case tdxOK:
		enclave := EnclaveMeasurementsFromTDX(tdx)
		if err := CompareMultiPlatformTDX(codeMeasurements, enclave); err != nil {
			result.CodeMatchErr = err
		} else {
			result.CodeMatch = true
			result.CodeMatchDetail = fmt.Sprintf("TDX code measurements match %s@%s (RTMR1=%.16s..., RTMR2=%.16s...)",
				repo, code.Tag, codeMeasurements.RTMR1, codeMeasurements.RTMR2)
		}
		verifyPlatform(ctx, sv, raw.TinfoilPlatformRelease, enclave, result, now)

	case sev != nil && sev.ParseErr == nil:
		enclave := EnclaveMeasurementsFromSEV(sev)
		if err := CompareMultiPlatformSEVSNP(codeMeasurements, enclave); err != nil {
			result.CodeMatchErr = err
		} else {
			result.CodeMatch = true
			result.CodeMatchDetail = fmt.Sprintf("SEV-SNP launch measurement matches %s@%s (%.16s...)",
				repo, code.Tag, codeMeasurements.SNPMeasurement)
		}

	default:
		result.CodeMatchErr = errors.New("no parseable TDX or SEV-SNP result for code measurement comparison")
	}
	return result
}

// verifyPlatform matches the TDX MRTD and RTMR0 against the platform release
// the enclave names.
func verifyPlatform(ctx context.Context, sv *SigstoreVerifier, rel attestation.TinfoilRelease,
	enclave *EnclaveMeasurements, result *attestation.TinfoilSupplyChainResult, now time.Time,
) {
	predicateBytes, predicateType, signer, err := verifyNamedRelease(ctx, sv, rel, "platform", PlatformRepo, now)
	if err == nil && predicateType != PredicatePlatformEndorsements {
		err = fmt.Errorf("unexpected platform predicate type %q", predicateType)
	}
	if err != nil {
		result.Components = append(result.Components, attestation.TinfoilComponentResult{Repo: PlatformRepo, SigstoreErr: err})
		result.HWMatchErr = fmt.Errorf("platform release: %w", err)
		return
	}
	result.Components = append(result.Components, attestation.TinfoilComponentResult{
		Repo: PlatformRepo, SigstoreVerified: true, OIDCIssuer: signer.OIDCIssuer, SAN: signer.SAN,
	})
	entries, err := ParsePlatformMeasurements(predicateBytes)
	if err != nil {
		result.HWMatchErr = err
		return
	}
	shape, err := MatchHardwareMeasurements(entries, enclave)
	if err != nil {
		result.HWMatchErr = fmt.Errorf("%s@%s: %w", PlatformRepo, rel.Tag, err)
		return
	}
	result.HWMatch = shape + " in " + PlatformRepo + "@" + rel.Tag
}

// verifyNamedRelease verifies the release named in one collateral entry,
// which must belong to wantRepo.
func verifyNamedRelease(ctx context.Context, sv *SigstoreVerifier, rel attestation.TinfoilRelease, entry, wantRepo string, now time.Time,
) (predicateBytes []byte, predicateType string, signer SignerIdentity, err error) {
	if rel.Repo == "" {
		return nil, "", SignerIdentity{}, fmt.Errorf("the enclave names no %s release in its collateral", entry)
	}
	if rel.Repo != wantRepo {
		return nil, "", SignerIdentity{}, fmt.Errorf("the enclave's %s release is in %s, want %s", entry, rel.Repo, wantRepo)
	}
	return sv.VerifyRelease(ctx, rel, now)
}

package aci

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/jsonstrict"
)

// CanonicalPath is the path of the ACI/1 attestation report (§4). ACI/1
// verifiers use the /v1/aci/* routes; other routes are optional for a
// service.
const CanonicalPath = "/v1/aci/attestation"

// aciCanonicalReport is the ACI/1 §4.1 report that GET /v1/aci/attestation
// serves. Unlike the Venice and the gateway variants of the compatibility
// route, it carries no dstack-compatible fields, and its quote binds the
// whole workload keyset through the §3.2 statement.
type aciCanonicalReport struct {
	APIVersion           string         `json:"api_version"`
	WorkloadKeysetDigest string         `json:"workload_keyset_digest"`
	Attestation          aciAttestation `json:"attestation"`
	ServiceCapabilities  aciServiceCaps `json:"service_capabilities"`
}

// ParseCanonical parses the ACI/1 report of /v1/aci/attestation. At every
// depth, every member must be one that §4.1 defines and none may be absent;
// duplicate member names fail (jsonstrict checks all three at every depth).
// The E2EE key that teep encrypts to is the single keyset entry of the E2EE
// v2 secp256k1 suite. provider names the provider in errors.
func ParseCanonical(ctx context.Context, body []byte, provider string) (*attestation.RawAttestation, error) {
	var report aciCanonicalReport
	unknown, missing, err := jsonstrict.Unmarshal(body, &report)
	if err != nil {
		return nil, fmt.Errorf("%s aci/1: unmarshal attestation report: %w", provider, err)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%s aci/1: attestation report has undefined fields %q", provider, unknown)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s aci/1: attestation report lacks fields %q", provider, missing)
	}
	if report.APIVersion != "aci/1" {
		return nil, fmt.Errorf("%s aci/1: attestation report api_version is %q, want aci/1", provider, report.APIVersion)
	}
	key, err := canonicalE2EEKey(&report.Attestation.WorkloadKeyset)
	if err != nil {
		return nil, fmt.Errorf("%s aci/1: %w", provider, err)
	}
	raw, err := aciToRaw(ctx, &aciResponse{
		APIVersion:           report.APIVersion,
		WorkloadKeysetDigest: report.WorkloadKeysetDigest,
		Attestation:          report.Attestation,
		ServiceCapabilities:  report.ServiceCapabilities,
		SigningKey:           key,
	}, nil, nil, body, provider)
	if err != nil {
		return nil, err
	}
	raw.ACICanonicalReport = true
	ks := &report.Attestation.WorkloadKeyset
	for _, k := range ks.ReceiptSigningKeys {
		raw.ACIReceiptKeys = append(raw.ACIReceiptKeys, attestation.ACIReceiptKey{KeyID: k.KeyID, Algo: k.Algo, PublicKey: strings.ToLower(k.PublicKey)})
	}
	notAfter, err := ks.NotAfter.Int64()
	if err != nil {
		return nil, fmt.Errorf("%s aci/1: keyset not_after: %w", provider, err)
	}
	raw.ACIKeysetNotAfter = notAfter
	return raw, nil
}

// canonicalE2EEKey returns the public key of the single keyset E2EE entry of
// the E2EE v2 secp256k1 suite, a 130-hex-character uncompressed key.
func canonicalE2EEKey(keyset *aciWorkloadKeyset) (string, error) {
	var key string
	for i := range keyset.E2EEPublicKeys {
		if keyset.E2EEPublicKeys[i].Algo != e2ee.ACIv2Algo {
			continue
		}
		if key != "" {
			return "", fmt.Errorf("workload keyset lists more than one %s key", e2ee.ACIv2Algo)
		}
		key = keyset.E2EEPublicKeys[i].PublicKey
	}
	if len(key) != 130 || key[:2] != "04" {
		return "", fmt.Errorf("workload keyset has no uncompressed %s key", e2ee.ACIv2Algo)
	}
	return key, nil
}

// StatementReportDataVerifier verifies the REPORTDATA of the canonical
// ACI/1 report: sha256 of the §3.2 statement over the workload keyset digest
// and the client nonce, followed by 32 zero bytes. It recomputes the keyset
// digest from the keyset, so the quote binds every keyset field: the E2EE,
// receipt and TLS keys and the expiry.
type StatementReportDataVerifier struct{}

// VerifyReportData implements provider.ReportDataVerifier.
func (StatementReportDataVerifier) VerifyReportData(reportData [64]byte, raw *attestation.RawAttestation, nonce attestation.Nonce) (string, error) {
	if !raw.ACICanonicalReport {
		return "", errors.New("the ACI/1 statement binding needs the report of " + CanonicalPath)
	}
	keyset, ok := raw.ACIWorkloadKeyset.(*aciWorkloadKeyset)
	if !ok || keyset == nil {
		return "", errors.New("ACI/1 workload keyset not available")
	}
	value, err := keyset.toCanonicalValue()
	if err != nil {
		return "", fmt.Errorf("canonicalize workload keyset: %w", err)
	}
	digest, err := jcsSHA256Hex(value)
	if err != nil {
		return "", fmt.Errorf("workload keyset digest: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(raw.ACIWorkloadKeysetDigest)) != 1 {
		return "", fmt.Errorf("declared workload_keyset_digest %q is not the digest of the keyset (%s)", raw.ACIWorkloadKeysetDigest, digest)
	}
	statement := `{"keyset_digest":"` + digest + `","nonce":"` + nonce.Hex() + `","purpose":"aci.report_data.v1"}`
	sum := sha256.Sum256([]byte(statement))
	var want [64]byte
	copy(want[:32], sum[:])
	if subtle.ConstantTimeCompare(reportData[:], want[:]) != 1 {
		return "", errors.New("REPORTDATA is not sha256 of the ACI/1 statement over the keyset digest and the client nonce")
	}
	return fmt.Sprintf("REPORTDATA binds the keyset digest %s... and the client nonce (ACI/1 §3.2)", digest[:min(len(digest), 23)]), nil
}

// TLSKeyForDomain returns the SPKI SHA-256 fingerprint (64 lowercase hex
// characters) that the canonical report's keyset lists for domain. The
// keyset must list exactly one entry for the domain, and the report's
// downstream_tls_binding must name the same domain and fingerprint (ACI/1
// §4.2). The quote binds the keyset through the §3.2 statement, so the
// fingerprint is hardware-bound once StatementReportDataVerifier passes.
func TLSKeyForDomain(raw *attestation.RawAttestation, domain string) (string, error) {
	if !raw.ACICanonicalReport {
		return "", errors.New("the keyset TLS key needs the report of " + CanonicalPath)
	}
	keyset, ok := raw.ACIWorkloadKeyset.(*aciWorkloadKeyset)
	if !ok || keyset == nil {
		return "", errors.New("ACI/1 workload keyset not available")
	}
	var spki string
	for i := range keyset.TLSPublicKeys {
		if keyset.TLSPublicKeys[i].Domain != domain {
			continue
		}
		if spki != "" {
			return "", fmt.Errorf("workload keyset lists more than one TLS key for %s", domain)
		}
		spki = strings.ToLower(keyset.TLSPublicKeys[i].SPKISHA256)
	}
	if len(spki) != 64 {
		return "", fmt.Errorf("workload keyset lists no TLS key for %s", domain)
	}
	if raw.ACIDownstreamTLSDomain != domain ||
		subtle.ConstantTimeCompare([]byte(strings.ToLower(raw.ACIDownstreamTLSSPKI)), []byte(spki)) != 1 {
		return "", fmt.Errorf("downstream_tls_binding names %q, not the keyset TLS key of %s", raw.ACIDownstreamTLSDomain, domain)
	}
	return spki, nil
}

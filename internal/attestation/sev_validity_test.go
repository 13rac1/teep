package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

// These cases isolate date extraction after verification. The online test below
// exercises the production certificate-chain and report-signature verification.
func TestSEVCertificateValiditySelection(t *testing.T) {
	vcekExpiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	vlekExpiry := vcekExpiry.AddDate(1, 0, 0)
	vcek := sevValidityCertificate(t, vcekExpiry)
	vlek := sevValidityCertificate(t, vlekExpiry)
	early := sevValidityCertificate(t, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	late := sevValidityCertificate(t, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	zero := sevValidityCertificate(t, time.Time{})
	// These are the embedded AMD root expirations, independent of supplied issuers.
	milanRootExpiry := time.Date(2045, 10, 22, 17, 23, 5, 0, time.UTC)
	genoaRootExpiry := time.Date(2047, 1, 26, 15, 34, 37, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*pb.Attestation)
		want   time.Time // Zero means the extraction must fail.
	}{
		{"vcek", func(*pb.Attestation) {}, vcekExpiry},
		// The dependency's default roots currently contain no trusted ASVK.
		{"vlek_missing_trusted_asvk", func(a *pb.Attestation) {
			a.Report.SignerInfo = sevabi.ComposeSignerInfo(sevabi.SignerInfo{SigningKey: sevabi.VlekReportSigner})
		}, time.Time{}},
		{"ignore_early_supplied_issuers", func(a *pb.Attestation) {
			a.CertificateChain.AskCert, a.CertificateChain.ArkCert = early, early
		}, vcekExpiry},
		{"trusted_root_bounds_vcek", func(a *pb.Attestation) {
			a.CertificateChain.VcekCert = late
		}, milanRootExpiry},
		{"cpuid_selects_trusted_product", func(a *pb.Attestation) {
			a.Report.Cpuid1EaxFms = sevabi.MaskedCpuid1EaxFromSevProduct(&pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_GENOA})
			a.CertificateChain.VcekCert = late
		}, genoaRootExpiry},
		{"missing_selected_vlek", func(a *pb.Attestation) {
			a.Report.SignerInfo = sevabi.ComposeSignerInfo(sevabi.SignerInfo{SigningKey: sevabi.VlekReportSigner})
			a.CertificateChain.VlekCert = nil
		}, time.Time{}},
		{"malformed_selected_vcek", func(a *pb.Attestation) {
			a.CertificateChain.VcekCert = []byte("invalid certificate")
		}, time.Time{}},
		{"zero_expiry", func(a *pb.Attestation) {
			a.CertificateChain.VcekCert = zero
		}, time.Time{}},
		{"unknown_product", func(a *pb.Attestation) {
			a.Product = &pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_UNKNOWN}
		}, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := &pb.Attestation{
				Report:  &pb.Report{SignerInfo: sevabi.ComposeSignerInfo(sevabi.SignerInfo{SigningKey: sevabi.VcekReportSigner})},
				Product: &pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_MILAN},
				CertificateChain: &pb.CertificateChain{
					VcekCert: vcek, VlekCert: vlek, AskCert: late, ArkCert: late,
				},
			}
			tc.mutate(evidence)
			validity, err := verifiedSEVCertificateValidity(evidence)
			got, present := validity.Expiry()
			if tc.want.IsZero() {
				if err == nil || present {
					t.Fatal("invalid evidence supplied a validity bound")
				}
				return
			}
			if err != nil || !present || !got.Equal(tc.want) {
				t.Fatalf("expiry=%v present=%v err=%v, want %v", got, present, err, tc.want)
			}
		})
	}
}

func sevValidityCertificate(t *testing.T, expiry time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Time{}, NotAfter: expiry}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSEVOnlineValidityRequiresAuthenticatedEvidence(t *testing.T) {
	report, err := sevabi.ReportToProto(testdata.AttestationBytes)
	if err != nil {
		t.Fatal(err)
	}
	certificateURL := kds.VCEKCertURL("Milan", report.GetChipId(), kds.TCBVersion(report.GetReportedTcb()))
	want := time.Date(2029, 9, 24, 0, 55, 28, 0, time.UTC)
	for _, mode := range []string{"valid", "report_signature", "certificate_signature", "malformed_report"} {
		t.Run(mode, func(t *testing.T) {
			raw, certificate := slices.Clone(testdata.AttestationBytes), slices.Clone(testdata.VcekBytes)
			switch mode {
			case "report_signature":
				raw[0x2a0] ^= 1 // First byte of the ABI report signature.
			case "certificate_signature":
				certificate[len(certificate)-1] ^= 1
			case "malformed_report":
				raw = raw[:10]
			}
			// Only retrieval is mocked. Signed collateral and the CPU report pass
			// through the production online verifier with embedded AMD roots.
			getter := sevtest.SimpleGetter(map[string][]byte{
				"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": trust.AskArkMilanVcekBytes,
				certificateURL: certificate,
			})
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					result := VerifySEVReportOnline(t.Context(), raw, getter)
					got, present := result.Validity.Expiry()
					if mode != "valid" {
						if result.OnlineVerified || present || (result.ParseErr == nil && result.CertChainErr == nil && result.SignatureErr == nil) {
							t.Error("failed verification published authenticated expiry")
						}
						return
					}
					if !result.OnlineVerified || result.CertChainErr != nil || result.SignatureErr != nil || !present || !got.Equal(want) {
						t.Errorf("verified=%v expiry=%v present=%v chain=%v signature=%v", result.OnlineVerified, got, present, result.CertChainErr, result.SignatureErr)
					}
				})
			}
			wg.Wait()
		})
	}
}

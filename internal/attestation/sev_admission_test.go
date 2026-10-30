package attestation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

const milanChainURL = "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"

func milanVCEKURL(t *testing.T) string {
	t.Helper()
	report, err := sevabi.ReportToProto(testdata.AttestationBytes)
	if err != nil {
		t.Fatal(err)
	}
	return kds.VCEKCertURL("Milan", report.GetChipId(), kds.TCBVersion(report.GetReportedTcb()))
}

// failingSEVGetter returns the configured error for one URL and delegates
// every other URL.
type failingSEVGetter struct {
	base trust.HTTPSGetter
	url  string
	err  error
}

func (g *failingSEVGetter) Get(target string) ([]byte, error) {
	return g.GetContext(context.Background(), target)
}

func (g *failingSEVGetter) GetContext(ctx context.Context, target string) ([]byte, error) {
	if target == g.url {
		return nil, g.err
	}
	return trust.GetWith(ctx, g.base, target)
}

// kdsRedirectTransport sends KDS requests to a local TLS test server. Only the
// network destination changes; the production getter reads the response.
type kdsRedirectTransport struct {
	base  http.RoundTripper
	local *url.URL
}

func (tr *kdsRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = tr.local.Scheme
	clone.URL.Host = tr.local.Host
	return tr.base.RoundTrip(clone)
}

// vcekNotFoundGetter serves the Milan chain and answers HTTP 404 for every
// other KDS request, through the production client getter.
func vcekNotFoundGetter(t *testing.T) trust.HTTPSGetter {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vcek/v1/Milan/cert_chain" {
			_, _ = w.Write(trust.AskArkMilanVcekBytes)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	local, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Transport = &kdsRedirectTransport{base: client.Transport, local: local}
	return NewSEVCertGetter(client)
}

// genoaReport returns a synthetic report whose CPUID FMS selects the Genoa
// product line. No test in this package retrieves the Genoa chain
// successfully, so go-sev-guest's process-wide chain cache cannot satisfy the
// chain request and the getter is always called.
func genoaReport(t *testing.T) []byte {
	t.Helper()
	return makeSEVReport(t, func(r *pb.Report) {
		r.Version = sevabi.ReportVersion3
		r.Cpuid1EaxFms = sevabi.MaskedCpuid1EaxFromSevProduct(&pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_GENOA})
	})
}

type sevOutcome int

const (
	sevVerified sevOutcome = iota
	sevRetrievalFailed
	sevRejected
)

// checkSEVOutcome asserts that exactly the error class of want is set.
func checkSEVOutcome(t *testing.T, result *SEVVerifyResult, want sevOutcome) {
	t.Helper()
	if result.ParseErr != nil {
		t.Errorf("unexpected parse error: %v", result.ParseErr)
		return
	}
	switch want {
	case sevVerified:
		if !result.OnlineVerified || result.FetchErr != nil || result.CertChainErr != nil || result.SignatureErr != nil {
			t.Errorf("verified=%v fetch=%v chain=%v signature=%v; want verified", result.OnlineVerified, result.FetchErr, result.CertChainErr, result.SignatureErr)
		}
	case sevRetrievalFailed:
		if result.OnlineVerified || result.FetchErr == nil || result.CertChainErr != nil || result.SignatureErr != nil {
			t.Errorf("verified=%v fetch=%v chain=%v signature=%v; want retrieval failure only", result.OnlineVerified, result.FetchErr, result.CertChainErr, result.SignatureErr)
		}
	case sevRejected:
		if result.OnlineVerified || result.FetchErr != nil || result.CertChainErr == nil || result.SignatureErr == nil {
			t.Errorf("verified=%v fetch=%v chain=%v signature=%v; want rejection only", result.OnlineVerified, result.FetchErr, result.CertChainErr, result.SignatureErr)
		}
	}
}

func TestSEVOnlineRequiresAuthenticatedEvidence(t *testing.T) {
	vcekURL := milanVCEKURL(t)
	fetchFailed := errors.New("dial tcp: i/o timeout")
	for _, tc := range []struct {
		mode string
		want sevOutcome
	}{
		{"valid", sevVerified},
		{"vcek_fetch_error", sevRetrievalFailed},
		{"vcek_http_404", sevRetrievalFailed},
		{"chain_fetch_error", sevRetrievalFailed},
		{"malformed_vcek", sevRejected},
		{"certificate_signature", sevRejected},
		{"report_signature", sevRejected},
		{"malformed_report", sevRejected},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			raw, certificate := slices.Clone(testdata.AttestationBytes), slices.Clone(testdata.VcekBytes)
			switch tc.mode {
			case "report_signature":
				raw[0x2a0] ^= 1 // First byte of the ABI report signature.
			case "certificate_signature":
				certificate[len(certificate)-1] ^= 1
			case "malformed_vcek":
				certificate = []byte("not a certificate")
			case "malformed_report":
				raw = raw[:10]
			case "chain_fetch_error":
				raw = genoaReport(t)
			}
			// Only retrieval is mocked. Signed collateral and the CPU report pass
			// through the production online verifier with embedded AMD roots.
			var getter trust.HTTPSGetter = sevtest.SimpleGetter(map[string][]byte{
				milanChainURL: trust.AskArkMilanVcekBytes,
				vcekURL:       certificate,
			})
			switch tc.mode {
			case "vcek_fetch_error":
				getter = &failingSEVGetter{base: getter, url: vcekURL, err: fetchFailed}
			case "chain_fetch_error":
				getter = &failingSEVGetter{base: getter, url: "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain", err: fetchFailed}
			case "vcek_http_404":
				getter = vcekNotFoundGetter(t)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					result := VerifySEVReportOnline(t.Context(), raw, getter)
					if tc.mode == "malformed_report" {
						if result.ParseErr == nil || result.OnlineVerified || result.FetchErr != nil {
							t.Errorf("parse=%v verified=%v fetch=%v; want parse failure", result.ParseErr, result.OnlineVerified, result.FetchErr)
						}
						return
					}
					checkSEVOutcome(t, result, tc.want)
					if tc.mode == "vcek_fetch_error" && !errors.Is(result.FetchErr, fetchFailed) {
						t.Errorf("retrieval cause lost: %v", result.FetchErr)
					}
				})
			}
			wg.Wait()
		})
	}
}

// Each verification owns its retrieval record. A failed retrieval in one
// verification must not appear in a verification that runs at the same time.
func TestSEVOnlineFetchFailureIsPerCall(t *testing.T) {
	vcekURL := milanVCEKURL(t)
	valid := sevtest.SimpleGetter(map[string][]byte{
		milanChainURL: trust.AskArkMilanVcekBytes,
		vcekURL:       testdata.VcekBytes,
	})
	failing := &failingSEVGetter{base: valid, url: vcekURL, err: errors.New("connection reset")}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			checkSEVOutcome(t, VerifySEVReportOnline(t.Context(), testdata.AttestationBytes, failing), sevRetrievalFailed)
		})
		wg.Go(func() {
			checkSEVOutcome(t, VerifySEVReportOnline(t.Context(), testdata.AttestationBytes, valid), sevVerified)
		})
	}
	wg.Wait()
}

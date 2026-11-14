package attestation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
// every other URL. called records that the failing URL was requested, so a
// test cannot pass on go-sev-guest's process-wide product chain cache alone.
type failingSEVGetter struct {
	base   trust.HTTPSGetter
	url    string
	err    error
	called atomic.Bool
}

func (g *failingSEVGetter) Get(target string) ([]byte, error) {
	return g.GetContext(context.Background(), target)
}

func (g *failingSEVGetter) GetContext(ctx context.Context, target string) ([]byte, error) {
	if target == g.url {
		g.called.Store(true)
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

// vcekStatusGetter serves the Milan chain and answers the given HTTP status
// for every other KDS request, through the production client getter.
func vcekStatusGetter(t *testing.T, status int) trust.HTTPSGetter {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vcek/v1/Milan/cert_chain" {
			_, _ = w.Write(trust.AskArkMilanVcekBytes)
			return
		}
		w.WriteHeader(status)
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
		mode   string
		want   sevOutcome
		status int // HTTP status of the VCEK response; 0 when not served over HTTP.
	}{
		{"valid", sevVerified, 0},
		{"vcek_fetch_error", sevRetrievalFailed, 0},
		// The VCEK URL contains report fields the provider controls, so a
		// 4xx answer rejects the evidence. 408, 429 and 5xx answers do not
		// depend on the request content and stay retrieval failures.
		{"vcek_http_404", sevRejected, http.StatusNotFound},
		{"vcek_http_400", sevRejected, http.StatusBadRequest},
		{"vcek_http_429", sevRetrievalFailed, http.StatusTooManyRequests},
		{"vcek_http_500", sevRetrievalFailed, http.StatusInternalServerError},
		{"vcek_http_503", sevRetrievalFailed, http.StatusServiceUnavailable},
		{"chain_fetch_error", sevRetrievalFailed, 0},
		{"malformed_vcek", sevRejected, 0},
		{"certificate_signature", sevRejected, 0},
		{"report_signature", sevRejected, 0},
		{"malformed_report", sevRejected, 0},
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
			var failing *failingSEVGetter
			switch tc.mode {
			case "vcek_fetch_error":
				failing = &failingSEVGetter{base: getter, url: vcekURL, err: fetchFailed}
			case "chain_fetch_error":
				failing = &failingSEVGetter{base: getter, url: "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain", err: fetchFailed}
			}
			if failing != nil {
				getter = failing
			}
			if tc.status != 0 {
				getter = vcekStatusGetter(t, tc.status)
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
					if failing != nil {
						checkSEVFetchCause(t, result.FetchErr, fetchFailed)
					}
					if tc.status != 0 {
						checkSEVStatusCause(t, result, tc.status)
					}
				})
			}
			wg.Wait()
			if failing != nil && !failing.called.Load() {
				t.Errorf("getter never requested %s; the result did not come from the getter", failing.url)
			}
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
	if !failing.called.Load() {
		t.Error("failing getter never called")
	}
}

// checkSEVFetchCause asserts that the retrieval error keeps its cause for
// errors.Is and shows the cause text once.
func checkSEVFetchCause(t *testing.T, fetchErr, cause error) {
	t.Helper()
	if !errors.Is(fetchErr, cause) {
		t.Errorf("retrieval cause lost: %v", fetchErr)
		return
	}
	if n := strings.Count(fetchErr.Error(), cause.Error()); n != 1 {
		t.Errorf("error %q shows the cause %d times; want 1", fetchErr, n)
	}
}

// checkSEVStatusCause asserts that the error set for an HTTP status answer
// keeps the typed status error and shows it once.
func checkSEVStatusCause(t *testing.T, result *SEVVerifyResult, status int) {
	t.Helper()
	err := result.FetchErr
	if err == nil {
		err = result.CertChainErr
	}
	var statusErr *SEVCertStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != status {
		t.Errorf("error %v does not carry HTTP status %d", err, status)
		return
	}
	if n := strings.Count(err.Error(), statusErr.Error()); n != 1 {
		t.Errorf("error %q shows the status error %d times; want 1", err, n)
	}
}

// verifySEVEvidence classifies a recorded getter error as a retrieval
// failure. That is correct only while every getter call aborts verification.
// CheckRevocations adds CRL downloads whose errors go-sev-guest can ignore,
// and other options can add getter calls of the same kind. This test fails if
// the options set anything other than the getter.
func TestSEVVerifyOptionsAbortOnGetterError(t *testing.T) {
	getter := sevtest.SimpleGetter(nil)
	opts := sevVerifyOptions(getter)
	if opts.CheckRevocations {
		t.Fatal("CheckRevocations is on; a failed CRL download would not abort verification")
	}
	if opts.Getter != getter {
		t.Error("options do not use the given getter")
	}
	v := reflect.ValueOf(opts).Elem()
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		if name != "Getter" && !v.Field(i).IsZero() {
			t.Errorf("option %s is set; confirm every getter call still aborts verification before changing this test", name)
		}
	}
}

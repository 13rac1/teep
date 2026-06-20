package attestation

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
)

// makeSEVReport builds a synthetic SEV-SNP attestation report with the given
// overrides applied to a valid baseline. The baseline passes all policy and
// TCB checks.
func makeSEVReport(t *testing.T, mutate func(r *pb.Report)) []byte {
	t.Helper()

	// Build a baseline report that passes all policy and TCB checks.
	// Policy: SMT=true, Debug=false, SingleSocket=false, ABI major=1, minor=55.
	policy := sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{
		ABIMajor: sevMinMajorVersion,
		ABIMinor: sevMinMinorVersion,
		SMT:      true,
	})

	// TCB: all components at or above minimums.
	tcb, err := kds.ComposeTCBParts(kds.TCBParts{
		BlSpl:    sevMinBlSpl,
		TeeSpl:   sevMinTeeSpl,
		SnpSpl:   sevMinSnpSpl,
		UcodeSpl: sevMinUcodeSpl,
	})
	if err != nil {
		t.Fatalf("ComposeTCBParts: %v", err)
	}

	report := &pb.Report{
		Version:         sevabi.ReportVersion2,
		Policy:          policy,
		CurrentTcb:      uint64(tcb),
		ReportData:      make([]byte, sevabi.ReportDataSize),
		Measurement:     make([]byte, sevabi.MeasurementSize),
		HostData:        make([]byte, sevabi.HostDataSize),
		FamilyId:        make([]byte, sevabi.FamilyIDSize),
		ImageId:         make([]byte, sevabi.ImageIDSize),
		IdKeyDigest:     make([]byte, sevabi.IDKeyDigestSize),
		AuthorKeyDigest: make([]byte, sevabi.AuthorKeyDigestSize),
		ReportId:        make([]byte, sevabi.ReportIDSize),
		ReportIdMa:      make([]byte, sevabi.ReportIDMASize),
		ChipId:          make([]byte, sevabi.ChipIDSize),
		Signature:       make([]byte, sevabi.SignatureSize),
		CurrentBuild:    sevMinBuild,
		CurrentMajor:    sevMinMajorVersion,
		CurrentMinor:    sevMinMinorVersion,
		SignatureAlgo:   sevabi.SignEcdsaP384Sha384,
	}

	if mutate != nil {
		mutate(report)
	}

	raw, err := sevabi.ReportToAbiBytes(report)
	if err != nil {
		t.Fatalf("ReportToAbiBytes: %v", err)
	}
	return raw
}

// TestVerifySEVReportParse verifies that a valid synthetic report parses
// successfully and extracts fields correctly.
func TestVerifySEVReportParse(t *testing.T) {
	wantData := [64]byte{0xde, 0xad, 0xbe, 0xef}
	wantMeasurement := make([]byte, sevabi.MeasurementSize)
	wantMeasurement[0] = 0xca
	wantMeasurement[1] = 0xfe

	raw := makeSEVReport(t, func(r *pb.Report) {
		rd := make([]byte, sevabi.ReportDataSize)
		copy(rd, wantData[:])
		r.ReportData = rd
		r.Measurement = wantMeasurement
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}

	if result.ReportData != wantData {
		t.Errorf("ReportData: got %s, want %s",
			hex.EncodeToString(result.ReportData[:4]),
			hex.EncodeToString(wantData[:4]))
	}

	if len(result.Measurement) != sevabi.MeasurementSize {
		t.Errorf("Measurement length: got %d, want %d", len(result.Measurement), sevabi.MeasurementSize)
	}
	if result.Measurement[0] != 0xca || result.Measurement[1] != 0xfe {
		t.Errorf("Measurement: got %s, want cafe...",
			hex.EncodeToString(result.Measurement[:2]))
	}
}

// TestVerifySEVReportReportDataExtraction verifies REPORTDATA is extracted
// correctly from various report payloads.
func TestVerifySEVReportReportDataExtraction(t *testing.T) {
	// Fill all 64 bytes with a known pattern.
	var want [64]byte
	for i := range want {
		want[i] = byte(i)
	}

	raw := makeSEVReport(t, func(r *pb.Report) {
		r.ReportData = want[:]
	})

	result := VerifySEVReportOffline(context.Background(), raw)
	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}

	if result.ReportData != want {
		t.Errorf("ReportData mismatch:\n  got:  %s\n  want: %s",
			hex.EncodeToString(result.ReportData[:]),
			hex.EncodeToString(want[:]))
	}
}

// TestVerifySEVReportValidPolicy verifies that a report with valid policy
// and TCB passes all checks.
func TestVerifySEVReportValidPolicy(t *testing.T) {
	raw := makeSEVReport(t, nil)

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr != nil {
		t.Errorf("unexpected PolicyErr: %v", result.PolicyErr)
	}
	if result.TCBErr != nil {
		t.Errorf("unexpected TCBErr: %v", result.TCBErr)
	}
	if result.DebugEnabled {
		t.Error("DebugEnabled should be false for baseline report")
	}
}

// TestVerifySEVReportDebugRejected verifies that a report with debug=true
// fails policy validation.
func TestVerifySEVReportDebugRejected(t *testing.T) {
	raw := makeSEVReport(t, func(r *pb.Report) {
		r.Policy = sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{
			ABIMajor: sevMinMajorVersion,
			ABIMinor: sevMinMinorVersion,
			SMT:      true,
			Debug:    true,
		})
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if !result.DebugEnabled {
		t.Error("DebugEnabled should be true when debug policy bit is set")
	}
	if result.PolicyErr == nil {
		t.Error("expected PolicyErr for debug=true, got nil")
	}
	t.Logf("PolicyErr: %v", result.PolicyErr)
}

// TestVerifySEVReportSMTDisabledRejected verifies that a report with SMT=false
// fails policy validation.
func TestVerifySEVReportSMTDisabledRejected(t *testing.T) {
	raw := makeSEVReport(t, func(r *pb.Report) {
		r.Policy = sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{
			ABIMajor: sevMinMajorVersion,
			ABIMinor: sevMinMinorVersion,
			SMT:      false,
		})
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr == nil {
		t.Error("expected PolicyErr for SMT=false, got nil")
	}
	t.Logf("PolicyErr: %v", result.PolicyErr)
}

// TestVerifySEVReportSingleSocketRejected verifies that a report with
// SingleSocket=true fails policy validation.
func TestVerifySEVReportSingleSocketRejected(t *testing.T) {
	raw := makeSEVReport(t, func(r *pb.Report) {
		r.Policy = sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{
			ABIMajor:     sevMinMajorVersion,
			ABIMinor:     sevMinMinorVersion,
			SMT:          true,
			SingleSocket: true,
		})
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr == nil {
		t.Error("expected PolicyErr for SingleSocket=true, got nil")
	}
	t.Logf("PolicyErr: %v", result.PolicyErr)
}

// TestVerifySEVReportMigrateMAEnabledRejected verifies that a report with
// MigrateMA=true fails policy validation.
func TestVerifySEVReportMigrateMAEnabledRejected(t *testing.T) {
	raw := makeSEVReport(t, func(r *pb.Report) {
		r.Policy = sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{
			ABIMajor:  sevMinMajorVersion,
			ABIMinor:  sevMinMinorVersion,
			SMT:       true,
			MigrateMA: true,
		})
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr == nil {
		t.Error("expected PolicyErr for MigrateMA=true, got nil")
	}
	t.Logf("PolicyErr: %v", result.PolicyErr)
}

// TestVerifySEVReportLowBuildRejected verifies that a report with a build
// number below the minimum fails policy validation.
func TestVerifySEVReportLowBuildRejected(t *testing.T) {
	raw := makeSEVReport(t, func(r *pb.Report) {
		r.CurrentBuild = sevMinBuild - 1
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr == nil {
		t.Error("expected PolicyErr for low build, got nil")
	}
	t.Logf("PolicyErr: %v", result.PolicyErr)
}

// TestVerifySEVReportLowVersionRejected verifies that a report with a version
// below the minimum fails policy validation.
func TestVerifySEVReportLowVersionRejected(t *testing.T) {
	raw := makeSEVReport(t, func(r *pb.Report) {
		r.CurrentMajor = 1
		r.CurrentMinor = 54
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr == nil {
		t.Error("expected PolicyErr for low version, got nil")
	}
	t.Logf("PolicyErr: %v", result.PolicyErr)
}

// TestVerifySEVReportLowTCBRejected verifies that a report with TCB components
// below the minimums fails TCB validation.
func TestVerifySEVReportLowTCBRejected(t *testing.T) {
	// Note: no "low TeeSpl" subtest because sevMinTeeSpl is 0x00 —
	// uint8 subtraction would wrap to 0xFF which is above the minimum,
	// making it impossible to test a below-minimum value.
	tests := []struct {
		name   string
		mutate func(t *testing.T, r *pb.Report)
	}{
		{
			name: "low BlSpl",
			mutate: func(t *testing.T, r *pb.Report) {
				t.Helper()
				tcb, err := kds.ComposeTCBParts(kds.TCBParts{
					BlSpl:    sevMinBlSpl - 1,
					TeeSpl:   sevMinTeeSpl,
					SnpSpl:   sevMinSnpSpl,
					UcodeSpl: sevMinUcodeSpl,
				})
				if err != nil {
					t.Fatalf("ComposeTCBParts: %v", err)
				}
				r.CurrentTcb = uint64(tcb)
			},
		},
		{
			name: "low SnpSpl",
			mutate: func(t *testing.T, r *pb.Report) {
				t.Helper()
				tcb, err := kds.ComposeTCBParts(kds.TCBParts{
					BlSpl:    sevMinBlSpl,
					TeeSpl:   sevMinTeeSpl,
					SnpSpl:   sevMinSnpSpl - 1,
					UcodeSpl: sevMinUcodeSpl,
				})
				if err != nil {
					t.Fatalf("ComposeTCBParts: %v", err)
				}
				r.CurrentTcb = uint64(tcb)
			},
		},
		{
			name: "low UcodeSpl",
			mutate: func(t *testing.T, r *pb.Report) {
				t.Helper()
				tcb, err := kds.ComposeTCBParts(kds.TCBParts{
					BlSpl:    sevMinBlSpl,
					TeeSpl:   sevMinTeeSpl,
					SnpSpl:   sevMinSnpSpl,
					UcodeSpl: sevMinUcodeSpl - 1,
				})
				if err != nil {
					t.Fatalf("ComposeTCBParts: %v", err)
				}
				r.CurrentTcb = uint64(tcb)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := makeSEVReport(t, func(r *pb.Report) { tt.mutate(t, r) })
			result := VerifySEVReportOffline(context.Background(), raw)

			if result.ParseErr != nil {
				t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
			}
			if result.TCBErr == nil {
				t.Error("expected TCBErr, got nil")
			}
			t.Logf("TCBErr: %v", result.TCBErr)
		})
	}
}

// TestVerifySEVReportTCBExtraction verifies that TCB components are correctly
// extracted from the report.
func TestVerifySEVReportTCBExtraction(t *testing.T) {
	tcb, err := kds.ComposeTCBParts(kds.TCBParts{
		BlSpl:    0x09,
		TeeSpl:   0x01,
		SnpSpl:   0x10,
		UcodeSpl: 0x50,
	})
	if err != nil {
		t.Fatalf("ComposeTCBParts: %v", err)
	}

	raw := makeSEVReport(t, func(r *pb.Report) {
		r.CurrentTcb = uint64(tcb)
	})

	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}

	if result.CurrentTCB.BlSpl != 0x09 {
		t.Errorf("BlSpl: got 0x%02x, want 0x09", result.CurrentTCB.BlSpl)
	}
	if result.CurrentTCB.TeeSpl != 0x01 {
		t.Errorf("TeeSpl: got 0x%02x, want 0x01", result.CurrentTCB.TeeSpl)
	}
	if result.CurrentTCB.SnpSpl != 0x10 {
		t.Errorf("SnpSpl: got 0x%02x, want 0x10", result.CurrentTCB.SnpSpl)
	}
	if result.CurrentTCB.UcodeSpl != 0x50 {
		t.Errorf("UcodeSpl: got 0x%02x, want 0x50", result.CurrentTCB.UcodeSpl)
	}
}

// TestVerifySEVReportMalformedInput verifies that malformed/truncated input
// returns a ParseErr.
func TestVerifySEVReportMalformedInput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte("too short")},
		{"truncated", make([]byte, sevabi.ReportSize-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifySEVReportOffline(context.Background(), tt.input)
			if result.ParseErr == nil {
				t.Error("expected ParseErr for malformed input, got nil")
			}
			t.Logf("ParseErr: %v", result.ParseErr)
		})
	}
}

// TestVerifySEVReportGuestPolicyExtracted verifies that the raw GuestPolicy
// uint64 is extracted from the report.
func TestVerifySEVReportGuestPolicyExtracted(t *testing.T) {
	raw := makeSEVReport(t, nil)
	result := VerifySEVReportOffline(context.Background(), raw)

	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.GuestPolicy == 0 {
		t.Error("GuestPolicy should be non-zero for a valid report")
	}
	t.Logf("GuestPolicy: 0x%016x", result.GuestPolicy)
}

// TestNewSEVVerifierOffline verifies that NewSEVVerifier in offline mode
// returns a working verifier that does not require a getter.
func TestNewSEVVerifierOffline(t *testing.T) {
	verifier := NewSEVVerifier(true, nil)
	raw := makeSEVReport(t, nil)

	result := verifier(context.Background(), raw)
	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	if result.PolicyErr != nil {
		t.Errorf("unexpected PolicyErr: %v", result.PolicyErr)
	}
	if result.TCBErr != nil {
		t.Errorf("unexpected TCBErr: %v", result.TCBErr)
	}
}

// sevNoopGetter is a trust.HTTPSGetter that immediately returns an error.
// Used to test online mode without making real network calls.
type sevNoopGetter struct{}

func (*sevNoopGetter) Get(_ string) ([]byte, error) {
	return nil, errors.New("noop getter")
}

func (*sevNoopGetter) GetContext(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("noop getter")
}

// TestNewSEVVerifierOnline verifies that NewSEVVerifier in online mode
// calls the getter and reports cert/sig errors when the getter fails.
func TestNewSEVVerifierOnline(t *testing.T) {
	verifier := NewSEVVerifier(false, &sevNoopGetter{})
	raw := makeSEVReport(t, nil)

	result := verifier(context.Background(), raw)
	if result.ParseErr != nil {
		t.Fatalf("unexpected ParseErr: %v", result.ParseErr)
	}
	// With a noop getter, cert fetching should fail.
	if result.CertChainErr == nil {
		t.Error("expected CertChainErr with noop getter, got nil")
	}
	if result.SignatureErr == nil {
		t.Error("expected SignatureErr with noop getter, got nil")
	}
	t.Logf("CertChainErr: %v", result.CertChainErr)
}

// ---------------------------------------------------------------------------
// sevClientHTTPSGetter
// ---------------------------------------------------------------------------

func TestSEVClientHTTPSGetter_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("cert-data"))
	}))
	defer ts.Close()

	g := &sevClientHTTPSGetter{client: ts.Client()}
	body, err := g.Get(ts.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "cert-data" {
		t.Errorf("body = %q, want cert-data", body)
	}
}

func TestSEVClientHTTPSGetter_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	g := &sevClientHTTPSGetter{client: ts.Client()}
	_, err := g.Get(ts.URL)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestSEVClientHTTPSGetter_GetContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ctx-data"))
	}))
	defer ts.Close()

	g := &sevClientHTTPSGetter{client: ts.Client()}
	body, err := g.GetContext(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("GetContext: %v", err)
	}
	if string(body) != "ctx-data" {
		t.Errorf("body = %q, want ctx-data", body)
	}
}

func TestSEVClientHTTPSGetter_CanceledContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	g := &sevClientHTTPSGetter{client: ts.Client()}
	_, err := g.GetContext(ctx, ts.URL)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestNewSEVCertGetter(t *testing.T) {
	getter := NewSEVCertGetter(http.DefaultClient)
	if getter == nil {
		t.Fatal("expected non-nil getter")
	}
}

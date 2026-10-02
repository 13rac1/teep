package verify

import (
	"context"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/config"
	"github.com/13rac1/teep/internal/provider"
)

// nextRouteReporter re-resolves to one fixed route.
type nextRouteReporter struct {
	next     provider.ResolvedRoute
	reported []string
}

func (r *nextRouteReporter) RecordCandidateFailure(_ context.Context, _, authority string) {
	r.reported = append(r.reported, authority)
}

func (r *nextRouteReporter) ResolveRoute(context.Context, string) (provider.ResolvedRoute, error) {
	return r.next, nil
}

func candidateRoute(t *testing.T, authority string) provider.ResolvedRoute {
	t.Helper()
	route, err := provider.NewResolvedRoute("https://"+authority, "repo/"+authority)
	if err != nil {
		t.Fatal(err)
	}
	return route
}

// verifyWithFailover returns the outcome of the last candidate and sets route
// to that candidate. provider.TestRunFailover covers the failover rules.
func TestVerifyWithFailoverUsesLastCandidate(t *testing.T) {
	route := candidateRoute(t, "a.enclave.test")
	reporter := &nextRouteReporter{next: candidateRoute(t, "b.enclave.test")}
	passing := &attestation.VerificationReport{}
	evidence := func(_ context.Context, _ *Options, r *provider.ResolvedRoute) (verificationOutcome, error) {
		if r.Authority() == "a.enclave.test" {
			return verificationOutcome{report: &attestation.VerificationReport{
				Factors: []attestation.FactorResult{{Name: "test_factor", Status: attestation.Fail, Enforced: true}},
			}}, nil
		}
		return verificationOutcome{report: passing}, nil
	}

	outcome, err := verifyWithFailover(t.Context(), &Options{ModelName: "model"}, &route, reporter, evidence)
	if err != nil {
		t.Fatalf("verifyWithFailover: %v", err)
	}
	if outcome.report != passing {
		t.Error("outcome is not candidate B's report")
	}
	if route.Authority() != "b.enclave.test" {
		t.Errorf("route = %q, want b.enclave.test", route.Authority())
	}
	if len(reporter.reported) != 1 || reporter.reported[0] != "a.enclave.test" {
		t.Errorf("reported = %v, want [a.enclave.test]", reporter.reported)
	}
}

// Replay must repeat the captured attempts, and capture records only the final
// attempt's evidence: both disable candidate failover.
func TestStandaloneFailoverReporterDisabledForReplayAndCapture(t *testing.T) {
	opts := &Options{
		ProviderName: "tinfoil_v3_direct",
		Provider:     &config.Provider{Name: "tinfoil_v3_direct", APIKey: "key"},
	}
	if reporter := standaloneFailoverReporter(opts); reporter == nil {
		t.Fatal("reporter = nil for a live tinfoil_v3_direct run, want failover enabled")
	}
	replay := *opts
	replay.replay = true
	if reporter := standaloneFailoverReporter(&replay); reporter != nil {
		t.Error("reporter != nil for replay, want failover disabled")
	}
	capturing := *opts
	capturing.capture = &verificationCapture{}
	if reporter := standaloneFailoverReporter(&capturing); reporter != nil {
		t.Error("reporter != nil during capture, want failover disabled")
	}
}

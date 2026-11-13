package attestation

import (
	"strings"
	"testing"
	"time"
)

func replicaReport(statuses ...Status) *VerificationReport {
	r := &VerificationReport{}
	for i, s := range statuses {
		r.Factors = append(r.Factors, FactorResult{Name: string(rune('a' + i)), Status: s, Detail: "d", Enforced: i == 0})
	}
	r.recomputeCounters()
	return r
}

// A factor of the merged report takes the worse status of the instances,
// and a failure names the instance it came from.
func TestMergeReplicaWorseStatus(t *testing.T) {
	r := replicaReport(Pass, Pass, Fail, NotApplicable)
	other := replicaReport(Fail, Skip, Pass, NotApplicable)
	other.Factors[0].Detail = "quote invalid"
	if err := r.MergeReplica("cc79", other); err != nil {
		t.Fatal(err)
	}
	want := []Status{Fail, Skip, Fail, NotApplicable}
	for i, f := range r.Factors {
		if f.Status != want[i] {
			t.Errorf("factor %s = %v, want %v", f.Name, f.Status, want[i])
		}
	}
	if r.Factors[0].Detail != "instance cc79: quote invalid" {
		t.Errorf("detail = %q", r.Factors[0].Detail)
	}
	if r.Factors[2].Detail != "d" {
		t.Errorf("a passing instance changed a failed factor: %q", r.Factors[2].Detail)
	}
	if !r.Blocked() || r.EnforcedFailed != 1 || r.Failed != 2 || r.Skipped != 1 || r.Passed != 0 {
		t.Errorf("counters: blocked %v enforced %d failed %d skipped %d passed %d",
			r.Blocked(), r.EnforcedFailed, r.Failed, r.Skipped, r.Passed)
	}
}

// Reports that do not hold the same factors cannot be merged.
func TestMergeReplicaRefusesDifferentFactors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		other *VerificationReport
		want  string
	}{
		{"no report", nil, "no report"},
		{"fewer factors", replicaReport(Pass), "factors"},
		{"other name", func() *VerificationReport { o := replicaReport(Pass, Pass); o.Factors[1].Name = "x"; return o }(), "factor 1"},
		{"other enforcement", func() *VerificationReport { o := replicaReport(Pass, Pass); o.Factors[1].Enforced = true; return o }(), "factor 1"},
		{"applies to one", replicaReport(Pass, NotApplicable), "only one instance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := replicaReport(Pass, Pass).MergeReplica("a8a2", tc.other)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSetInstances(t *testing.T) {
	r := replicaReport(Pass)
	r.SetInstances([]string{"19ae", "a8a2", "cc79"})
	if got := r.Metadata["instances"]; got != "3 (19ae, a8a2, cc79)" {
		t.Errorf("instances = %q", got)
	}
}

// Every instance's NRAS result must be valid at publication: the window
// is the earlier expiry and the later start.
func TestAdmissionIntersect(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	a := AdmissionTime{notBefore: t0, expires: t0.Add(time.Hour)}
	b := AdmissionTime{notBefore: t0.Add(time.Minute), expires: t0.Add(30 * time.Minute)}
	got := a.Intersect(b)
	if !got.notBefore.Equal(t0.Add(time.Minute)) || !got.expires.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("intersect = %+v", got)
	}
	if err := got.Check(t0.Add(45 * time.Minute)); err == nil {
		t.Error("accepted a time after the earlier expiry")
	}
	if got := a.Intersect(AdmissionTime{}); got != a {
		t.Errorf("intersect with no NRAS window = %+v, want %+v", got, a)
	}
}

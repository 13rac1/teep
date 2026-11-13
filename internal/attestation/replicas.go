package attestation

import (
	"fmt"
	"strings"
)

// MergeReplica folds the report of another instance of the same model into
// r. The gateway selects the instance for each request, so a factor holds
// only if it holds for every instance: each factor takes the worse status
// of the two reports, and a failure names the instance that failed. Both
// reports must hold the same factors in the same order; any difference is
// an error, because the merged report would not describe either instance.
func (r *VerificationReport) MergeReplica(instanceID string, other *VerificationReport) error {
	if other == nil {
		return fmt.Errorf("instance %s: no report", instanceID)
	}
	if len(r.Factors) != len(other.Factors) {
		return fmt.Errorf("instance %s: report has %d factors, want %d", instanceID, len(other.Factors), len(r.Factors))
	}
	for i := range r.Factors {
		f, o := &r.Factors[i], &other.Factors[i]
		if f.Name != o.Name || f.Enforced != o.Enforced {
			return fmt.Errorf("instance %s: factor %d is %q, want %q", instanceID, i, o.Name, f.Name)
		}
		if (f.Status == NotApplicable) != (o.Status == NotApplicable) {
			return fmt.Errorf("instance %s: factor %s applies to only one instance", instanceID, f.Name)
		}
		if statusRank(o.Status) > statusRank(f.Status) {
			f.Status, f.Deferred = o.Status, o.Deferred
			f.Detail = "instance " + instanceID + ": " + o.Detail
		}
	}
	r.recomputeCounters()
	return nil
}

// SetInstances records the instance ids that the report covers.
func (r *VerificationReport) SetInstances(ids []string) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
	}
	r.Metadata["instances"] = fmt.Sprintf("%d (%s)", len(ids), strings.Join(ids, ", "))
}

// statusRank orders statuses from best to worst for MergeReplica.
func statusRank(s Status) int {
	switch s {
	case Pass, NotApplicable:
		return 0
	case Skip:
		return 1
	default:
		return 2
	}
}

// Intersect returns the time window in which both admissions hold: the
// earlier expiry and the later start.
func (a AdmissionTime) Intersect(b AdmissionTime) AdmissionTime {
	out := a
	if !b.expires.IsZero() && (out.expires.IsZero() || b.expires.Before(out.expires)) {
		out.expires = b.expires
	}
	if b.notBefore.After(out.notBefore) {
		out.notBefore = b.notBefore
	}
	return out
}

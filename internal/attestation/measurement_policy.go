package attestation

// MeasurementPolicy defines optional allowlists for quote measurements.
// Empty allowlists mean "no policy" for that measurement.
//
// When WarnOnly is true, measurement mismatches produce annotated Pass results
// instead of Fail, allowing operators to observe drift without blocking traffic.
type MeasurementPolicy struct {
	MRTDAllow   map[string]struct{}
	MRSeamAllow map[string]struct{}
	RTMRAllow   [4]map[string]struct{}

	// WarnOnly, when true, causes measurement allowlist mismatches to
	// produce annotated Pass results instead of Fail. This lets operators
	// deploy allowlists in observation mode before enforcing them.
	WarnOnly bool

	// WarnOnlySet indicates WarnOnly was explicitly configured (e.g. from
	// TOML warn_measurements), as opposed to being a Go zero-value default.
	// Used by the config merge layer to distinguish "not set" from "set to false".
	WarnOnlySet bool
}

// HasMRTDPolicy reports whether an MRTD allowlist is configured.
func (p MeasurementPolicy) HasMRTDPolicy() bool {
	return len(p.MRTDAllow) > 0
}

// HasMRSeamPolicy reports whether an MRSEAM allowlist is configured.
func (p MeasurementPolicy) HasMRSeamPolicy() bool {
	return len(p.MRSeamAllow) > 0
}

// HasRTMRPolicy reports whether an RTMR allowlist is configured for index i.
func (p MeasurementPolicy) HasRTMRPolicy(i int) bool {
	if i < 0 || i >= len(p.RTMRAllow) {
		return false
	}
	return len(p.RTMRAllow[i]) > 0
}

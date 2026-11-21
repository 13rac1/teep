package attestation

// MeasurementPolicy defines optional allowlists for quote measurements.
// Empty allowlists mean "no policy" for that measurement.
type MeasurementPolicy struct {
	MRTDAllow   map[string]struct{}
	MRSeamAllow map[string]struct{}
	RTMRAllow   [4]map[string]struct{}
	// ComposeHashAllow lists sha256(app_compose) values; only the gateway
	// policy sets it.
	ComposeHashAllow map[string]struct{}
}

// HasComposeHashPolicy reports whether a compose hash allowlist is configured.
func (p MeasurementPolicy) HasComposeHashPolicy() bool {
	return len(p.ComposeHashAllow) > 0
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

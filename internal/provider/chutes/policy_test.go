package chutes

import (
	"encoding/hex"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := DefaultMeasurementPolicy()

	if !p.HasMRSeamPolicy() {
		t.Error("DefaultMeasurementPolicy should have MRSeamAllow")
	}
	if !p.HasMRTDPolicy() {
		t.Error("DefaultMeasurementPolicy should have MRTDAllow")
	}

	// MRSEAM must include both shared dstack values and chutes-specific values.
	dstackBase := attestation.DstackBaseMeasurementPolicy()
	for h := range dstackBase.MRSeamAllow {
		if _, ok := p.MRSeamAllow[h]; !ok {
			t.Errorf("MRSeamAllow missing shared dstack entry %s...", h[:16])
		}
	}
	for h := range Sek8sMRSEAMAllow {
		if _, ok := p.MRSeamAllow[h]; !ok {
			t.Errorf("MRSeamAllow missing sek8s entry %s...", h[:16])
		}
	}
	if len(p.MRSeamAllow) != len(Sek8sMRSEAMAllow) {
		t.Errorf("MRSeamAllow has %d entries, want %d", len(p.MRSeamAllow), len(Sek8sMRSEAMAllow))
	}

	// MRTD must contain the sek8s OVMF value.
	for h := range Sek8sMRTDAllow {
		if _, ok := p.MRTDAllow[h]; !ok {
			t.Errorf("MRTDAllow missing sek8s entry %s...", h[:16])
		}
	}

	// RTMR0-2 must be configured.
	for i := range 3 {
		if !p.HasRTMRPolicy(i) {
			t.Errorf("DefaultMeasurementPolicy should have RTMR%d policy", i)
		}
	}

	// RTMR3 must not be configured (runtime IMA, validator-side only).
	if p.HasRTMRPolicy(3) {
		t.Error("DefaultMeasurementPolicy should not have RTMR3 policy")
	}
}

func TestDefaultMeasurementPolicyCopies(t *testing.T) {
	p1 := DefaultMeasurementPolicy()
	p2 := DefaultMeasurementPolicy()
	// Mutating one copy must not affect the other.
	p1.MRSeamAllow["deadbeef"] = struct{}{}
	if _, ok := p2.MRSeamAllow["deadbeef"]; ok {
		t.Error("DefaultMeasurementPolicy returns shared MRSeamAllow maps instead of copies")
	}
	p1.MRTDAllow["deadbeef"] = struct{}{}
	if _, ok := p2.MRTDAllow["deadbeef"]; ok {
		t.Error("DefaultMeasurementPolicy returns shared MRTDAllow maps instead of copies")
	}
}

func TestSek8sMRTDAllow(t *testing.T) {
	if len(Sek8sMRTDAllow) < 1 {
		t.Error("Sek8sMRTDAllow is empty")
	}
	for h := range Sek8sMRTDAllow {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Errorf("invalid hex in Sek8sMRTDAllow: %s", h)
		}
		if len(b) != 48 {
			t.Errorf("Sek8sMRTDAllow entry %q decodes to %d bytes, want 48", h[:16], len(b))
		}
	}
}

func TestDefaultMeasurementPolicyRTMRValues(t *testing.T) {
	p := DefaultMeasurementPolicy()
	for i := range 3 {
		for h := range p.RTMRAllow[i] {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Errorf("invalid hex in RTMR%d allowlist: %s", i, h)
			}
			if len(b) != 48 {
				t.Errorf("RTMR%d entry %q decodes to %d bytes, want 48", i, h[:16], len(b))
			}
		}
	}
}

func TestDefaultMeasurementPolicyMRTDNotDstack(t *testing.T) {
	p := DefaultMeasurementPolicy()
	dstackBase := attestation.DstackBaseMeasurementPolicy()
	// sek8s MRTD must NOT overlap with dstack MRTD.
	for h := range dstackBase.MRTDAllow {
		if _, ok := p.MRTDAllow[h]; ok {
			t.Errorf("sek8s MRTDAllow unexpectedly contains dstack value %s...", h[:16])
		}
	}
}

func TestSek8sMRSEAMAllow(t *testing.T) {
	dstackBase := attestation.DstackBaseMeasurementPolicy()
	// Must be a strict superset of dstack MRSEAM.
	if len(Sek8sMRSEAMAllow) <= len(dstackBase.MRSeamAllow) {
		t.Errorf("Sek8sMRSEAMAllow (%d) should have more entries than dstack MRSEAM (%d)",
			len(Sek8sMRSEAMAllow), len(dstackBase.MRSeamAllow))
	}
	for h := range dstackBase.MRSeamAllow {
		if _, ok := Sek8sMRSEAMAllow[h]; !ok {
			t.Errorf("Sek8sMRSEAMAllow missing dstack entry %s...", h[:16])
		}
	}
	// Chutes-specific entries must NOT be in the dstack list.
	extra := 0
	for h := range Sek8sMRSEAMAllow {
		if _, ok := dstackBase.MRSeamAllow[h]; !ok {
			extra++
		}
	}
	if extra != 2 {
		t.Errorf("expected 2 chutes-specific MRSEAM entries, got %d", extra)
	}
}

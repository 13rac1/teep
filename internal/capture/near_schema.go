package capture

import (
	"errors"

	"github.com/13rac1/teep/internal/provider/nearparse"
)

// UnmarshalJSON requires the configured mode even when it is false.
func (c *NearConfig) UnmarshalJSON(data []byte) error {
	type fields NearConfig
	var value fields
	unknown, err := nearparse.Object(data, &value, "near_config")
	if err != nil {
		return err
	}
	if len(unknown) != 0 {
		return errors.New("unknown NEAR capture configuration fields")
	}
	*c = NearConfig(value)
	return nil
}

// UnmarshalJSON rejects unsupported fields and invalid route representations.
func (r *NearRoute) UnmarshalJSON(data []byte) error {
	type fields NearRoute
	var value fields
	unknown, err := nearparse.Object(data, &value, "near_route")
	if err != nil {
		return err
	}
	if len(unknown) != 0 {
		return errors.New("unknown NEAR capture route fields")
	}
	switch value.Mode {
	case "static":
		if value.Index != nil || value.Canonical != "" {
			return errors.New("static NEAR route contains canonical authority or index")
		}
	case "discovered", "explicit":
		if value.Index == nil || value.Canonical == "" {
			return errors.New("indexed NEAR route lacks canonical authority or index")
		}
	default:
		return errors.New("unknown NEAR capture selection mode")
	}
	*r = NearRoute(value)
	return nil
}

// UnmarshalJSON preserves a distinct, complete TLS-only probe outcome.
func (o *TLSInferenceOutcome) UnmarshalJSON(data []byte) error {
	type fields TLSInferenceOutcome
	var value fields
	unknown, err := nearparse.Object(data, &value, "tls_inference")
	if err != nil {
		return err
	}
	if len(unknown) != 0 || (value.Failed && !value.Attempted) {
		return errors.New("invalid TLS-only inference outcome")
	}
	*o = TLSInferenceOutcome(value)
	return nil
}

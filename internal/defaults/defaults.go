// Package defaults provides the shared measurement default policies for all
// providers, centralizing the provider-to-policy mapping so that cmd/teep and
// internal/proxy do not maintain duplicate switch statements.
package defaults

import (
	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nanogpt"
	"github.com/13rac1/teep/internal/provider/nearcloud"
	"github.com/13rac1/teep/internal/provider/neardirect"
	"github.com/13rac1/teep/internal/provider/venice"
)

type providerDefaults struct {
	model   attestation.MeasurementPolicy
	gateway attestation.MeasurementPolicy
}

var registry = map[string]providerDefaults{
	"venice": {
		model: venice.DefaultMeasurementPolicy(),
	},
	"neardirect": {
		model: neardirect.DefaultMeasurementPolicy(),
	},
	"nearcloud": {
		model:   nearcloud.DefaultMeasurementPolicy(),
		gateway: nearcloud.DefaultGatewayMeasurementPolicy(),
	},
	"nanogpt": {
		model: nanogpt.DefaultMeasurementPolicy(),
	},
}

// MeasurementDefaults returns the Go-coded default measurement policies for
// the named provider. The first return is the model-backend policy; the second
// is the gateway policy (zero value for non-gateway providers).
func MeasurementDefaults(name string) (model, gateway attestation.MeasurementPolicy) {
	if d, ok := registry[name]; ok {
		return d.model, d.gateway
	}
	return attestation.MeasurementPolicy{}, attestation.MeasurementPolicy{}
}

package nearparse

import (
	"errors"
	"strings"
)

// ModelNameMatch states how the model name that a NEAR report attests
// relates to the model that the client requested. The name is the
// provider's assertion: teep verifies model identity only through
// measured_model_weights, which NEAR does not provide.
type ModelNameMatch string

const (
	// ModelNameExact states that the attested name is the requested name.
	ModelNameExact ModelNameMatch = ""
	// ModelNameContains states that one name contains the other, for example
	// "z-ai/glm-5.3-flash" for "z-ai/glm-5.3-flash-long".
	ModelNameContains ModelNameMatch = "contains"
	// ModelNameDiffers states that neither name contains the other.
	ModelNameDiffers ModelNameMatch = "differs"
)

// MatchModelName returns how attested relates to requested. Both names must
// be set: an empty name would be contained in every name.
func MatchModelName(requested, attested string) (ModelNameMatch, error) {
	if requested == "" || attested == "" {
		return "", errors.New("requested or attested model name is empty")
	}
	switch {
	case attested == requested:
		return ModelNameExact, nil
	case strings.Contains(attested, requested) || strings.Contains(requested, attested):
		return ModelNameContains, nil
	default:
		return ModelNameDiffers, nil
	}
}

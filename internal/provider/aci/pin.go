package aci

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/13rac1/teep/internal/jsonstrict"
)

// PinSessions returns body with provider.aci_session_ids set to ids, the
// attested sessions that teep verified (ACI/1 §5.3). The gateway then serves
// the request only through one of them and refuses it otherwise
// (session_not_accepted). body must be a JSON object; a provider member
// must be an object, and a client's own aci_ member of it fails, because
// teep sets the serving constraints. The other provider members stay.
func PinSessions(body []byte, ids []string) ([]byte, error) {
	if len(ids) == 0 {
		return nil, errors.New("no verified attested session to pin")
	}
	for _, id := range ids {
		if !isLowerHex64(id) {
			return nil, fmt.Errorf("session id %q is not 64 lowercase hex characters", id)
		}
	}
	if err := jsonstrict.ValidateUniqueFields(body); err != nil {
		return nil, fmt.Errorf("request body: %w", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return nil, errors.New("request body is not a JSON object")
	}
	constraints := map[string]json.RawMessage{}
	if raw, ok := top["provider"]; ok {
		if err := json.Unmarshal(raw, &constraints); err != nil || constraints == nil {
			return nil, errors.New("request provider member is not a JSON object")
		}
		for name := range constraints {
			if strings.HasPrefix(name, "aci_") {
				return nil, fmt.Errorf("request sets provider.%s; teep sets the ACI serving constraints", name)
			}
		}
	}
	pinned, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	constraints["aci_session_ids"] = pinned
	if top["provider"], err = json.Marshal(constraints); err != nil {
		return nil, err
	}
	return json.Marshal(top)
}

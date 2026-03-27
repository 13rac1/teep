package nearcloud

import "encoding/json"

// ExtractGatewayAppCompose exposes tcbInfo unmarshalling + AppCompose for external tests.
func ExtractGatewayAppCompose(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	var t tcbInfo
	if err := json.Unmarshal(data, &t); err != nil {
		return "", err
	}
	return t.AppCompose, nil
}

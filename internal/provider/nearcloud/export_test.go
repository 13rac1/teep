package nearcloud

import "encoding/json"

// ExtractGatewayAppCompose exports extractGatewayAppCompose for black-box tests.
func ExtractGatewayAppCompose(tcbInfo json.RawMessage) (string, error) {
	return extractGatewayAppCompose(tcbInfo)
}

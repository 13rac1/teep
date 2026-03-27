package neardirect

import "encoding/json"

// ExtractAppCompose exposes tcbInfo unmarshalling for external tests.
func ExtractAppCompose(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var t tcbInfo
	if err := json.Unmarshal(data, &t); err != nil {
		return ""
	}
	return t.AppCompose
}

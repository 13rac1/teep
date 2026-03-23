package neardirect

import "encoding/json"

// ExtractAppCompose exposes extractAppCompose for external tests.
func ExtractAppCompose(tcbInfo json.RawMessage) string {
	return extractAppCompose(tcbInfo)
}

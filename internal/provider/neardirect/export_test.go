package neardirect

import "github.com/13rac1/teep/internal/provider/nearparse"

// ExtractAppCompose exposes the shared TCB decoder for external tests.
func ExtractAppCompose(data []byte) string {
	object, err := nearparse.EncodedObject(data)
	if err != nil {
		return ""
	}
	var t nearparse.TCB
	if _, err := nearparse.Object(object, &t, "tcb_info"); err != nil {
		return ""
	}
	return t.AppCompose
}

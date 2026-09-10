package nearcloud

import "github.com/13rac1/teep/internal/provider/nearparse"

// ExtractGatewayAppCompose exposes the shared TCB decoder for external tests.
func ExtractGatewayAppCompose(data []byte) (string, error) {
	object, err := nearparse.EncodedObject(data)
	if err != nil {
		return "", err
	}
	var t nearparse.TCB
	if _, err := nearparse.Object(object, &t, "tcb_info"); err != nil {
		return "", err
	}
	return t.AppCompose, nil
}

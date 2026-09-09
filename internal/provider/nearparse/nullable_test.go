package nearparse

import "testing"

func TestObjectNullableField(t *testing.T) {
	for _, nullable := range []bool{false, true} {
		var target struct {
			Value *string `json:"value"`
		}
		var fields []string
		if nullable {
			fields = []string{"value"}
		}
		_, err := Object([]byte(`{"value":null}`), &target, "test", fields...)
		if (err == nil) != nullable {
			t.Fatalf("nullable=%v: %v", nullable, err)
		}
	}
}

package neardirect

import (
	"fmt"
	"strings"
	"testing"
)

func TestBackendCountStrictUnsigned(t *testing.T) {
	const host = "glm.completions.near.ai"
	for _, value := range []string{"0", "-1", "1.0", "1e0", "null", "true", "\"1\"", "18446744073709551616"} {
		t.Run(value, func(t *testing.T) {
			body := fmt.Sprintf(`{"domain":%q,"requested_domain":%q,"healthy":%s,"total":18446744073709551615}`, host, host, value)
			if _, _, err := parseBackendCount([]byte(body), host); err == nil {
				t.Fatal("invalid integer token accepted")
			}
		})
	}
	for _, value := range []string{"1", "257", "18446744073709551615"} {
		body := fmt.Sprintf(`{"domain":%q,"requested_domain":%q,"healthy":%s,"total":%s}`, host, host, value, value)
		if _, unknown, err := parseBackendCount([]byte(body), host); err != nil || len(unknown) != 0 {
			t.Fatalf("valid count: %v %v", unknown, err)
		}
	}
	valid := fmt.Sprintf(`{"domain":%q,"requested_domain":%q,"healthy":1,"total":1}`, host, host)
	for _, body := range []string{
		strings.Replace(valid, `"total":1`, `"total":null`, 1),
		strings.Replace(valid, `"total":1`, `"total":0`, 1),
		strings.Replace(valid, `"total":1`, `"total":1,"tot\u0061l":1`, 1),
		strings.Replace(valid, `"requested_domain":"`+host+`"`, `"requested_domain":"other.completions.near.ai"`, 1),
		strings.Replace(valid, `,"total":1`, "", 1),
		strings.Repeat(" ", 64<<10) + valid,
	} {
		if _, _, err := parseBackendCount([]byte(body), host); err == nil {
			t.Fatal("invalid count structure accepted")
		}
	}
	_, unknown, err := parseBackendCount([]byte(strings.Replace(valid, `"total":1`, `"total":1,"extra":true`, 1)), host)
	if err != nil || len(unknown) != 1 {
		t.Fatalf("unknown fields not returned: %v %v", unknown, err)
	}
}

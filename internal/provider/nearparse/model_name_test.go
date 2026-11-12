package nearparse

import "testing"

func TestMatchModelName(t *testing.T) {
	for _, tc := range []struct {
		requested, attested string
		want                ModelNameMatch
		wantErr             bool
	}{
		{"z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash", ModelNameExact, false},
		{"z-ai/glm-5.3-flash-long", "z-ai/glm-5.3-flash", ModelNameContains, false},
		{"z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash-long", ModelNameContains, false},
		{"deepseek-ai/DeepSeek-V4.1-Flash-1017", "z-ai/glm-5.3-flash", ModelNameDiffers, false},
		{"model", "", "", true},
		{"", "model", "", true},
	} {
		got, err := MatchModelName(tc.requested, tc.attested)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("MatchModelName(%q, %q) = %q, %v; want %q, error %v", tc.requested, tc.attested, got, err, tc.want, tc.wantErr)
		}
	}
}

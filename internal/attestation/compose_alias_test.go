package attestation

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// An app_compose whose docker_compose_file has a case-variant or duplicate
// second member fails the compose binding, although the quote binds its
// bytes. dstack copies the member with the exact name (jq), and
// encoding/json would take the last case-insensitive match, so teep would
// check the images of a decoy compose. Written as raw bytes so that the
// decoy follows the real member.
func TestComposeBindingRefusesAmbiguousDockerCompose(t *testing.T) {
	run := strings.Repeat("a", 64)
	decoy := strings.Repeat("b", 64)
	for name, appCompose := range map[string]string{
		"case variant": `{"manifest_version":2,"docker_compose_file":"services:\n  app:\n    image: real/app@sha256:` + run +
			`\n","Docker_Compose_File":"services:\n  app:\n    image: decoy/app@sha256:` + decoy + `\n"}`,
		"duplicate": `{"docker_compose_file":"services:\n  app:\n    image: real/app@sha256:` + run +
			`\n","docker_compose_file":"services:\n  app:\n    image: decoy/app@sha256:` + decoy + `\n"}`,
	} {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(appCompose))
			mrConfigID := append([]byte{0x01}, sum[:]...)
			if err := VerifyComposeBinding(appCompose, mrConfigID); err == nil {
				t.Fatal("compose binding passed for an ambiguous app_compose")
			}
		})
	}

	plain := `{"manifest_version":2,"docker_compose_file":"services:\n  app:\n    image: real/app@sha256:` + run + `\n","extra":true}`
	sum := sha256.Sum256([]byte(plain))
	if err := VerifyComposeBinding(plain, append([]byte{0x01}, sum[:]...)); err != nil {
		t.Fatalf("compose binding with an added member: %v", err)
	}
}

// An app_compose that is not a JSON object fails the compose binding,
// although the quote binds its bytes: dstack decodes it as an object.
func TestComposeBindingRefusesNonObject(t *testing.T) {
	for name, appCompose := range map[string]string{
		"list":            `["services:\n  app:\n    image: a/b@sha256:` + strings.Repeat("a", 64) + `\n"]`,
		"string":          `"services: {}"`,
		"null":            `null`,
		"yaml":            "services:\n  app:\n    image: a/b\n",
		"byte order mark": "\xef\xbb\xbf" + `{"docker_compose_file":"services: {}"}`,
		"empty":           ``,
	} {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(appCompose))
			if err := VerifyComposeBinding(appCompose, append([]byte{0x01}, sum[:]...)); err == nil {
				t.Fatal("compose binding passed for an app_compose that is not a JSON object")
			}
		})
	}
	spaced := " \n" + `{"docker_compose_file":"services: {}"}`
	sum := sha256.Sum256([]byte(spaced))
	if err := VerifyComposeBinding(spaced, append([]byte{0x01}, sum[:]...)); err != nil {
		t.Fatalf("compose binding with leading white space: %v", err)
	}
}

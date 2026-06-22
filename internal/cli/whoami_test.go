package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestPrintIdentity(t *testing.T) {
	out := printIdentityForTest(&openngfwv1.GetIdentityResponse{
		Actor:        "bob",
		Role:         "operator",
		AuthEnabled:  true,
		AuthSource:   "local-users-file",
		Capabilities: []string{"read", "write"},
	})
	for _, want := range []string{
		"Actor:        bob",
		"Role:         operator",
		"Auth enabled: true",
		"Auth source:  local-users-file",
		"Capabilities: read, write",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintIdentityNoCapabilities(t *testing.T) {
	out := printIdentityForTest(&openngfwv1.GetIdentityResponse{})
	if !strings.Contains(out, "Actor:        -") || !strings.Contains(out, "Capabilities: -") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func printIdentityForTest(resp *openngfwv1.GetIdentityResponse) string {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printIdentity(cmd, resp)
	return buf.String()
}

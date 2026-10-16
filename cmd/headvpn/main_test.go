package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != exitUsage {
		t.Fatalf("no args: code %d", code)
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &errb); code != exitOK || !strings.HasPrefix(out.String(), "headvpn ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
}

func TestUnknownProfileIsUsageError(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.toml")
	_ = os.WriteFile(cfg, []byte(`[profiles.work]
backend = "aws-official"
aws_profile = "work"
idp = "keycloak"
idp_origin = "https://idp.example.com"
username = "a@example.com"
password = "env:PW"
`), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"connect", "nope", "--config", cfg}, &out, &errb); code != exitUsage {
		t.Fatalf("code %d, stderr %q", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"profiles", "--config", cfg}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "work\taws-official\tkeycloak") {
		t.Fatalf("profiles: %d %q", code, out.String())
	}
}

func TestSecretSetValidatesReference(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{{"secret"}, {"secret", "set"}, {"secret", "set", "noslash"}, {"secret", "get", "a/b"}} {
		if code := run(args, &out, &errb); code != exitUsage {
			t.Fatalf("%v: code %d", args, code)
		}
	}
}

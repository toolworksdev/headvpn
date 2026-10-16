package crv1

import (
	"strings"
	"testing"
)

// Shape taken from a real management transcript (state id and query redacted).
const mgmtLine = `>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:instance-7/1234567890123456789/00000000-0000-4000-8000-000000000001:b'Ti9B':https://idp.example.com/realms/example/protocol/saml?SAMLRequest=fZJdT4MwFIb%2FCun9oFQ']`

func TestParseManagementLine(t *testing.T) {
	c, err := Parse(mgmtLine)
	if err != nil {
		t.Fatal(err)
	}
	if c.Flags != "R" {
		t.Errorf("flags = %q", c.Flags)
	}
	if c.StateID != "instance-7/1234567890123456789/00000000-0000-4000-8000-000000000001" {
		t.Errorf("state id = %q", c.StateID)
	}
	if c.Username != "b'Ti9B'" {
		t.Errorf("username = %q", c.Username)
	}
	if !strings.HasPrefix(c.Text, "https://idp.example.com/realms/example/protocol/saml?SAMLRequest=") ||
		strings.HasSuffix(c.Text, "']") {
		t.Errorf("text = %q", c.Text)
	}
}

func TestParseLogLine(t *testing.T) {
	c, err := Parse(`AUTH: Received control message: AUTH_FAILED,CRV1:R:sid:b'Ti9B':https://idp.example.com/x?a=b`)
	if err != nil || c.StateID != "sid" || c.Text != "https://idp.example.com/x?a=b" {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{
		`>PASSWORD:Verification Failed: 'Auth' ['Invalid username or password']`,
		`CRV1:R:sid`,
		`CRV1:R::user:https://x`,
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q): expected error", s)
		}
	}
}

func TestURLOriginCheck(t *testing.T) {
	c, _ := Parse(mgmtLine)
	if _, err := c.URL("https://idp.example.com"); err != nil {
		t.Errorf("trusted origin rejected: %v", err)
	}
	if _, err := c.URL("https://IDP.example.com/"); err != nil {
		t.Errorf("origin match should ignore case and trailing slash: %v", err)
	}
	for _, origin := range []string{"https://evil.example.com", "https://idp.example.com:8443", "idp.example.com"} {
		if _, err := c.URL(origin); err == nil {
			t.Errorf("origin %q should be rejected", origin)
		}
	}
	plain := Challenge{StateID: "s", Text: "http://idp.example.com/realms/example/protocol/saml"}
	if _, err := plain.URL("http://idp.example.com"); err == nil {
		t.Error("non-https challenge URL should be rejected")
	}
}

func TestPassword(t *testing.T) {
	pw, err := Password("sid", "PHNhbWw+/x==")
	if err != nil {
		t.Fatal(err)
	}
	if pw != "CRV1::sid::PHNhbWw%2B%2Fx%3D%3D" {
		t.Errorf("password = %q", pw)
	}
	if _, err := Password("sid", strings.Repeat("A", maxPassword)); err == nil {
		t.Error("expected size error")
	}
}

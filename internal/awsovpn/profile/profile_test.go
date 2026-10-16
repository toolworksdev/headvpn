package profile

import (
	"slices"
	"strings"
	"testing"
)

// Same directives as the an AWS-exported client profile, certificates elided.
const awsProfile = `client
dev tun
proto udp
remote cvpn-endpoint-0123456789abcdef0.prod.clientvpn.us-east-1.amazonaws.com 443
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
<ca>
-----BEGIN CERTIFICATE-----
remote evil.example.com 1194
-----END CERTIFICATE-----
</ca>

auth-user-pass
auth-retry interact
auth-nocache
reneg-sec 0

verify-x509-name sec.example.com name
`

func TestNamesMatchAWSClient(t *testing.T) {
	p, err := Parse([]byte(awsProfile))
	if err != nil {
		t.Fatal(err)
	}
	// What the AWS client sent as UV_AWS_CLIENT_OVPN_FLAGS for this profile.
	want := "client,dev,proto,remote,remote-random-hostname,resolv-retry,nobind,remote-cert-tls,cipher,verb,ca,auth-user-pass,auth-retry,auth-nocache,reneg-sec,verify-x509-name"
	if got := strings.Join(p.Names(), ","); got != want {
		t.Errorf("names:\n got %s\nwant %s", got, want)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	for name, extra := range map[string]string{
		"script":   "up /tmp/x.sh\nscript-security 2\n",
		"plugin":   "plugin /tmp/evil.so\n",
		"dashdash": "--route-up /tmp/x.sh\n",
	} {
		p, err := Parse([]byte(awsProfile + extra))
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}

	p, _ := Parse([]byte(strings.Replace(awsProfile, "auth-user-pass\n", "auth-user-pass /root/creds\n", 1)))
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "file") {
		t.Errorf("auth-user-pass with file: %v", err)
	}
	p, _ = Parse([]byte(strings.Replace(awsProfile, "auth-user-pass\n", "", 1)))
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "SAML") {
		t.Errorf("missing auth-user-pass: %v", err)
	}
}

func TestInlineBlockContentIgnored(t *testing.T) {
	p, _ := Parse([]byte(awsProfile))
	remotes := 0
	for _, d := range p.Directives {
		if d.Name == "remote" {
			remotes++
		}
	}
	if remotes != 1 {
		t.Errorf("parsed %d remotes, want 1 (inline block content must be skipped)", remotes)
	}
	if !slices.Contains(p.Names(), "ca") {
		t.Error("inline <ca> not reported")
	}
}

func TestUnterminatedInline(t *testing.T) {
	if _, err := Parse([]byte("client\n<ca>\nxxx\n")); err == nil {
		t.Error("expected error")
	}
}

func TestValidateNeverEchoesFileContent(t *testing.T) {
	p, err := Parse([]byte("root:$6$secretsalt$hashhashhash:19000:0:99999:7:::\nremote x 443\n"))
	if err != nil {
		return // refusing to parse is fine too
	}
	err = p.Validate()
	if err == nil {
		t.Fatal("accepted a file that is not a profile")
	}
	if strings.Contains(err.Error(), "hashhash") || strings.Contains(err.Error(), "secretsalt") {
		t.Fatalf("error echoes file content: %v", err)
	}
}

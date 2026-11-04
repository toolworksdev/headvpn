package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const good = `
[profiles.work]
backend = "aws-official"
aws_profile = "work"
idp = "keycloak"
idp_origin = "https://idp.example.com"
username = "ana@example.com"
password = "keychain:headvpn/work.password"
totp_secret = "keychain:headvpn/work.totp"
connect_timeout = "90s"
`

func TestLoadGood(t *testing.T) {
	c, err := Load(write(t, good))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Profiles["work"]
	if p.Timeout() != 90*time.Second || p.AWSProfile != "work" {
		t.Fatalf("%+v", p)
	}
}

func TestRejectsUnknownKeys(t *testing.T) {
	_, err := Load(write(t, good+"pasword = \"x\"\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("typo accepted: %v", err)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"no backend":  strings.Replace(good, `backend = "aws-official"`, "", 1),
		"bad backend": strings.Replace(good, `"aws-official"`, `"wireguard"`, 1),
		"no profile":  strings.Replace(good, `aws_profile = "work"`, "", 1),
		"bad idp":     strings.Replace(good, `idp = "keycloak"`, `idp = "okta"`, 1),
		"no password": strings.Replace(good, `password = "keychain:headvpn/work.password"`, "", 1),
		"both otp":    good + `otp = "prompt:"` + "\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOpenVPNBackend(t *testing.T) {
	base := `
[profiles.lin]
backend = "aws-openvpn"
ovpn = "/etc/headvpn/work.ovpn"
idp = "keycloak"
idp_origin = "https://idp.example.com"
username = "ana@example.com"
password = "env:PW"
totp_secret = "env:SEED"
`
	c, err := Load(write(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Profiles["lin"].UseFIPS() {
		t.Fatal("FIPS must default to on, like the AWS client")
	}
	for name, body := range map[string]string{
		"relative ovpn": strings.Replace(base, "/etc/headvpn/work.ovpn", "work.ovpn", 1),
		"no ovpn":       strings.Replace(base, `ovpn = "/etc/headvpn/work.ovpn"`, "", 1),
		"prompt otp":    strings.Replace(base, `totp_secret = "env:SEED"`, `otp = "prompt:"`, 1),
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPritunlBackend(t *testing.T) {
	handoff := `
[profiles.office]
backend = "pritunl"
pritunl_profile = "vpn (ana)"
`
	if _, err := Load(write(t, handoff)); err != nil {
		t.Fatalf("handoff profile: %v", err)
	}
	full := handoff + `idp = "entra"
username = "ana@example.com"
password = "env:PW"
totp_secret = "env:SEED"
`
	if _, err := Load(write(t, full)); err != nil {
		t.Fatalf("entra profile: %v", err)
	}
	for name, body := range map[string]string{
		"no profile":    strings.Replace(handoff, `pritunl_profile = "vpn (ana)"`, "", 1),
		"bad mode":      handoff + `pritunl_mode = "ipsec"` + "\n",
		"entra no code": strings.Replace(full, `totp_secret = "env:SEED"`, "", 1),
		"entra on aws":  strings.Replace(full, `backend = "pritunl"`, `backend = "aws-official"`+"\n"+`aws_profile = "x"`, 1),
		"no idp on aws": "[profiles.a]\nbackend = \"aws-official\"\naws_profile = \"x\"\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWritableConfigIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits")
	}
	path := write(t, "[profiles.a]\nbackend = \"pritunl\"\npritunl_profile = \"x\"\n")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err=%v, want a refusal of a group/world-writable config", err)
	}
}

const goodSSO = `
[sso.work]
idp = "keycloak"
idp_origin = "https://idp.example.com"
username = "ana@example.com"
password = "keychain:headvpn/work.password"
totp_secret = "keychain:headvpn/work.totp"
verify_profile = "work-prod"
login_timeout = "45s"
`

func TestSSO(t *testing.T) {
	c, err := Load(write(t, goodSSO))
	if err != nil {
		t.Fatal(err)
	}
	s := c.SSO["work"]
	if s.Timeout() != 45*time.Second || s.VerifyProfile != "work-prod" || s.AsProfile().IdPOrigin != "https://idp.example.com" {
		t.Fatalf("%+v", s)
	}
	bad := map[string]string{
		"no idp":             strings.Replace(goodSSO, `idp = "keycloak"`, "", 1),
		"bad idp":            strings.Replace(goodSSO, `idp = "keycloak"`, `idp = "okta"`, 1),
		"keycloak no origin": strings.Replace(goodSSO, `idp_origin = "https://idp.example.com"`, "", 1),
		"no password":        strings.Replace(goodSSO, `password = "keychain:headvpn/work.password"`, "", 1),
		"entra no code":      strings.Replace(strings.Replace(goodSSO, `"keycloak"`, `"entra"`, 1), `totp_secret = "keychain:headvpn/work.totp"`, "", 1),
		"both otp":           goodSSO + `otp = "prompt:"` + "\n",
		"typo":               goodSSO + `verify_profle = "x"` + "\n",
	}
	for name, body := range bad {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

const goodKibana = `
[kibana.search]
idp = "keycloak"
idp_origin = "https://idp.example.com"
url = "https://search.example.com/_plugin/kibana"
username = "me@example.com"
password = "keychain:headvpn/search.password"
totp_secret = "keychain:headvpn/search.totp"
login_timeout = "30s"
`

func TestKibana(t *testing.T) {
	c, err := Load(write(t, goodKibana))
	if err != nil {
		t.Fatal(err)
	}
	k := c.Kibana["search"]
	if k.Timeout() != 30*time.Second || k.AsProfile().IdPOrigin != "https://idp.example.com" {
		t.Fatalf("%+v", k)
	}
	bad := map[string]string{
		"no idp":      strings.Replace(goodKibana, `idp = "keycloak"`, "", 1),
		"entra":       strings.Replace(goodKibana, `idp = "keycloak"`, `idp = "entra"`, 1),
		"no origin":   strings.Replace(goodKibana, `idp_origin = "https://idp.example.com"`, "", 1),
		"http url":    strings.Replace(goodKibana, `url = "https://`, `url = "http://`, 1),
		"no url":      strings.Replace(goodKibana, `url = "https://search.example.com/_plugin/kibana"`, "", 1),
		"no password": strings.Replace(goodKibana, `password = "keychain:headvpn/search.password"`, "", 1),
		"both otp":    goodKibana + `otp = "prompt:"` + "\n",
		"typo":        goodKibana + `urll = "x"` + "\n",
	}
	for name, body := range bad {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

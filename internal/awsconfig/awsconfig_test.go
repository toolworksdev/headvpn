package awsconfig

import (
	"reflect"
	"strings"
	"testing"
)

const sample = `
[default]
region = us-east-1

[sso-session acme]
sso_start_url = https://acme.awsapps.com/start/#
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile acme-prod]
sso_session = acme
sso_account_id = 111111111111
sso_role_name = Admin
s3 =
  max_concurrent_requests = 20

[profile acme-dev]
sso_session = acme
sso_account_id = 222222222222

[profile legacy]
sso_start_url = https://d-1234567890.awsapps.com/start#/
sso_region = us-west-2
sso_account_id = 333333333333

[profile plain]
region = eu-west-1

[profile broken]
sso_session = missing
`

func load(t *testing.T) File {
	f, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSession(t *testing.T) {
	got, err := load(t).Resolve("acme")
	if err != nil {
		t.Fatal(err)
	}
	want := Target{Name: "acme", Session: "acme", StartURL: "https://acme.awsapps.com/start/#", Region: "us-east-1",
		LoginArgs: []string{"--sso-session", "acme"}, Profiles: []string{"acme-dev", "acme-prod"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestProfileOfASession(t *testing.T) {
	got, err := load(t).Resolve("acme-prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.Session != "acme" || got.LoginArgs[1] != "acme" || got.Profiles[0] != "acme-prod" || len(got.Profiles) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestLegacyProfile(t *testing.T) {
	got, err := load(t).Resolve("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Session != "" || got.Region != "us-west-2" || !reflect.DeepEqual(got.LoginArgs, []string{"--profile", "legacy"}) {
		t.Fatalf("%+v", got)
	}
}

func TestNotSSO(t *testing.T) {
	for _, n := range []string{"plain", "nope", "broken", "default"} {
		if _, err := load(t).Resolve(n); err == nil {
			t.Errorf("%s resolved", n)
		}
	}
}

func TestIndentedSubsectionIsNotAKey(t *testing.T) {
	if _, ok := load(t)["profile acme-prod"]["max_concurrent_requests"]; ok {
		t.Fatal("nested s3 key leaked into the profile")
	}
}

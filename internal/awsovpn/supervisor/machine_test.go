//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/toolworksdev/headvpn/internal/awsovpn/mgmt"
	"github.com/toolworksdev/headvpn/internal/idp/keycloak"
)

const (
	origin    = "https://idp.example.com"
	challenge = `>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:instance-7/123/abc:b'Ti9B':https://idp.example.com/realms/example/protocol/saml?SAMLRequest=fZJd']`
	need      = `>PASSWORD:Need 'Auth' username/password`
)

func feed(m *machine, line string) []action { return m.onMessage(mgmt.Parse(line)) }

func cmds(acts []action) []string {
	var out []string
	for _, a := range acts {
		if s, ok := a.(sendAction); ok {
			out = append(out, s.cmd)
		}
	}
	return out
}

func wantCreds(t *testing.T, acts []action, pw string) {
	t.Helper()
	want := []string{`username "Auth" "N/A"`, `password "Auth" "` + pw + `"`}
	if got := cmds(acts); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if a := acts[1].(sendAction); strings.Contains(a.logAs, pw) {
		t.Fatalf("password not redacted in log form: %q", a.logAs)
	}
}

func onlyAuth(t *testing.T, acts []action) authAction {
	t.Helper()
	if len(acts) != 1 {
		t.Fatalf("want one auth action, got %#v", acts)
	}
	a, ok := acts[0].(authAction)
	if !ok {
		t.Fatalf("want auth action, got %#v", acts[0])
	}
	return a
}

func onlyFail(t *testing.T, acts []action) failAction {
	t.Helper()
	if len(acts) != 1 {
		t.Fatalf("want one fail action, got %#v", acts)
	}
	f, ok := acts[0].(failAction)
	if !ok {
		t.Fatalf("want fail action, got %#v", acts[0])
	}
	return f
}

// Replays the sequence seen in the AWS VPN Client logs: initial connect,
// then a ping-restart that re-authenticates inside the same process.
func TestTranscript(t *testing.T) {
	m := &machine{idpOrigin: origin}
	if got := cmds(m.start()); !reflect.DeepEqual(got, []string{"state on", "hold off", "hold release"}) {
		t.Fatalf("start: %q", got)
	}
	if acts := feed(m, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info"); acts != nil {
		t.Fatalf("info: %#v", acts)
	}
	if got := cmds(feed(m, ">HOLD:Waiting for hold release:0")); !reflect.DeepEqual(got, []string{"hold release"}) {
		t.Fatalf("hold: %q", got)
	}
	wantCreds(t, feed(m, need), "ACS::35001")
	feed(m, ">STATE:1784914078,AUTH,,,,,,")

	a := onlyAuth(t, feed(m, challenge))
	if a.challenge.StateID != "instance-7/123/abc" || a.url.Host != "idp.example.com" {
		t.Fatalf("auth action: %+v", a)
	}
	feed(m, ">STATE:1784914078,RECONNECTING,auth-failure,,,,,")
	// OpenVPN asks again ~5 s later, before the Keycloak login finished.
	if acts := feed(m, need); acts != nil {
		t.Fatalf("must wait for login, got %#v", acts)
	}
	wantCreds(t, m.onAuth("CRV1::instance-7/123/abc::PHNh", nil), "CRV1::instance-7/123/abc::PHNh")

	acts := feed(m, ">STATE:1784914084,CONNECTED,SUCCESS,10.0.0.5,203.0.113.10,443,,")
	if c, ok := acts[0].(connectedAction); !ok || c.st.LocalIP != "10.0.0.5" {
		t.Fatalf("connected: %#v", acts)
	}

	// ping-restart: same cycle, this time the login finishes first.
	feed(m, ">STATE:1784928382,RECONNECTING,ping-restart,,,,,")
	wantCreds(t, feed(m, need), "ACS::35001")
	onlyAuth(t, feed(m, challenge))
	if acts := m.onAuth("CRV1::instance-7/123/abc::PHNi", nil); acts != nil {
		t.Fatalf("no request pending, should store: %#v", acts)
	}
	wantCreds(t, feed(m, need), "CRV1::instance-7/123/abc::PHNi")
	if _, ok := feed(m, ">STATE:1,CONNECTED,SUCCESS,10.0.0.5,203.0.113.10,443,,")[0].(connectedAction); !ok {
		t.Fatal("reconnect not reported")
	}
}

func TestUntrustedIdPIsFatal(t *testing.T) {
	m := &machine{idpOrigin: "https://keycloak.example.com"}
	feed(m, need)
	f := onlyFail(t, feed(m, challenge))
	if f.retry || !strings.Contains(f.err.Error(), "not the trusted idp_origin") {
		t.Fatalf("got %+v", f)
	}
}

func TestRepeatedRejectionsGiveUp(t *testing.T) {
	m := &machine{idpOrigin: origin}
	for i := 1; i <= maxRejections; i++ {
		feed(m, need)
		onlyAuth(t, feed(m, challenge))
		m.onAuth("CRV1::x::y", nil)
		wantCreds(t, feed(m, need), "CRV1::x::y")
		acts := feed(m, `>PASSWORD:Verification Failed: 'Auth' ['Invalid username or password']`)
		if i < maxRejections {
			if _, ok := acts[0].(warnAction); !ok {
				t.Fatalf("rejection %d: want warning, got %#v", i, acts)
			}
			continue
		}
		f := onlyFail(t, acts)
		if f.retry || !strings.Contains(f.err.Error(), "Invalid username or password") {
			t.Fatalf("got %+v", f)
		}
	}
}

func TestConnectedResetsRejections(t *testing.T) {
	m := &machine{idpOrigin: origin, rejected: maxRejections - 1}
	feed(m, ">STATE:1,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,443,,")
	if m.rejected != 0 {
		t.Fatalf("rejected = %d", m.rejected)
	}
}

func TestLoginErrors(t *testing.T) {
	m := &machine{idpOrigin: origin}
	feed(m, need)
	onlyAuth(t, feed(m, challenge))
	if f := onlyFail(t, m.onAuth("", fmt.Errorf("%w: invalid authenticator code", keycloak.ErrRejected))); f.retry {
		t.Error("Keycloak credential errors must not be retried (account lockout)")
	}

	m = &machine{idpOrigin: origin}
	feed(m, need)
	onlyAuth(t, feed(m, challenge))
	if f := onlyFail(t, m.onAuth("", errors.New("dial tcp: i/o timeout"))); !f.retry {
		t.Error("network errors should restart the session")
	}
}

func TestFatalAndUnsupported(t *testing.T) {
	m := &machine{idpOrigin: origin}
	if f := onlyFail(t, feed(m, ">FATAL:ERROR: could not read Auth username/password/ok/string from management interface")); !f.retry {
		t.Error("FATAL should restart")
	}
	if f := onlyFail(t, feed(m, ">PASSWORD:Need 'Private Key' password")); f.retry {
		t.Error("unsupported credential request should be permanent")
	}
}

func TestRedactChallenge(t *testing.T) {
	got := redactChallenge(challenge)
	if strings.Contains(got, "fZJd") || !strings.Contains(got, "protocol/saml?SAMLRequest=…") {
		t.Errorf("got %q", got)
	}
}

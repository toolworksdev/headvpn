package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/secret"
)

type fakeBackend struct {
	states       []string
	i            int
	starts       atomic.Int32
	stops        atomic.Int32
	connectAfter *atomic.Bool // when set, Status reports Connected once true
}

func (f *fakeBackend) Status(ctx context.Context, p string) (string, error) {
	if f.connectAfter != nil && f.connectAfter.Load() {
		return "Connected", nil
	}
	s := f.states[min(f.i, len(f.states)-1)]
	f.i++
	return s, nil
}
func (f *fakeBackend) Start(ctx context.Context, p string) error { f.starts.Add(1); return nil }
func (f *fakeBackend) Stop(ctx context.Context, p string) error  { f.stops.Add(1); return nil }
func (f *fakeBackend) WaitFor(ctx context.Context, p, want string, every time.Duration) (string, error) {
	for {
		st, _ := f.Status(ctx, p)
		if st == want {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, fmt.Errorf("timeout waiting for %s", want)
		case <-time.After(time.Millisecond):
		}
	}
}

// fakeIdP answers login + OTP and posts the assertion to acs.
func fakeIdP(t *testing.T, pw string, acs string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("step") {
		case "":
			fmt.Fprintf(w, `<form id="kc-form-login" action="%s/a?step=login" method="post"><input name="username"/><input name="password" type="password"/></form>`, srv.URL)
		case "login":
			_ = r.ParseForm()
			if r.PostForm.Get("password") != pw {
				fmt.Fprintf(w, `<form id="kc-form-login" action="%s/a?step=login" method="post"><input name="username"/><input name="password"/></form><span id="input-error">Invalid username or password.</span>`, srv.URL)
				return
			}
			fmt.Fprintf(w, `<form id="kc-otp-login-form" action="%s/a?step=otp" method="post"><input name="otp"/></form>`, srv.URL)
		case "otp":
			fmt.Fprintf(w, `<form method="post" action="%s/"><input type="hidden" name="SAMLResponse" value="QQ=="/></form>`, acs)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T, b *fakeBackend, pw string) (config.Profile, Deps, *atomic.Int32) {
	t.Helper()
	var delivered atomic.Int32
	acs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("SAMLResponse") == "QQ==" {
			delivered.Add(1)
			if b.connectAfter != nil {
				b.connectAfter.Store(true)
			}
		}
	}))
	t.Cleanup(acs.Close)
	idp := fakeIdP(t, "right", acs.URL)
	jar, _ := cookiejar.New(nil)
	hc := idp.Client()
	hc.Jar = jar
	p := config.Profile{
		Backend: "aws-official", AWSProfile: "work", IdP: "keycloak", IdPOrigin: idp.URL,
		Username: "ana@example.com", Password: "env:PW", TOTPSecret: "env:SEED",
	}
	env := map[string]string{"PW": pw, "SEED": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}
	r := secret.NewResolver(nil)
	secret.SetTestHooks(r, func(k string) string { return env[k] })
	d := Deps{
		Backend: func(config.Profile) Backend { return b },
		Secrets: r,
		FindURL: func(ctx context.Context, origin string, since time.Time) (string, error) {
			if origin != idp.URL {
				t.Errorf("origin %q", origin)
			}
			return idp.URL + "/realms/r/protocol/saml?SAMLRequest=x", nil
		},
		HTTP: hc, Deliver: acs.Client(), Now: time.Now, Poll: time.Millisecond,
	}
	return p, d, &delivered
}

func TestConnectHappyPath(t *testing.T) {
	b := &fakeBackend{states: []string{"NotConnected", "WaitingForIdentity"}, connectAfter: new(atomic.Bool)}
	p, d, delivered := setup(t, b, "right")
	res, err := Connect(context.Background(), "work", p, d)
	if err != nil || res.State != "Connected" || res.Via != "headvpn" {
		t.Fatalf("%+v %v", res, err)
	}
	if b.starts.Load() != 1 || b.stops.Load() != 0 || delivered.Load() != 1 {
		t.Fatalf("starts=%d stops=%d delivered=%d", b.starts.Load(), b.stops.Load(), delivered.Load())
	}
}

func TestConnectWhenAlreadyUpDoesNothing(t *testing.T) {
	b := &fakeBackend{states: []string{"Connected"}}
	p, d, _ := setup(t, b, "right")
	res, err := Connect(context.Background(), "work", p, d)
	if err != nil || !res.Already || b.starts.Load() != 0 {
		t.Fatalf("%+v %v starts=%d", res, err, b.starts.Load())
	}
}

func TestMissingSecretFailsBeforeStarting(t *testing.T) {
	b := &fakeBackend{states: []string{"NotConnected"}}
	p, d, _ := setup(t, b, "")
	if _, err := Connect(context.Background(), "work", p, d); err == nil {
		t.Fatal("connected without a password")
	}
	if b.starts.Load() != 0 {
		t.Fatal("started the client before resolving secrets")
	}
}

func TestRejectedLoginCleansUpAndIsMarked(t *testing.T) {
	b := &fakeBackend{states: []string{"NotConnected", "WaitingForIdentity"}}
	p, d, delivered := setup(t, b, "wrong")
	_, err := Connect(context.Background(), "work", p, d)
	if !Rejected(err) {
		t.Fatalf("want a rejected-credentials error, got %v", err)
	}
	if b.stops.Load() != 1 || delivered.Load() != 0 {
		t.Fatalf("stops=%d delivered=%d", b.stops.Load(), delivered.Load())
	}
}

func TestStaleAttemptIsStoppedFirst(t *testing.T) {
	b := &fakeBackend{states: []string{"WaitingForIdentity", "NotConnected", "WaitingForIdentity"}, connectAfter: new(atomic.Bool)}
	p, d, _ := setup(t, b, "right")
	if _, err := Connect(context.Background(), "work", p, d); err != nil {
		t.Fatal(err)
	}
	if b.stops.Load() != 1 || b.starts.Load() != 1 {
		t.Fatalf("stops=%d starts=%d", b.stops.Load(), b.starts.Load())
	}
}

func TestBrowserWithLiveSessionConnectsFirst(t *testing.T) {
	b := &fakeBackend{states: []string{"NotConnected", "WaitingForIdentity", "WaitingForIdentity", "Connected"}}
	p, d, delivered := setup(t, b, "right")
	d.FindURL = func(ctx context.Context, origin string, since time.Time) (string, error) {
		<-ctx.Done() // history unreadable: never finds anything
		return "", ctx.Err()
	}
	t0 := time.Now()
	res, err := Connect(context.Background(), "work", p, d)
	if err != nil || res.State != "Connected" || res.Via != "browser" {
		t.Fatalf("%+v %v", res, err)
	}
	// Noticed while waiting, not after the 30 s history timeout.
	if el := time.Since(t0); el > 5*time.Second {
		t.Fatalf("took %s: the client state was not watched during the URL wait", el)
	}
	if b.stops.Load() != 0 || delivered.Load() != 0 {
		t.Fatalf("stops=%d delivered=%d: must neither tear down nor log in again", b.stops.Load(), delivered.Load())
	}
}

func TestWatcherStartsBeforeTheClient(t *testing.T) {
	b := &fakeBackend{states: []string{"NotConnected", "WaitingForIdentity"}, connectAfter: new(atomic.Bool)}
	p, d, _ := setup(t, b, "right")
	inner := d.FindURL
	var startsWhenWatching atomic.Int32
	startsWhenWatching.Store(-1)
	d.FindURL = func(ctx context.Context, origin string, since time.Time) (string, error) {
		startsWhenWatching.Store(b.starts.Load())
		return inner(ctx, origin, since)
	}
	if _, err := Connect(context.Background(), "work", p, d); err != nil {
		t.Fatal(err)
	}
	if n := startsWhenWatching.Load(); n != 0 {
		t.Fatalf("the URL watcher began after the client had started (starts=%d): it would miss the open", n)
	}
}

// refusingRT fails every request like a closed port, and remembers it tried.
type refusingRT struct{ tried *atomic.Bool }

func (r refusingRT) RoundTrip(*http.Request) (*http.Response, error) {
	r.tried.Store(true)
	return nil, errors.New("dial tcp 127.0.0.1:35001: connect: connection refused")
}

// The default browser answered the same SAML request first: the client
// closed its port, our delivery is refused, but the tunnel is coming up.
func TestBrowserWinsTheDeliveryRace(t *testing.T) {
	won := new(atomic.Bool)
	b := &fakeBackend{states: []string{"NotConnected", "WaitingForIdentity"}, connectAfter: won}
	p, d, _ := setup(t, b, "right")
	d.Deliver = &http.Client{Transport: refusingRT{won}} // the browser got there first
	res, err := Connect(context.Background(), "work", p, d)
	if err != nil || res.State != "Connected" || res.Via != "browser" {
		t.Fatalf("%+v %v", res, err)
	}
	if b.stops.Load() != 0 {
		t.Fatal("stopped a tunnel the browser was bringing up")
	}
}

func TestRefusedDeliveryWithoutProgressStillFails(t *testing.T) {
	b := &fakeBackend{states: []string{"NotConnected", "WaitingForIdentity"}}
	p, d, _ := setup(t, b, "right")
	d.Deliver = &http.Client{Transport: refusingRT{new(atomic.Bool)}}
	if _, err := Connect(context.Background(), "work", p, d); err == nil {
		t.Fatal("reported success while the client still waits for an identity")
	}
	if b.stops.Load() == 0 {
		t.Fatal("left the client waiting for an identity")
	}
}

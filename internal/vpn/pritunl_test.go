package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/toolworksdev/headvpn/internal/backend/pritunl"
	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/secret"
)

// fakePritunl models the client service: Start either connects at once
// (token still valid) or returns a login URL and connects once loginDone.
type fakePritunl struct {
	connected, active bool
	url               string // returned by Start
	connectAfterStart bool
	starts, stops     int
}

func (f *fakePritunl) Find(ctx context.Context, ref string) (pritunl.Profile, error) {
	if ref != "vpn (ana)" {
		return pritunl.Profile{}, pritunl.ErrNoProfile
	}
	rs := "Inactive"
	if f.active {
		rs = "Active"
	}
	return pritunl.Profile{ID: "abc", Name: ref, Connected: f.connected, RunState: rs}, nil
}

func (f *fakePritunl) Start(ctx context.Context, id, mode string) (string, error) {
	f.starts++
	f.active = true
	if f.connectAfterStart {
		f.connected = true
	}
	return f.url, nil
}

func (f *fakePritunl) Stop(ctx context.Context, id string) error {
	f.stops++
	f.active, f.connected = false, false
	return nil
}

func (f *fakePritunl) WaitFor(ctx context.Context, id string, want bool, every time.Duration) (pritunl.Profile, error) {
	for {
		if p, _ := f.Find(ctx, "vpn (ana)"); p.Connected == want && (want || !f.active) {
			return p, nil
		}
		select {
		case <-ctx.Done():
			return pritunl.Profile{}, ctx.Err()
		case <-time.After(every):
		}
	}
}

func pritunlDeps(f *fakePritunl) (Deps, *[]string) {
	var urls []string
	return Deps{
		Pritunl:    func(config.Profile) PritunlCLI { return f },
		Secrets:    secret.NewResolver(nil),
		Now:        time.Now,
		Poll:       time.Millisecond,
		OnLoginURL: func(_, u string) { urls = append(urls, u) },
	}, &urls
}

var handoff = config.Profile{Backend: "pritunl", PritunlProfile: "vpn (ana)"}

func TestPritunlTokenStillValidConnectsWithoutLogin(t *testing.T) {
	f := &fakePritunl{connectAfterStart: true}
	d, urls := pritunlDeps(f)
	r, err := Connect(context.Background(), "office", handoff, d)
	if err != nil || r.State != "Connected" || r.Via != "token" || len(*urls) != 0 {
		t.Fatalf("%+v %v urls=%v", r, err, *urls)
	}
}

func TestPritunlLoginIsHandedToAPersonAndTimesOutCleanly(t *testing.T) {
	f := &fakePritunl{url: "https://vpn.example.com/key/request?state=s"}
	d, urls := pritunlDeps(f)
	p := handoff
	p.ConnectTimeout.Duration = 50 * time.Millisecond
	r, err := Connect(context.Background(), "office", p, d)
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err=%v, want ErrLoginRequired", err)
	}
	if r.LoginURL != f.url || len(*urls) != 1 || (*urls)[0] != f.url {
		t.Fatalf("login URL not surfaced: result=%q events=%v", r.LoginURL, *urls)
	}
	if f.stops == 0 || f.active {
		t.Fatal("left a pending SSO attempt behind")
	}
}

func TestPritunlAlreadyConnectedDoesNothing(t *testing.T) {
	f := &fakePritunl{connected: true, active: true}
	d, _ := pritunlDeps(f)
	r, err := Connect(context.Background(), "office", handoff, d)
	if err != nil || !r.Already || f.starts != 0 {
		t.Fatalf("%+v %v starts=%d", r, err, f.starts)
	}
}

func TestPritunlEntraSecretsAreCheckedBeforeStarting(t *testing.T) {
	f := &fakePritunl{connectAfterStart: true}
	d, _ := pritunlDeps(f)
	p := handoff
	p.IdP, p.Username, p.Password, p.TOTPSecret = "entra", "ana@example.com", "env:HEADVPN_TEST_UNSET_PW", "env:HEADVPN_TEST_UNSET_SEED"
	if _, err := Connect(context.Background(), "office", p, d); err == nil {
		t.Fatal("connected without the password")
	}
	if f.starts != 0 {
		t.Fatal("started the client before resolving the secrets")
	}
}

func TestPritunlDisconnect(t *testing.T) {
	f := &fakePritunl{connected: true, active: true}
	d, _ := pritunlDeps(f)
	if r := Disconnect(context.Background(), "office", handoff, d); r.State != "NotConnected" || r.Error != "" {
		t.Fatalf("%+v", r)
	}
}

package pritunl

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fake replays canned CLI output per subcommand.
type fake struct {
	out   map[string][]string // subcommand -> successive outputs (last one repeats)
	calls []string
}

func (f *fake) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	q := f.out[args[0]]
	if len(q) == 0 {
		return nil, errors.New("exit status 1")
	}
	o := q[0]
	if len(q) > 1 {
		f.out[args[0]] = q[1:]
	}
	return []byte(o), nil
}

const (
	off = `[{"id":"abc","name":"work (ana)","run_state":"Inactive","connected":false,"status":"Disconnected"}]`
	on  = `[{"id":"abc","name":"work (ana)","run_state":"Active","connected":true,"status":"Connected","client_address":"10.0.0.2/26"}]`
	sso = "Single sign-on authentication required, open link to complete authentication:\nhttps://vpn.example.com/key/request?state=x\n"
)

func TestStartReturnsTheSSOLink(t *testing.T) {
	f := &fake{out: map[string][]string{"start": {sso}}}
	c := &Client{CLI: "pritunl-client", Run: f.run}
	u, err := c.Start(context.Background(), "abc", "ovpn")
	if err != nil || u != "https://vpn.example.com/key/request?state=x" {
		t.Fatalf("url=%q err=%v", u, err)
	}
	if f.calls[0] != "start abc --mode ovpn" {
		t.Fatalf("argv %q", f.calls[0])
	}
}

func TestStartWithValidTokenHasNoLink(t *testing.T) {
	f := &fake{out: map[string][]string{"start": {""}}}
	c := &Client{Run: f.run}
	if u, err := c.Start(context.Background(), "abc", ""); err != nil || u != "" {
		t.Fatalf("url=%q err=%v", u, err)
	}
}

func TestLoginURLIgnoresUnrelatedLinks(t *testing.T) {
	if u := loginURL("see https://docs.example.com for help\n"); u != "" {
		t.Fatalf("picked %q from output without the SSO notice", u)
	}
}

func TestFindByIDOrName(t *testing.T) {
	f := &fake{out: map[string][]string{"list": {off}}}
	c := &Client{Run: f.run}
	for _, ref := range []string{"abc", "work (ana)"} {
		if p, err := c.Find(context.Background(), ref); err != nil || p.ID != "abc" {
			t.Fatalf("%s: %+v %v", ref, p, err)
		}
	}
	if _, err := c.Find(context.Background(), "nope"); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitForConnected(t *testing.T) {
	f := &fake{out: map[string][]string{"list": {off, off, on}}}
	c := &Client{Run: f.run}
	p, err := c.WaitFor(context.Background(), "abc", true, time.Millisecond)
	if err != nil || !p.Connected {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestServiceDownIsExplained(t *testing.T) {
	c := &Client{Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("Error: sprofile: Request failed\nGet \"http://unix/sprofile\": dial unix /var/run/pritunl.sock: connect: no such file or directory"), errors.New("exit status 1")
	}}
	if _, err := c.List(context.Background()); !errors.Is(err, ErrServiceDown) {
		t.Fatalf("err=%v, want ErrServiceDown", err)
	}
}

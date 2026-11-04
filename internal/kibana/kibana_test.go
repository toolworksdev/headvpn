package kibana

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/toolworksdev/headvpn/internal/saml"
)

// fakeApp is a Kibana with a SAML realm and a console proxy.
type fakeApp struct {
	idpLogin  string // where saml/login redirects
	acsPosts  atomic.Int32
	methods   []string // method= of every proxied request
	paths     []string
	bodies    []string
	gotAssert string
}

func (f *fakeApp) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_plugin/kibana/auth/saml/login":
			http.Redirect(w, r, f.idpLogin+"?SAMLRequest=abc", http.StatusFound)
		case r.URL.Path == "/_plugin/kibana/_opendistro/_security/saml/acs" && r.Method == http.MethodPost:
			f.acsPosts.Add(1)
			_ = r.ParseForm()
			f.gotAssert = r.PostForm.Get("SAMLResponse")
			http.SetCookie(w, &http.Cookie{Name: "security_authentication", Value: "s1", Path: "/_plugin/kibana"})
			http.Redirect(w, r, "/_plugin/kibana/", http.StatusFound)
		case r.URL.Path == "/_plugin/kibana/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/_plugin/kibana/api/console/proxy":
			if ck, err := r.Cookie("security_authentication"); err != nil || ck.Value != "s1" {
				http.Error(w, `{"statusCode":401}`, http.StatusUnauthorized)
				return
			}
			if r.Header.Get("kbn-xsrf") == "" {
				http.Error(w, "xsrf", http.StatusBadRequest)
				return
			}
			b, _ := io.ReadAll(r.Body)
			f.methods = append(f.methods, r.URL.Query().Get("method"))
			f.paths = append(f.paths, r.URL.Query().Get("path"))
			f.bodies = append(f.bodies, string(b))
			_, _ = w.Write([]byte(`{"count":42}`))
		default:
			http.NotFound(w, r)
		}
	})
}

type env struct {
	app, other *httptest.Server
	f          *fakeApp
	c          *Client
	otherHits  atomic.Int32
}

// newEnv starts the app and an unrelated https server (a stand-in for both
// the IdP and any attacker-controlled host).
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{f: &fakeApp{}}
	e.other = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.otherHits.Add(1)
	}))
	t.Cleanup(e.other.Close)
	e.app = httptest.NewTLSServer(e.f.handler(t))
	t.Cleanup(e.app.Close)
	e.f.idpLogin = e.other.URL + "/realms/r/protocol/saml"
	c, err := New(e.app.URL+"/_plugin/kibana", e.other.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.SetTransport(e.app.Client().Transport) // trusts httptest's shared test CA
	e.c = c
	return e
}

func goodIdP(e *env, calls *int) IdP {
	return func(ctx context.Context, loginURL string) (*saml.PostForm, error) {
		*calls++
		return &saml.PostForm{Action: e.app.URL + "/_plugin/kibana/_opendistro/_security/saml/acs",
			SAMLResponse: "PHNhbWw+", RelayState: "rs"}, nil
	}
}

func TestLoginThenReadOnlyGet(t *testing.T) {
	e := newEnv(t)
	calls := 0
	if err := e.c.Login(context.Background(), goodIdP(e, &calls)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || e.f.acsPosts.Load() != 1 || e.f.gotAssert != "PHNhbWw+" {
		t.Fatalf("idp calls=%d acs=%d assertion=%q", calls, e.f.acsPosts.Load(), e.f.gotAssert)
	}
	st, body, err := e.c.Get(context.Background(), "/logs/_search", []byte(`{"size":1}`))
	if err != nil || st != 200 || string(body) != `{"count":42}` {
		t.Fatalf("get: st=%d body=%s err=%v", st, body, err)
	}
	if e.f.methods[0] != "GET" || e.f.paths[0] != "logs/_search" || e.f.bodies[0] != `{"size":1}` {
		t.Fatalf("proxied %v %v %v", e.f.methods, e.f.paths, e.f.bodies)
	}
}

func TestGetIsAlwaysGET(t *testing.T) {
	e := newEnv(t)
	calls := 0
	if err := e.c.Login(context.Background(), goodIdP(e, &calls)); err != nil {
		t.Fatal(err)
	}
	// A path that smuggles another method must still be proxied as GET.
	_, _, _ = e.c.Get(context.Background(), "logs/_doc/1?method=DELETE", nil)
	for _, m := range e.f.methods {
		if m != "GET" {
			t.Fatalf("proxied method %q", m)
		}
	}
}

func TestRefusesLoginRedirectOutsideIdPOrigin(t *testing.T) {
	e := newEnv(t)
	evil := httptest.NewTLSServer(http.NotFoundHandler())
	defer evil.Close()
	e.f.idpLogin = evil.URL + "/phish"
	calls := 0
	err := e.c.Login(context.Background(), goodIdP(e, &calls))
	if err == nil || calls != 0 {
		t.Fatalf("err=%v idp calls=%d: the IdP must not be asked", err, calls)
	}
}

func TestRefusesAssertionToAnotherOrigin(t *testing.T) {
	e := newEnv(t)
	idp := func(ctx context.Context, loginURL string) (*saml.PostForm, error) {
		return &saml.PostForm{Action: e.other.URL + "/acs", SAMLResponse: "PHNhbWw+"}, nil
	}
	before := e.otherHits.Load()
	err := e.c.Login(context.Background(), idp)
	if err == nil || !strings.Contains(err.Error(), "refusing to send the SAML assertion") {
		t.Fatalf("err=%v", err)
	}
	if e.otherHits.Load() != before {
		t.Fatal("the assertion reached another host")
	}
}

func TestRefusesPlainHTTPAssertionConsumer(t *testing.T) {
	e := newEnv(t)
	u, _ := url.Parse(e.app.URL)
	idp := func(ctx context.Context, loginURL string) (*saml.PostForm, error) {
		return &saml.PostForm{Action: "http://" + u.Host + "/_plugin/kibana/_opendistro/_security/saml/acs", SAMLResponse: "x"}, nil
	}
	if err := e.c.Login(context.Background(), idp); err == nil {
		t.Fatal("assertion sent over http")
	}
}

func TestIdPErrorStopsLogin(t *testing.T) {
	e := newEnv(t)
	boom := errors.New("rejected")
	err := e.c.Login(context.Background(), func(ctx context.Context, loginURL string) (*saml.PostForm, error) { return nil, boom })
	if !errors.Is(err, boom) || e.f.acsPosts.Load() != 0 {
		t.Fatalf("err=%v acs=%d", err, e.f.acsPosts.Load())
	}
}

func TestGetWithoutLoginIsUnauthorized(t *testing.T) {
	e := newEnv(t)
	st, _, err := e.c.Get(context.Background(), "logs/_count", nil)
	if err != nil || st != http.StatusUnauthorized {
		t.Fatalf("st=%d err=%v", st, err)
	}
}

func TestNewRequiresHTTPS(t *testing.T) {
	if _, err := New("http://search.example.com/_plugin/kibana", "https://idp.example.com"); err == nil {
		t.Fatal("http app accepted")
	}
	if _, err := New("https://search.example.com/_plugin/kibana", "http://idp.example.com"); err == nil {
		t.Fatal("http idp accepted")
	}
}

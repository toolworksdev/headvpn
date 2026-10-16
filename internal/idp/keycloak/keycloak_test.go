package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Markup trimmed from a real Keycloak 26 (PatternFly 5) login theme.
const loginPage = `<!DOCTYPE html><html><head><title>Sign in to Example</title></head><body>
<form id="kc-form-login" action="%s/realms/r/login-actions/authenticate?session_code=a&execution=b" method="post">
<input id="username" name="username" value="" type="text"/>
<div id="input-error-container-username"></div>
<input id="password" name="password" value="" type="password"/>
<div id="input-error-container-password"></div>
<input type="checkbox" id="rememberMe" name="rememberMe"/>
<input type="hidden" id="id-hidden-input" name="credentialId"/>
<input type="hidden" name="csrf" value="tok-1"/>
</form>
<form id="webauth" action="%s/realms/r/login-actions/authenticate?x=passkey" method="post">
<input type="hidden" name="clientDataJSON"/>
</form>%s</body></html>`

const otpPage = `<html><head><title>Sign in to Example</title></head><body>
<form id="kc-otp-login-form" action="%s/realms/r/login-actions/authenticate?session_code=c&execution=d" method="post">
<input type="radio" name="selectedCredentialId" value="cred-1" checked/>
<input id="otp" name="otp" autocomplete="one-time-code" type="text"/>
</form>%s</body></html>`

const samlPage = `<html><body onload="document.forms[0].submit()">
<form method="post" action="http://127.0.0.1:35001/">
<input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
<input type="hidden" name="RelayState" value="rs-1"/>
</form></body></html>`

const errSpan = `<span id="input-error" class="pf-v5-c-helper-text__item-text">Invalid username or password.</span>`

type fakeKC struct {
	pw, otp       string
	loginPosts    atomic.Int32
	otpPosts      atomic.Int32
	actionOrigin  string // where forms post; defaults to the server itself
	redirectStart string // when set, the first GET redirects here
}

func (f *fakeKC) handler(self func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := f.actionOrigin
		if origin == "" {
			origin = self()
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/realms/r/protocol/saml"):
			if f.redirectStart != "" {
				http.Redirect(w, r, f.redirectStart, http.StatusFound)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "AUTH_SESSION_ID", Value: "s1", Path: "/"})
			fmt.Fprintf(w, loginPage, origin, origin, "")
		case r.Method == http.MethodPost && r.URL.Query().Get("execution") == "b":
			f.loginPosts.Add(1)
			if c, err := r.Cookie("AUTH_SESSION_ID"); err != nil || c.Value != "s1" {
				http.Error(w, "no session", http.StatusBadRequest)
				return
			}
			_ = r.ParseForm()
			if r.PostForm.Get("csrf") != "tok-1" {
				http.Error(w, "hidden fields were not submitted", http.StatusBadRequest)
				return
			}
			if r.PostForm.Get("username") != "ana@example.com" || r.PostForm.Get("password") != f.pw {
				fmt.Fprintf(w, loginPage, origin, origin, errSpan)
				return
			}
			fmt.Fprintf(w, otpPage, origin, "")
		case r.Method == http.MethodPost && r.URL.Query().Get("execution") == "d":
			f.otpPosts.Add(1)
			_ = r.ParseForm()
			if r.PostForm.Get("selectedCredentialId") != "cred-1" || r.PostForm.Get("otp") != f.otp {
				fmt.Fprintf(w, otpPage, origin, `<span id="input-error-otp-code">Invalid authenticator code.</span>`)
				return
			}
			fmt.Fprint(w, samlPage)
		default:
			http.NotFound(w, r)
		}
	})
}

func newServer(t *testing.T, f *fakeKC) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(f.handler(func() string { return srv.URL }))
	t.Cleanup(srv.Close)
	return srv
}

func login(srv *httptest.Server, pw string, otpCalls *int) *Login {
	jar, _ := cookiejar.New(nil)
	c := srv.Client()
	c.Jar = jar
	return &Login{
		Origin: srv.URL, Username: "ana@example.com", Password: pw, Client: c,
		OTP: func() (string, error) { *otpCalls++; return "123456", nil },
	}
}

func TestHappyPathReturnsLoopbackSAMLForm(t *testing.T) {
	f := &fakeKC{pw: "right", otp: "123456"}
	srv := newServer(t, f)
	calls := 0
	form, err := login(srv, "right", &calls).Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x")
	if err != nil {
		t.Fatal(err)
	}
	if form.Action != "http://127.0.0.1:35001/" || form.SAMLResponse != "PHNhbWw+" || form.RelayState != "rs-1" {
		t.Fatalf("unexpected form %+v", form)
	}
	if calls != 1 || f.loginPosts.Load() != 1 || f.otpPosts.Load() != 1 {
		t.Fatalf("calls otp=%d loginPosts=%d otpPosts=%d", calls, f.loginPosts.Load(), f.otpPosts.Load())
	}
}

func TestWrongPasswordStopsAfterOneAttempt(t *testing.T) {
	f := &fakeKC{pw: "right", otp: "123456"}
	srv := newServer(t, f)
	calls := 0
	_, err := login(srv, "wrong", &calls).Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x")
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "Invalid username or password") {
		t.Fatalf("want ErrRejected with the page message, got %v", err)
	}
	if f.loginPosts.Load() != 1 || calls != 0 {
		t.Fatalf("must not retry: loginPosts=%d otpCalls=%d", f.loginPosts.Load(), calls)
	}
}

func TestWrongOTPStopsAfterOneAttempt(t *testing.T) {
	f := &fakeKC{pw: "right", otp: "999999"}
	srv := newServer(t, f)
	calls := 0
	_, err := login(srv, "right", &calls).Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x")
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "Invalid authenticator code") {
		t.Fatalf("want ErrRejected with the page message, got %v", err)
	}
	if f.otpPosts.Load() != 1 || calls != 1 {
		t.Fatalf("must not retry: otpPosts=%d otpCalls=%d", f.otpPosts.Load(), calls)
	}
}

func TestRefusesLoginURLOutsideOrigin(t *testing.T) {
	var hits atomic.Int32
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer untrusted.Close()
	l := &Login{Origin: "https://idp.example.com", Username: "ana@example.com", Password: "right", Client: untrusted.Client()}
	if _, err := l.Run(context.Background(), untrusted.URL+"/realms/r/protocol/saml?SAMLRequest=x"); err == nil {
		t.Fatal("accepted a login URL outside idp_origin")
	}
	// Not even the first GET may leave: the URL came from outside this tool.
	if hits.Load() != 0 {
		t.Fatalf("the untrusted host received %d requests", hits.Load())
	}
}

func TestNeverPostsCredentialsToAnotherOrigin(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	f := &fakeKC{pw: "right", otp: "123456", actionOrigin: evil.URL}
	srv := newServer(t, f)
	calls := 0
	_, err := login(srv, "right", &calls).Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x")
	if err == nil || !strings.Contains(err.Error(), "refusing to post credentials") {
		t.Fatalf("want refusal, got %v", err)
	}
	if evilHits.Load() != 0 {
		t.Fatalf("the other origin received %d requests", evilHits.Load())
	}
}

func TestRefusesRedirectOutsideOrigin(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	f := &fakeKC{pw: "right", otp: "123456", redirectStart: evil.URL + "/phish"}
	srv := newServer(t, f)
	calls := 0
	if _, err := login(srv, "right", &calls).Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x"); err == nil {
		t.Fatal("followed a redirect outside idp_origin")
	}
	if evilHits.Load() != 0 {
		t.Fatalf("the other origin received %d requests", evilHits.Load())
	}
}

func TestOriginMustBeHTTPS(t *testing.T) {
	if _, err := parseOrigin("http://idp.example.com"); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("accepted a plain-http IdP: %v", err)
	}
	for _, ok := range []string{"https://idp.example.com", "http://127.0.0.1:8080"} {
		if _, err := parseOrigin(ok); err != nil {
			t.Fatalf("parseOrigin(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "idp.example.com", "https://"} {
		if _, err := parseOrigin(bad); err == nil {
			t.Fatalf("parseOrigin(%q) accepted", bad)
		}
	}
}

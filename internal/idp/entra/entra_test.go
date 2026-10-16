package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeEntra reproduces the sequence measured against a real tenant:
// authorize page → password → MFA (BeginAuth/EndAuth/ProcessAuth) → KMSI →
// redirect to the VPN server. Every $Config carries only the fields read.
type fakeEntra struct {
	t                 *testing.T
	idp, vpn          *httptest.Server
	proofs            string // JSON array for arrUserProofs
	postURL           string // overrides urlPost on the password page
	mu                sync.Mutex
	passwordsSeenAt   []string // hosts that received a passwd field
	codes             []string
	callback          bool
	redirectElsewhere string
}

func cfgPage(w http.ResponseWriter, cfg map[string]any) {
	b, _ := json.Marshal(cfg)
	fmt.Fprintf(w, "<html><script>//<![CDATA[\n$Config=%s;\n//]]></script></html>", b)
}

func newFake(t *testing.T) *fakeEntra {
	f := &fakeEntra{t: t, proofs: `[{"authMethodId":"PhoneAppAuthentication","isDefault":true},{"authMethodId":"PhoneAppOTP"}]`}
	f.idp = httptest.NewTLSServer(http.HandlerFunc(f.serveIdP))
	f.vpn = httptest.NewTLSServer(http.HandlerFunc(f.serveVPN))
	t.Cleanup(f.idp.Close)
	t.Cleanup(f.vpn.Close)
	return f
}

func (f *fakeEntra) serveVPN(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/key/request":
		http.Redirect(w, r, f.idp.URL+"/tenant/oauth2/v2.0/authorize?client_id=x&state=s", http.StatusFound)
	case "/callback":
		if r.URL.Query().Get("code") == "authcode" {
			f.callback = true
		}
		fmt.Fprint(w, "ok")
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeEntra) serveIdP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.PostForm.Get("passwd") != "" {
		f.mu.Lock()
		f.passwordsSeenAt = append(f.passwordsSeenAt, r.Host)
		f.mu.Unlock()
	}
	switch r.URL.Path {
	case "/tenant/oauth2/v2.0/authorize":
		post := f.idp.URL + "/tenant/login"
		if f.postURL != "" {
			post = f.postURL
		}
		cfgPage(w, map[string]any{"pgid": "ConvergedSignIn", "sFT": "ft1", "sCtx": "c1", "canary": "k", "urlPost": post, "sErrorCode": "50058"})
	case "/tenant/login":
		if r.PostForm.Get("flowToken") != "ft1" || r.PostForm.Get("ctx") != "c1" {
			http.Error(w, "bad flow", 400)
			return
		}
		if r.PostForm.Get("loginfmt") != "ana@example.com" || r.PostForm.Get("passwd") != "right" {
			cfgPage(w, map[string]any{"pgid": "ConvergedSignIn", "sErrorCode": "50126", "sFT": "ft1", "urlPost": f.idp.URL + "/tenant/login"})
			return
		}
		cfgPage(w, map[string]any{"pgid": "DetectBrowserCapabilities", "urlResume": f.idp.URL + "/tenant/resume?ctx=c1"})
	case "/tenant/resume":
		var proofs []any
		_ = json.Unmarshal([]byte(f.proofs), &proofs)
		cfgPage(w, map[string]any{"pgid": "ConvergedTFA", "arrUserProofs": proofs, "sFT": "ft2", "sCtx": "c2",
			"canary": "k", "apiCanary": "ak", "hpgid": 1114, "hpgact": 2000,
			"urlBeginAuth": f.idp.URL + "/common/SAS/BeginAuth", "urlEndAuth": f.idp.URL + "/common/SAS/EndAuth",
			"urlPost": f.idp.URL + "/common/SAS/ProcessAuth"})
	case "/common/SAS/BeginAuth":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		ok := b["AuthMethodId"] == "PhoneAppOTP" && b["flowToken"] == "ft2" && r.Header.Get("canary") == "ak"
		_ = json.NewEncoder(w).Encode(map[string]any{"Success": ok, "SessionId": "sess", "FlowToken": "ft3", "Ctx": "c3"})
	case "/common/SAS/EndAuth":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		code, _ := b["AdditionalAuthData"].(string)
		f.codes = append(f.codes, code)
		if code != "123456" || b["SessionId"] != "sess" {
			_ = json.NewEncoder(w).Encode(map[string]any{"Success": false, "ResultValue": "OathCodeIncorrect"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Success": true, "FlowToken": "ft4", "Ctx": "c4"})
	case "/common/SAS/ProcessAuth":
		if r.PostForm.Get("flowToken") != "ft4" || r.PostForm.Get("otc") != "123456" || r.PostForm.Get("request") != "c4" {
			http.Error(w, "bad process", 400)
			return
		}
		cfgPage(w, map[string]any{"pgid": "KmsiInterrupt", "sFT": "ft5", "sCtx": "c5", "canary": "k", "urlPost": "/kmsi"})
	case "/kmsi":
		if r.PostForm.Get("flowToken") != "ft5" {
			http.Error(w, "bad kmsi", 400)
			return
		}
		target := f.vpn.URL + "/callback?code=authcode&state=s"
		if f.redirectElsewhere != "" {
			target = f.redirectElsewhere
		}
		http.Redirect(w, r, target, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeEntra) login(pw string, otp func() (string, error)) *Login {
	jar, _ := cookiejar.New(nil)
	c := f.idp.Client()
	c.Jar = jar
	return &Login{Origin: f.idp.URL, Username: "ana@example.com", Password: pw, OTP: otp, Client: c}
}

func code(n *int) func() (string, error) {
	return func() (string, error) { *n++; return "123456", nil }
}

func TestSignInReachesTheVPNServer(t *testing.T) {
	f := newFake(t)
	var asked int
	if err := f.login("right", code(&asked)).Run(context.Background(), f.vpn.URL+"/key/request?state=s"); err != nil {
		t.Fatal(err)
	}
	if !f.callback {
		t.Fatal("the VPN server never got the authorization code")
	}
	if asked != 1 || len(f.codes) != 1 {
		t.Fatalf("codes asked=%d sent=%d, want exactly one", asked, len(f.codes))
	}
}

func TestWrongPasswordIsFinalAndNeverAsksForACode(t *testing.T) {
	f := newFake(t)
	var asked int
	err := f.login("wrong", code(&asked)).Run(context.Background(), f.vpn.URL+"/key/request")
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "50126") {
		t.Fatalf("err=%v, want ErrRejected AADSTS50126", err)
	}
	if asked != 0 {
		t.Fatal("generated a code after a rejected password")
	}
}

func TestWrongCodeIsRejected(t *testing.T) {
	f := newFake(t)
	err := f.login("right", func() (string, error) { return "000000", nil }).Run(context.Background(), f.vpn.URL+"/key/request")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err=%v, want ErrRejected", err)
	}
	if len(f.codes) != 1 {
		t.Fatalf("sent %d codes, want 1 (no retry)", len(f.codes))
	}
}

func TestPushOnlyAccountIsUnsupported(t *testing.T) {
	f := newFake(t)
	f.proofs = `[{"authMethodId":"PhoneAppNotification","isDefault":true}]`
	var asked int
	err := f.login("right", code(&asked)).Run(context.Background(), f.vpn.URL+"/key/request")
	if !errors.Is(err, ErrUnexpectedPage) || asked != 0 {
		t.Fatalf("err=%v asked=%d", err, asked)
	}
}

func TestPasswordNeverLeavesTheIdP(t *testing.T) {
	f := newFake(t)
	evil := httptest.NewTLSServer(http.HandlerFunc(f.serveIdP)) // records passwd too
	defer evil.Close()
	f.postURL = evil.URL + "/tenant/login"
	err := f.login("right", nil).Run(context.Background(), f.vpn.URL+"/key/request")
	if err == nil {
		t.Fatal("followed a page that posts the password elsewhere")
	}
	for _, h := range f.passwordsSeenAt {
		if h != strings.TrimPrefix(f.idp.URL, "https://") {
			t.Fatalf("password reached %s", h)
		}
	}
}

func TestRedirectToAnUntrustedHostIsRefused(t *testing.T) {
	f := newFake(t)
	var hit bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true; fmt.Fprint(w, "x") }))
	defer other.Close()
	f.redirectElsewhere = other.URL + "/steal?code=authcode"
	var asked int
	err := f.login("right", code(&asked)).Run(context.Background(), f.vpn.URL+"/key/request")
	if err == nil || hit {
		t.Fatalf("err=%v hit=%v: the authorization code must not reach an untrusted host", err, hit)
	}
	if strings.Contains(err.Error(), "authcode") {
		t.Fatalf("error message leaks the authorization code: %v", err)
	}
}

func TestReturnThroughAConfiguredRelay(t *testing.T) {
	f := newFake(t)
	var relayed bool
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayed = true
		http.Redirect(w, r, f.vpn.URL+"/callback?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer relay.Close()
	f.redirectElsewhere = relay.URL + "/callback/azure?code=authcode&state=s"
	var asked int
	l := f.login("right", code(&asked))
	if err := l.Run(context.Background(), f.vpn.URL+"/key/request"); err == nil {
		t.Fatal("followed a relay that was not configured")
	}
	f.callback, relayed = false, false
	l = f.login("right", code(&asked))
	l.Relays = []string{relay.URL}
	if err := l.Run(context.Background(), f.vpn.URL+"/key/request"); err != nil || !relayed || !f.callback {
		t.Fatalf("err=%v relayed=%v callback=%v", err, relayed, f.callback)
	}
}

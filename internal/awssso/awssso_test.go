package awssso

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/toolworksdev/headvpn/internal/saml"
)

// fakeAWS answers every AWS host of a login, in the order measured on a real
// access portal federated with an external IdP. Requests reach it whatever
// host the URL names (the client dials it for every host), so the real host
// names — and the guards on them — are exercised.
type fakeAWS struct {
	t          *testing.T
	srv        *httptest.Server
	cb         *httptest.Server // the CLI's loopback
	mu         sync.Mutex
	hits       map[string]int // host+path → count
	consented  bool
	gotCode    string
	gotState   string
	consentFor string // clientId the consent screen shows
	acsRedir   string // where the ACS sends the browser after the IdP
	backTo     string // where authorize finally sends the code (default: cb)
}

const (
	region   = "us-east-1"
	startURL = "https://example.awsapps.com/start/#"
	clientID = "cli-client"
	state    = "st-123"
)

func newFake(t *testing.T) *fakeAWS {
	f := &fakeAWS{t: t, hits: map[string]int{}, consentFor: clientID}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.cb = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.gotCode, f.gotState = r.URL.Query().Get("code"), r.URL.Query().Get("state")
		f.mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(func() { f.srv.Close(); f.cb.Close() })
	return f
}

func (f *fakeAWS) client() *http.Client {
	addr := f.srv.Listener.Addr().String()
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test server only
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

func (f *fakeAWS) authorizeURL() string {
	return "https://oidc." + region + ".amazonaws.com/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "state": {state},
		"redirect_uri": {f.cb.URL + "/oauth/callback"}, "code_challenge": {"x"}, "code_challenge_method": {"S256"},
	}.Encode()
}

func (f *fakeAWS) count(hostPath string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[hostPath]
}

func (f *fakeAWS) hostHits(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, v := range f.hits {
		if strings.HasPrefix(k, host+"/") {
			n += v
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.Host+r.URL.Path]++
	consented := f.consented
	f.mu.Unlock()
	_ = r.ParseForm()
	q := r.URL.Query()
	oidc := "oidc." + region + ".amazonaws.com"
	portal := "portal.sso." + region + ".amazonaws.com"
	switch r.Host + r.URL.Path {
	case oidc + "/authorize":
		if arc := q.Get("authorization_resumption_context"); arc != "" {
			if arc != "ARC" {
				http.Error(w, "bad arc", 400)
				return
			}
			if consented {
				back := f.backTo
				if back == "" {
					back = f.cb.URL + "/oauth/callback"
				}
				http.Redirect(w, r, back+"?code=CODE&state="+state, http.StatusFound)
				return
			}
			http.Redirect(w, r, "https://example.awsapps.com/start/?clientId="+f.consentFor+"&clientType=PUBLIC&authorizationResumptionContext=ARC", http.StatusFound)
			return
		}
		http.Redirect(w, r, "https://example.awsapps.com/start/?callback_url=x&orchestrator_id=ORCH", http.StatusFound)
	case portal + "/login":
		if q.Get("directory_id") != "example" || !strings.Contains(q.Get("redirect_url"), "orchestrator_id=ORCH") {
			http.Error(w, "bad login", 400)
			return
		}
		writeJSON(w, map[string]string{"redirectUrl": "https://" + region + ".signin.aws/platform/d-1/login?workflowStateHandle=W&shouldRedirect=true", "csrfToken": "CSRF"})
	case region + ".signin.aws/platform/d-1/login":
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		fmt.Fprint(w, `<html><body><form id='postForm' method='POST' action='https://idp.example.com/saml'><input type='hidden' name='SAMLRequest' value='REQ'/><input type='hidden' name='RelayState' value='RS'/></form><script>document.getElementById('postForm').submit();</script></body></html>`)
	case region + ".signin.aws.amazon.com/platform/saml/acs/1":
		http.Redirect(w, r, "https://"+region+".signin.aws/platform/saml/acs/1", http.StatusTemporaryRedirect)
	case region + ".signin.aws/platform/saml/acs/1":
		if r.PostForm.Get("SAMLResponse") != "RESP" || r.PostForm.Get("RelayState") != "RS" {
			http.Error(w, "bad assertion", 400)
			return
		}
		to := f.acsRedir
		if to == "" {
			to = "https://example.awsapps.com/start/?state=ST&workflowResultHandle=WR&wdc_csrf_token=W"
		}
		http.Redirect(w, r, to, http.StatusFound)
	case portal + "/auth/sso-token":
		if r.Header.Get("x-amz-sso-csrf-token") != "CSRF" || r.PostForm.Get("authCode") != "WR" || r.PostForm.Get("state") != "ST" || r.PostForm.Get("orgId") != "example" {
			http.Error(w, "bad sso-token", 400)
			return
		}
		writeJSON(w, map[string]any{"token": "TOKEN", "redirectUrl": "https://example.awsapps.com/start/", "errorMessage": nil})
	case oidc + "/authentication_result":
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if r.Header.Get("x-amz-sso_bearer_token") != "TOKEN" || b["orchestrator_id"] != "ORCH" {
			http.Error(w, "bad authentication_result", 401)
			return
		}
		writeJSON(w, map[string]any{"location": "https://" + oidc + "/authorize?authorization_resumption_context=ARC"})
	case portal + "/session/device":
		if r.Header.Get("Authorization") != "Bearer TOKEN" {
			http.Error(w, "no auth", 401)
			return
		}
		writeJSON(w, map[string]string{"token": "USERSESSION"})
	case oidc + "/consent_details":
		writeJSON(w, map[string]any{"clientName": "botocore-client-x", "consentStatus": "PENDING"})
	case oidc + "/device_authorization/associate_token":
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["authorizationResumptionContext"] != "ARC" || b["userSessionId"] != "USERSESSION" {
			http.Error(w, "bad associate", 400)
			return
		}
		f.mu.Lock()
		f.consented = true
		f.mu.Unlock()
		writeJSON(w, map[string]any{})
	default:
		http.Error(w, "unexpected "+r.Host+r.URL.Path, 404)
	}
}

// idp returns the SAML response a real IdP would, addressed to acs.
func idp(t *testing.T, acs string, calls *int) IdP {
	return func(ctx context.Context, action string, form url.Values) (*saml.PostForm, error) {
		*calls++
		if action != "https://idp.example.com/saml" || form.Get("SAMLRequest") != "REQ" {
			t.Errorf("IdP got action %q SAMLRequest %q", action, form.Get("SAMLRequest"))
		}
		return &saml.PostForm{Action: acs, SAMLResponse: "RESP", RelayState: form.Get("RelayState")}, nil
	}
}

func (f *fakeAWS) flow(acs string, calls *int) *Flow {
	return &Flow{StartURL: startURL, Region: region, Client: f.client(), IdP: idp(f.t, acs, calls)}
}

const goodACS = "https://" + region + ".signin.aws.amazon.com/platform/saml/acs/1"

func TestLoginWithConsent(t *testing.T) {
	f := newFake(t)
	var calls int
	if err := f.flow(goodACS, &calls).Run(context.Background(), f.authorizeURL()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || f.gotCode != "CODE" || f.gotState != state {
		t.Fatalf("idp calls %d, callback code %q state %q", calls, f.gotCode, f.gotState)
	}
	if n := f.count("oidc." + region + ".amazonaws.com/device_authorization/associate_token"); n != 1 {
		t.Fatalf("consent approved %d times, want 1", n)
	}
}

func TestLoginAlreadyConsented(t *testing.T) {
	f := newFake(t)
	f.consented = true
	var calls int
	if err := f.flow(goodACS, &calls).Run(context.Background(), f.authorizeURL()); err != nil {
		t.Fatal(err)
	}
	if f.gotCode != "CODE" {
		t.Fatalf("callback code %q", f.gotCode)
	}
	if n := f.count("oidc." + region + ".amazonaws.com/device_authorization/associate_token"); n != 0 {
		t.Fatalf("approved consent %d times on an already-consented client", n)
	}
}

func TestRefusesAssertionForAnotherHost(t *testing.T) {
	f := newFake(t)
	var calls int
	err := f.flow("https://evil.example.net/acs", &calls).Run(context.Background(), f.authorizeURL())
	if err == nil || !strings.Contains(err.Error(), "refusing to send the SAML assertion") {
		t.Fatalf("err = %v", err)
	}
	if n := f.hostHits("evil.example.net"); n != 0 {
		t.Fatalf("the assertion reached the untrusted host (%d requests)", n)
	}
}

func TestRefusesAssertionOverHTTP(t *testing.T) {
	f := newFake(t)
	var calls int
	err := f.flow("http://"+region+".signin.aws.amazon.com/platform/saml/acs/1", &calls).Run(context.Background(), f.authorizeURL())
	if err == nil || !strings.Contains(err.Error(), "refusing to send the SAML assertion") {
		t.Fatalf("err = %v", err)
	}
}

func TestRefusesConsentForAnotherClient(t *testing.T) {
	f := newFake(t)
	f.consentFor = "someone-else"
	var calls int
	err := f.flow(goodACS, &calls).Run(context.Background(), f.authorizeURL())
	if err == nil || !strings.Contains(err.Error(), "client other than the CLI's") {
		t.Fatalf("err = %v", err)
	}
	if n := f.count("oidc." + region + ".amazonaws.com/device_authorization/associate_token"); n != 0 {
		t.Fatalf("approved consent for another client (%d)", n)
	}
}

func TestRefusesCodeForAnotherPort(t *testing.T) {
	f := newFake(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the code reached a loopback port the CLI does not listen on")
	}))
	defer other.Close()
	f.backTo = other.URL + "/oauth/callback"
	var calls int
	err := f.flow(goodACS, &calls).Run(context.Background(), f.authorizeURL())
	if err == nil || !strings.Contains(err.Error(), "refusing to deliver the code") {
		t.Fatalf("err = %v", err)
	}
	if f.gotCode != "" {
		t.Fatal("callback reached")
	}
}

func TestRefusesRedirectOffAWS(t *testing.T) {
	f := newFake(t)
	f.acsRedir = "https://evil.example.net/start/?state=ST&workflowResultHandle=WR"
	var calls int
	err := f.flow(goodACS, &calls).Run(context.Background(), f.authorizeURL())
	if err == nil || !strings.Contains(err.Error(), "refusing to follow the portal") {
		t.Fatalf("err = %v", err)
	}
	if n := f.hostHits("evil.example.net"); n != 0 {
		t.Fatalf("followed the portal off AWS (%d requests)", n)
	}
}

func TestRejectsForeignAuthorizeURL(t *testing.T) {
	f := newFake(t)
	var calls int
	for u, want := range map[string]string{
		"https://oidc.eu-west-1.amazonaws.com/authorize?client_id=a&state=b&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2F":     "not an authorize URL",
		"https://evil.example.net/authorize?client_id=a&state=b&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2F":                 "not an authorize URL",
		"https://oidc.us-east-1.amazonaws.com/authorize?client_id=a&state=b&redirect_uri=https%3A%2F%2Fevil.example.net%2F": "loopback redirect_uri",
	} {
		if err := f.flow(goodACS, &calls).Run(context.Background(), u); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", u, err, want)
		}
	}
	if calls != 0 || f.hostHits("oidc.us-east-1.amazonaws.com") != 0 {
		t.Fatalf("a foreign authorize URL was followed (idp %d, oidc %d)", calls, f.hostHits("oidc.us-east-1.amazonaws.com"))
	}
}

func TestDeliverOnlyToLoopback(t *testing.T) {
	r := &run{Flow: &Flow{}}
	for _, u := range []string{"http://evil.example.net/oauth/callback?code=c", "http://10.0.0.1:80/cb?code=c"} {
		if err := r.deliver(context.Background(), u); err == nil || !strings.Contains(err.Error(), "off the machine") {
			t.Errorf("%s: err = %v", u, err)
		}
	}
}

func TestRefusesCallbackWithAnotherState(t *testing.T) {
	f := newFake(t)
	r := &run{Flow: &Flow{}}
	back, _ := url.Parse(f.cb.URL + "/oauth/callback")
	code, _ := url.Parse(f.cb.URL + "/oauth/callback?code=CODE&state=other")
	if err := r.finish(context.Background(), code, back, state); err == nil {
		t.Fatal("delivered a code for another state")
	}
	if f.gotCode != "" {
		t.Fatal("callback reached")
	}
}

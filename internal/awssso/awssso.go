// Package awssso completes the browser half of `aws sso login` (IAM Identity
// Center, authorization code with PKCE) over plain HTTP.
//
// The AWS CLI prints an authorize URL and waits on a loopback port for the
// code. A browser would walk the AWS access portal (a script-driven page),
// be sent to the external IdP with a SAML request, come back, and press
// "Allow access". This package makes the same requests the portal's script
// makes — the sequence was measured on a real portal — hands the SAML request
// to an IdP adapter, approves the consent only for the client the CLI started,
// and delivers the code to the CLI's loopback port. The PKCE verifier never
// leaves the CLI: what travels here is only good together with it.
package awssso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/toolworksdev/headvpn/internal/htmlform"
	"github.com/toolworksdev/headvpn/internal/saml"
)

// ErrUnexpected means the portal answered something this package does not
// know (a new page, a changed API, an MFA step on the AWS side…).
var ErrUnexpected = errors.New("the AWS access portal answered something this tool does not know")

// IdP signs in at the IdP, starting from the SAML request the portal posts
// (action + form fields), and returns the SAML response form instead of
// posting it.
type IdP func(ctx context.Context, action string, form url.Values) (*saml.PostForm, error)

// Flow is one login.
type Flow struct {
	// StartURL and Region are sso_start_url and sso_region from the AWS config.
	StartURL string
	Region   string
	// Client carries the cookie jar for the AWS hosts; its CheckRedirect is
	// replaced. Nil builds one.
	Client *http.Client
	// Loopback delivers the code to the CLI; nil = a client without proxy.
	Loopback *http.Client
	IdP      IdP
	// Trace, when set, gets one line per request: method, host, path,
	// status. Never query strings, tokens or form values.
	Trace func(string)
}

const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"

type run struct {
	*Flow
	c       *http.Client
	start   *url.URL // access portal origin + path
	oidc    string   // https://oidc.<region>.amazonaws.com
	portal  string   // https://portal.sso.<region>.amazonaws.com
	allowed map[string]bool
}

// Run walks the login for the authorize URL the CLI printed, and returns once
// the CLI's loopback accepted the code.
func (f *Flow) Run(ctx context.Context, authorizeURL string) error {
	if f.IdP == nil {
		return errors.New("awssso: no IdP adapter")
	}
	if f.Region == "" || strings.ContainsAny(f.Region, "/.:@ ") {
		return fmt.Errorf("awssso: bad region %q", f.Region)
	}
	start, err := url.Parse(strings.TrimSuffix(strings.SplitN(f.StartURL, "#", 2)[0], "/") + "/")
	if err != nil || start.Scheme != "https" || start.Host == "" {
		return fmt.Errorf("awssso: sso_start_url %q must be an https URL", f.StartURL)
	}
	r := &run{Flow: f, start: start,
		oidc:   "https://oidc." + f.Region + ".amazonaws.com",
		portal: "https://portal.sso." + f.Region + ".amazonaws.com",
	}
	r.allowed = map[string]bool{
		"oidc." + f.Region + ".amazonaws.com":       true,
		"portal.sso." + f.Region + ".amazonaws.com": true,
		f.Region + ".signin.aws":                    true,
		f.Region + ".signin.aws.amazon.com":         true,
		strings.ToLower(start.Host):                 true,
	}
	c := f.Client
	if c == nil {
		c = newClient()
	}
	cc := *c
	// Every redirect is followed by hand, so each hop is checked first.
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r.c = &cc
	return r.run(ctx, authorizeURL)
}

func (r *run) run(ctx context.Context, authorizeURL string) error {
	// 0. The URL the CLI printed: it must be this region's OIDC authorize
	// endpoint and come back to a loopback port.
	az, err := url.Parse(authorizeURL)
	if err != nil || "https://"+az.Host != r.oidc || az.Path != "/authorize" {
		return fmt.Errorf("awssso: not an authorize URL of %s: %q", r.oidc, redact(authorizeURL))
	}
	q := az.Query()
	clientID, state := q.Get("client_id"), q.Get("state")
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || back.Scheme != "http" || !loopback(back.Hostname()) || clientID == "" || state == "" {
		return fmt.Errorf("%w: the authorize URL must carry client_id, state and a loopback redirect_uri", ErrUnexpected)
	}

	// 1. authorize → the access portal with callback_url + orchestrator_id.
	_, at, err := r.walk(ctx, http.MethodGet, authorizeURL, nil, r.isStart)
	if err != nil {
		return err
	}
	if at == nil {
		return fmt.Errorf("%w: authorize did not send us to the access portal", ErrUnexpected)
	}
	orchestrator := at.Query().Get("orchestrator_id")
	if orchestrator == "" {
		return fmt.Errorf("%w: no orchestrator_id on the way to the portal", ErrUnexpected)
	}

	// 2. The portal's script asks where to sign in.
	directory := strings.SplitN(r.start.Host, ".", 2)[0]
	var login struct {
		RedirectURL string `json:"redirectUrl"`
		CSRFToken   string `json:"csrfToken"`
	}
	loginURL := r.portal + "/login?" + url.Values{
		"directory_id": {directory},
		"redirect_url": {r.start.String() + "#/?" + at.RawQuery},
	}.Encode()
	if err := r.json(ctx, http.MethodGet, loginURL, nil, nil, &login); err != nil {
		return err
	}
	if login.RedirectURL == "" {
		return fmt.Errorf("%w: portal login gave no redirectUrl", ErrUnexpected)
	}

	// 3. The sign-in service answers with an auto-posting SAML request to
	// the external IdP.
	page, _, err := r.walk(ctx, http.MethodGet, login.RedirectURL, nil, nil)
	if err != nil {
		return err
	}
	req, ok := formWith(page.html, "SAMLRequest")
	if !ok {
		return fmt.Errorf("%w: the sign-in page holds no SAML request (HTTP %d %s) — is the directory federated with an external IdP?", ErrUnexpected, page.status, page.url.Host+page.url.Path)
	}
	idpAction, err := page.url.Parse(req.Action)
	if err != nil || idpAction.Scheme != "https" {
		return fmt.Errorf("%w: SAML request action is not https", ErrUnexpected)
	}

	// 4. The IdP signs in and returns the SAML response, which must go back
	// to this region's sign-in service and nowhere else.
	resp, err := r.IdP(ctx, idpAction.String(), req.Values())
	if err != nil {
		return err
	}
	acs, err := url.Parse(resp.Action)
	if err != nil || acs.Scheme != "https" || !r.isSignin(acs) {
		return fmt.Errorf("refusing to send the SAML assertion to %q: not the AWS sign-in service of %s", redact(resp.Action), r.Region)
	}
	vals := url.Values{"SAMLResponse": {resp.SAMLResponse}}
	if resp.RelayState != "" {
		vals.Set("RelayState", resp.RelayState)
	}
	page, at, err = r.walk(ctx, http.MethodPost, acs.String(), vals, r.isStart)
	if err != nil {
		return err
	}
	if at == nil {
		return fmt.Errorf("%w: the sign-in service did not return to the portal after the IdP (HTTP %d %s)", ErrUnexpected, page.status, page.url.Host+page.url.Path)
	}
	aq := at.Query()
	if aq.Get("workflowResultHandle") == "" || aq.Get("state") == "" {
		return fmt.Errorf("%w: back at the portal without workflowResultHandle/state", ErrUnexpected)
	}

	// 5. The portal turns the sign-in result into its bearer token.
	var tok struct {
		Token        string `json:"token"`
		ErrorMessage string `json:"errorMessage"`
		ErrorReason  string `json:"errorReason"`
	}
	csrf := login.CSRFToken
	if csrf == "" {
		csrf = aq.Get("wdc_csrf_token")
	}
	if err := r.form(ctx, r.portal+"/auth/sso-token", url.Values{
		"authCode": {aq.Get("workflowResultHandle")}, "state": {aq.Get("state")}, "orgId": {directory},
	}, http.Header{"x-amz-sso-csrf-token": {csrf}}, &tok); err != nil {
		return err
	}
	if tok.Token == "" {
		return fmt.Errorf("%w: no portal token (%s %s)", ErrUnexpected, tok.ErrorReason, firstLine(tok.ErrorMessage))
	}
	bearer := http.Header{"x-amz-sso_bearer_token": {tok.Token}, "x-amz-sso-bearer-token": {tok.Token}}

	// 6. Tell OIDC who signed in; it answers with where to resume.
	var result map[string]any
	if err := r.json(ctx, http.MethodPost, r.oidc+"/authentication_result", map[string]string{"orchestrator_id": orchestrator}, bearer, &result); err != nil {
		return err
	}
	resume := findURL(result, func(u *url.URL) bool { return "https://"+u.Host == r.oidc && u.Path == "/authorize" })
	if resume == "" {
		return fmt.Errorf("%w: authentication_result has no authorize URL (keys %v)", ErrUnexpected, keys(result))
	}

	// 7. Resuming the authorization lands on the consent screen — or, when
	// this client already holds consent (measured: a client the CLI reuses
	// from its cache), straight on the CLI's loopback with the code.
	isBack := func(u *url.URL) bool { return u.Scheme == "http" && loopback(u.Hostname()) }
	_, at, err = r.walk(ctx, http.MethodGet, resume, nil, func(u *url.URL) bool { return r.isStart(u) || isBack(u) })
	if err != nil {
		return err
	}
	if at == nil {
		return fmt.Errorf("%w: resuming the authorization reached neither the consent screen nor the CLI", ErrUnexpected)
	}
	if isBack(at) {
		r.trace("consent already given to this client")
		return r.finish(ctx, at, back, state)
	}
	cq := at.Query()
	arc := cq.Get("authorizationResumptionContext")
	// Consent is given only to the client the CLI registered for this login.
	if cq.Get("clientId") != clientID {
		return fmt.Errorf("refusing to approve access for a client other than the CLI's (%q)", cq.Get("clientId"))
	}
	if arc == "" {
		return fmt.Errorf("%w: consent screen without authorizationResumptionContext", ErrUnexpected)
	}

	// 8. A device session token for the consent calls.
	var dev struct {
		Token string `json:"token"`
	}
	if err := r.json(ctx, http.MethodPost, r.portal+"/session/device", map[string]any{}, http.Header{"Authorization": {"Bearer " + tok.Token}}, &dev); err != nil {
		return err
	}
	if dev.Token == "" {
		return fmt.Errorf("%w: no device session token", ErrUnexpected)
	}
	var details struct {
		ClientName    string `json:"clientName"`
		ConsentStatus string `json:"consentStatus"`
	}
	if err := r.json(ctx, http.MethodPost, r.oidc+"/consent_details", map[string]string{
		"authorizationResumptionContext": arc, "clientId": clientID, "clientType": cq.Get("clientType"), "userSessionId": dev.Token,
	}, nil, &details); err != nil {
		return err
	}
	r.trace("consent for " + details.ClientName + " (" + details.ConsentStatus + ")")

	// 9. "Allow access".
	if err := r.json(ctx, http.MethodPost, r.oidc+"/device_authorization/associate_token", map[string]string{
		"authorizationResumptionContext": arc, "userSessionId": dev.Token,
	}, nil, nil); err != nil {
		return err
	}

	// 10. Resuming again redirects to the CLI's loopback with the code.
	_, code, err := r.walk(ctx, http.MethodGet, r.oidc+"/authorize?"+url.Values{"authorization_resumption_context": {arc}}.Encode(), nil, isBack)
	if err != nil {
		return err
	}
	if code == nil {
		return fmt.Errorf("%w: the authorization did not return to the CLI", ErrUnexpected)
	}
	return r.finish(ctx, code, back, state)
}

// finish checks that the code goes to the port and path the CLI listens on,
// for the state it sent, and delivers it.
func (r *run) finish(ctx context.Context, code, back *url.URL, state string) error {
	if code.Host != back.Host || code.Path != back.Path {
		return fmt.Errorf("refusing to deliver the code to %s%s: the CLI listens on %s%s", code.Host, code.Path, back.Host, back.Path)
	}
	if code.Query().Get("state") != state || code.Query().Get("code") == "" {
		return fmt.Errorf("%w: callback without code or with another state", ErrUnexpected)
	}
	return r.deliver(ctx, code.String())
}

func (r *run) isStart(u *url.URL) bool {
	return u.Scheme == "https" && strings.EqualFold(u.Host, r.start.Host) && strings.HasPrefix(u.Path, strings.TrimSuffix(r.start.Path, "/"))
}

func (r *run) isSignin(u *url.URL) bool {
	h := strings.ToLower(u.Host)
	return h == r.Region+".signin.aws" || h == r.Region+".signin.aws.amazon.com"
}

type page struct {
	url    *url.URL
	status int
	body   []byte
	html   *htmlform.Page
}

// walk sends one request and follows redirects inside the allowed AWS hosts.
// It stops BEFORE requesting a location that stop() accepts, and returns it.
// An HTML page that only auto-posts to an allowed AWS host is followed too.
func (r *run) walk(ctx context.Context, method, target string, form url.Values, stop func(*url.URL) bool) (*page, *url.URL, error) {
	for hop := 0; hop < 12; hop++ {
		u, err := url.Parse(target)
		if err != nil {
			return nil, nil, err
		}
		if !r.allowed[strings.ToLower(u.Host)] || u.Scheme != "https" {
			return nil, nil, fmt.Errorf("refusing to follow the portal to %s://%s (not an AWS host of this login)", u.Scheme, u.Host)
		}
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			return nil, nil, err
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		p, resp, err := r.do(req)
		if err != nil {
			return nil, nil, err
		}
		if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			next, err := u.Parse(loc)
			if err != nil {
				return nil, nil, err
			}
			if stop != nil && stop(next) {
				return p, next, nil
			}
			if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
				method, form = http.MethodGet, nil
			}
			target = next.String()
			continue
		}
		if f, ok := autoPost(p.html); ok {
			next, err := u.Parse(f.Action)
			if err == nil && r.allowed[strings.ToLower(next.Host)] && !f.Has("SAMLRequest") {
				if stop != nil && stop(next) {
					return p, next, nil
				}
				method, form, target = http.MethodPost, f.Values(), next.String()
				continue
			}
		}
		if p.status >= 400 {
			return nil, nil, fmt.Errorf("%s %s%s: HTTP %d", method, u.Host, u.Path, p.status)
		}
		return p, nil, nil
	}
	return nil, nil, errors.New("awssso: too many redirects")
}

func (r *run) do(req *http.Request) (*page, *http.Response, error) {
	req.Header.Set("User-Agent", userAgent)
	resp, err := r.c.Do(req)
	if err != nil {
		return nil, nil, redactErr(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, err
	}
	r.trace(fmt.Sprintf("%s %s%s → %d", req.Method, req.URL.Host, req.URL.Path, resp.StatusCode))
	p := &page{url: req.URL, status: resp.StatusCode, body: b}
	if strings.Contains(resp.Header.Get("Content-Type"), "html") {
		if p.html, err = htmlform.Parse(bytes.NewReader(b)); err != nil {
			return nil, nil, err
		}
	}
	return p, resp, nil
}

// json sends a JSON (or empty) request to an AWS API and decodes the answer.
func (r *run) json(ctx context.Context, method, target string, body any, hdr http.Header, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return r.api(req, hdr, out)
}

func (r *run) form(ctx context.Context, target string, v url.Values, hdr http.Header, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r.api(req, hdr, out)
}

func (r *run) api(req *http.Request, hdr http.Header, out any) error {
	if !r.allowed[strings.ToLower(req.URL.Host)] || req.URL.Scheme != "https" {
		return fmt.Errorf("refusing to call %s: not an AWS host of this login", req.URL.Host)
	}
	for k, v := range hdr {
		req.Header[k] = v // keep the exact header names the portal uses
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://"+r.start.Host)
	req.Header.Set("Referer", r.start.String())
	p, _, err := r.do(req)
	if err != nil {
		return err
	}
	if p.status != http.StatusOK {
		return fmt.Errorf("%s %s%s: HTTP %d", req.Method, req.URL.Host, req.URL.Path, p.status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(p.body, out); err != nil {
		return fmt.Errorf("%w: %s%s did not answer JSON", ErrUnexpected, req.URL.Host, req.URL.Path)
	}
	return nil
}

// deliver hands the code to the CLI. Only loopback: the code is half of a
// credential (the other half, the PKCE verifier, is in the CLI).
func (r *run) deliver(ctx context.Context, target string) error {
	u, _ := url.Parse(target)
	if u == nil || !loopback(u.Hostname()) {
		return errors.New("refusing to deliver the code off the machine")
	}
	c := r.Loopback
	if c == nil {
		c = &http.Client{Transport: &http.Transport{Proxy: nil}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("deliver the code to the CLI on %s: %w", u.Host, redactErr(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	r.trace(fmt.Sprintf("GET %s%s → %d", u.Host, u.Path, resp.StatusCode))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("the CLI answered HTTP %d to the code", resp.StatusCode)
	}
	return nil
}

func (r *run) trace(s string) {
	if r.Trace != nil {
		r.Trace("aws-sso: " + s)
	}
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

func formWith(h *htmlform.Page, field string) (htmlform.Form, bool) {
	if h == nil {
		return htmlform.Form{}, false
	}
	for _, f := range h.Forms {
		if f.Has(field) {
			return f, true
		}
	}
	return htmlform.Form{}, false
}

// autoPost is a page whose only job is to post a hidden form onwards.
func autoPost(h *htmlform.Page) (htmlform.Form, bool) {
	if h == nil || len(h.Forms) != 1 {
		return htmlform.Form{}, false
	}
	f := h.Forms[0]
	if f.Action == "" || !strings.EqualFold(f.Method, "post") {
		return htmlform.Form{}, false
	}
	for _, in := range f.Inputs {
		if in.Type != "hidden" && in.Type != "submit" {
			return htmlform.Form{}, false
		}
	}
	return f, true
}

func findURL(v any, ok func(*url.URL) bool) string {
	switch t := v.(type) {
	case string:
		if u, err := url.Parse(t); err == nil && ok(u) {
			return t
		}
	case map[string]any:
		for _, x := range t {
			if s := findURL(x, ok); s != "" {
				return s
			}
		}
	case []any:
		for _, x := range t {
			if s := findURL(x, ok); s != "" {
				return s
			}
		}
	}
	return ""
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redact(ue.URL)
	}
	return err
}

func redact(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i] + "?…"
	}
	return s
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

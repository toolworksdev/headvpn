// Package entra answers a Microsoft Entra ID sign-in page with a username,
// password and a TOTP code, without a browser.
//
// The Entra sign-in page is a script-driven app, not an HTML form: its state
// (flow token, context, canary, the URLs to post to) travels in a `$Config`
// JSON object embedded in each page. This package reads that object and posts
// what the page's own script would post. Only the "verification code"
// second factor (PhoneAppOTP) is answered: push approvals, number matching,
// passkeys and SMS need a person and are reported as unsupported.
package entra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/toolworksdev/headvpn/internal/htmlform"
)

// DefaultOrigin is the public-cloud sign-in host.
const DefaultOrigin = "https://login.microsoftonline.com"

// ErrRejected means Entra refused the credentials or the code. Never retried
// automatically: repeated failures lock the account (smart lockout).
var ErrRejected = errors.New("entra rejected the login")

// ErrUnexpectedPage means Entra showed a step this package does not answer
// (consent, password change, an MFA method other than a code…).
var ErrUnexpectedPage = errors.New("entra returned a page this tool does not know how to answer")

// Login is one sign-in.
type Login struct {
	// Origin is the sign-in host credentials may be sent to.
	Origin   string
	Username string
	Password string
	// OTP returns the 6-digit code of the account's authenticator app.
	OTP func() (string, error)
	// Client must have a cookie jar. Its CheckRedirect is replaced.
	Client   *http.Client
	MaxSteps int
	// Relays are extra origins the browser may pass through on the way back
	// to the VPN server (e.g. Pritunl's https://auth.pritunl.com). They never
	// receive credentials, only the redirect Entra itself issues.
	Relays []string
	// Trace, when set, gets one line per page (host, path, page id, error
	// code, offered methods) — never tokens, codes or credentials.
	Trace func(string)
}

// config is the subset of the page's $Config this package reads.
type config struct {
	PageID         string  `json:"pgid"`
	FlowToken      string  `json:"sFT"`
	Ctx            string  `json:"sCtx"`
	Canary         string  `json:"canary"`
	APICanary      string  `json:"apiCanary"`
	SessionID      string  `json:"sessionId"`
	CorrelationID  string  `json:"correlationId"`
	HPGID          float64 `json:"hpgid"`
	HPGAct         float64 `json:"hpgact"`
	URLPost        string  `json:"urlPost"`
	URLBeginAuth   string  `json:"urlBeginAuth"`
	URLEndAuth     string  `json:"urlEndAuth"`
	URLResume      string  `json:"urlResume"`
	ErrorCode      string  `json:"sErrorCode"`
	ErrorText      string  `json:"sErrTxt"`
	UserProofs     []proof `json:"arrUserProofs"`
	KMSI           bool    `json:"fShowPersistentCookiesWarning"`
	PasswordPrompt bool    `json:"fShowPassword"`
}

type proof struct {
	AuthMethodID string `json:"authMethodId"`
	Display      string `json:"display"`
	IsDefault    bool   `json:"isDefault"`
}

var configRE = regexp.MustCompile(`(?s)\$Config=(\{.*?\});`)

// credential errors: wrong password, locked, unknown user, bad code.
var rejectCodes = map[string]string{
	"50126": "invalid username or password",
	"50053": "account locked (too many attempts)",
	"50034": "user does not exist",
	"50055": "password expired",
	"50057": "account disabled",
}

// informational codes Entra sets on pages that still expect an answer.
var informational = map[string]bool{"50058": true}

type page struct {
	url    *url.URL
	status int
	cfg    *config
	html   *htmlform.Page
	keys   []string // $Config field names, for tracing unknown pages
	forms  []string // form actions and input names, for tracing
}

// Run signs in starting at startURL (the URL the VPN client handed out). It
// returns once Entra redirects back to the VPN server's origin.
func (l *Login) Run(ctx context.Context, startURL string) error {
	idp, err := origin(l.Origin, DefaultOrigin)
	if err != nil {
		return err
	}
	start, err := url.Parse(startURL)
	if err != nil || start.Scheme != "https" || start.Host == "" {
		return fmt.Errorf("login URL must be https: %q", redact(startURL))
	}
	vpn := &url.URL{Scheme: start.Scheme, Host: start.Host}
	allowed := []*url.URL{idp, vpn}
	for _, r := range l.Relays {
		o, err := origin(r, r)
		if err != nil {
			return err
		}
		allowed = append(allowed, o)
	}
	c := *l.Client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 10 {
			return errors.New("too many redirects")
		}
		for _, o := range allowed {
			if same(req.URL, o) {
				return nil
			}
		}
		return fmt.Errorf("refusing redirect to %s://%s (not the IdP, the VPN server or a configured relay)", req.URL.Scheme, req.URL.Host)
	}
	steps := l.MaxSteps
	if steps == 0 {
		steps = 12
	}
	usedCode := false

	p, err := get(ctx, &c, startURL)
	if err != nil {
		return err
	}
	for i := 0; i < steps; i++ {
		l.trace(p)
		if same(p.url, vpn) {
			if p.status >= 200 && p.status < 400 {
				return nil
			}
			return fmt.Errorf("the VPN server answered HTTP %d after the sign-in", p.status)
		}
		if !same(p.url, idp) {
			return fmt.Errorf("%w: landed on %s", ErrUnexpectedPage, p.url.Host)
		}
		if p.cfg == nil {
			// Plain HTML step: the auto-posting form that hands the result
			// back to the VPN server.
			f, ok := autoPost(p.html)
			if !ok {
				return fmt.Errorf("%w: no $Config and no form (HTTP %d)", ErrUnexpectedPage, p.status)
			}
			action, err := p.url.Parse(f.Action)
			if err != nil || (!same(action, vpn) && !same(action, idp)) {
				return fmt.Errorf("%w: form posts to an untrusted origin", ErrUnexpectedPage)
			}
			if p, err = post(ctx, &c, action.String(), f.Values()); err != nil {
				return err
			}
			continue
		}
		cfg := p.cfg
		if informational[cfg.ErrorCode] {
			// Measured on a real tenant: the first sign-in page carries
			// AADSTS50058 ("no signed-in session for a silent sign-in") as
			// state, not as a failure.
			cfg.ErrorCode = ""
		}
		if cfg.ErrorCode != "" {
			if why, ok := rejectCodes[cfg.ErrorCode]; ok {
				return fmt.Errorf("%w: AADSTS%s %s", ErrRejected, cfg.ErrorCode, why)
			}
			return fmt.Errorf("%w: AADSTS%s %s", ErrUnexpectedPage, cfg.ErrorCode, firstLine(cfg.ErrorText))
		}
		switch {
		case len(cfg.UserProofs) > 0:
			if usedCode {
				return fmt.Errorf("%w: asked for a second factor again", ErrUnexpectedPage)
			}
			usedCode = true
			if p, err = l.secondFactor(ctx, &c, idp, cfg); err != nil {
				return err
			}
		case cfg.PageID == "DetectBrowserCapabilities" && cfg.URLResume != "":
			// Measured: after the password, Entra may stop to let the page's
			// script probe the browser, then the script loads urlResume.
			if err := trusted(idp, cfg.URLResume); err != nil {
				return err
			}
			if p, err = get(ctx, &c, cfg.URLResume); err != nil {
				return err
			}
		case cfg.PageID == "KmsiInterrupt":
			// "Stay signed in?" — no: nothing here keeps the cookies.
			if p, err = l.form(ctx, &c, idp, cfg.URLPost, url.Values{
				"LoginOptions": {"3"}, "type": {"28"}, "ctx": {cfg.Ctx},
				"hpgrequestid": {cfg.SessionID}, "flowToken": {cfg.FlowToken},
				"canary": {cfg.Canary}, "i19": {"1000"},
			}); err != nil {
				return err
			}
		case cfg.URLPost != "" && cfg.FlowToken != "" && (cfg.PageID == "" || cfg.PageID == "ConvergedSignIn" || cfg.PasswordPrompt):
			if p, err = l.form(ctx, &c, idp, cfg.URLPost, url.Values{
				"login": {l.Username}, "loginfmt": {l.Username}, "passwd": {l.Password},
				"type": {"11"}, "LoginOptions": {"3"}, "ps": {"2"}, "i13": {"0"},
				"canary": {cfg.Canary}, "ctx": {cfg.Ctx}, "hpgrequestid": {cfg.SessionID},
				"flowToken": {cfg.FlowToken}, "NewUser": {"1"}, "fspost": {"0"}, "i21": {"0"},
				"CookieDisabled": {""}, "IsFidoSupported": {"0"}, "isSignupPost": {"0"},
				"i19": {"1000"},
			}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: page %q", ErrUnexpectedPage, cfg.PageID)
		}
	}
	return fmt.Errorf("%w: no result after %d steps", ErrUnexpectedPage, steps)
}

func (l *Login) trace(p *page) {
	if l.Trace == nil {
		return
	}
	line := fmt.Sprintf("entra: HTTP %d %s%s", p.status, p.url.Host, p.url.Path)
	if p.cfg != nil {
		var ids []string
		for _, pr := range p.cfg.UserProofs {
			ids = append(ids, pr.AuthMethodID)
		}
		line += fmt.Sprintf(" pgid=%q err=%q proofs=%v", p.cfg.PageID, p.cfg.ErrorCode, ids)
		if os.Getenv("HEADVPN_DEBUG") == "2" {
			line += fmt.Sprintf(" keys=%v", p.keys)
		}
	}
	if len(p.forms) > 0 {
		line += fmt.Sprintf(" forms=%v", p.forms)
	}
	l.Trace(line)
}

// secondFactor answers the MFA step with a verification code.
func (l *Login) secondFactor(ctx context.Context, c *http.Client, idp *url.URL, cfg *config) (*page, error) {
	method := ""
	var offered []string
	for _, pr := range cfg.UserProofs {
		offered = append(offered, pr.AuthMethodID)
		if pr.AuthMethodID == "PhoneAppOTP" {
			method = pr.AuthMethodID
		}
	}
	if method == "" {
		return nil, fmt.Errorf("%w: no verification-code method among %v (register an authenticator app)", ErrUnexpectedPage, offered)
	}
	if l.OTP == nil {
		return nil, errors.New("entra asks for a verification code and no totp_secret/otp is configured")
	}
	for _, u := range []string{cfg.URLBeginAuth, cfg.URLEndAuth, cfg.URLPost} {
		if err := trusted(idp, u); err != nil {
			return nil, err
		}
	}
	hdr := http.Header{
		"Content-Type":      {"application/json"},
		"canary":            {cfg.APICanary},
		"hpgrequestid":      {cfg.SessionID},
		"client-request-id": {cfg.CorrelationID},
		"hpgid":             {strconv.Itoa(int(cfg.HPGID))},
		"hpgact":            {strconv.Itoa(int(cfg.HPGAct))},
	}
	var begin authResp
	if err := postJSON(ctx, c, cfg.URLBeginAuth, hdr, map[string]any{
		"AuthMethodId": method, "Method": "BeginAuth", "ctx": cfg.Ctx, "flowToken": cfg.FlowToken,
	}, &begin); err != nil {
		return nil, err
	}
	if !begin.Success {
		return nil, fmt.Errorf("%w: BeginAuth %s", ErrUnexpectedPage, begin.ResultValue)
	}
	code, err := l.OTP()
	if err != nil {
		return nil, err
	}
	started := time.Now()
	var end authResp
	if err := postJSON(ctx, c, cfg.URLEndAuth, hdr, map[string]any{
		"AuthMethodId": method, "Method": "EndAuth", "SessionId": begin.SessionID,
		"FlowToken": begin.FlowToken, "Ctx": begin.Ctx, "AdditionalAuthData": code, "PollCount": 1,
	}, &end); err != nil {
		return nil, err
	}
	if !end.Success {
		return nil, fmt.Errorf("%w: verification code not accepted (%s)", ErrRejected, end.ResultValue)
	}
	return l.form(ctx, c, idp, cfg.URLPost, url.Values{
		"type": {"19"}, "GeneralVerify": {"false"}, "request": {end.Ctx},
		"mfaAuthMethod": {method}, "otc": {code}, "login": {l.Username},
		"flowToken": {end.FlowToken}, "hpgrequestid": {cfg.SessionID}, "sacxt": {""},
		"hideSmsInMfaProofs": {"false"}, "canary": {cfg.Canary}, "i19": {"1000"},
		"mfaLastPollStart": {strconv.FormatInt(started.UnixMilli(), 10)},
		"mfaLastPollEnd":   {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	})
}

type authResp struct {
	Success     bool   `json:"Success"`
	ResultValue string `json:"ResultValue"`
	SessionID   string `json:"SessionId"`
	FlowToken   string `json:"FlowToken"`
	Ctx         string `json:"Ctx"`
}

func (l *Login) form(ctx context.Context, c *http.Client, idp *url.URL, target string, v url.Values) (*page, error) {
	if err := trusted(idp, target); err != nil {
		return nil, err
	}
	return post(ctx, c, target, v)
}

func trusted(idp *url.URL, target string) error {
	u, err := url.Parse(target)
	if err != nil || !same(u, idp) {
		return fmt.Errorf("refusing to send credentials to %q: not %s", redact(target), idp)
	}
	return nil
}

func get(ctx context.Context, c *http.Client, target string) (*page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return do(c, req)
}

func post(ctx context.Context, c *http.Client, target string, v url.Values) (*page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(c, req)
}

func postJSON(ctx context.Context, c *http.Client, target string, hdr http.Header, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header = hdr.Clone()
	resp, err := c.Do(req)
	if err != nil {
		return redactErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", redact(target), resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func do(c *http.Client, req *http.Request) (*page, error) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15")
	resp, err := c.Do(req)
	if err != nil {
		return nil, redactErr(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	p := &page{url: resp.Request.URL, status: resp.StatusCode}
	if m := configRE.FindSubmatch(body); m != nil {
		var cfg config
		if err := json.Unmarshal(m[1], &cfg); err == nil {
			// Measured: some steps give relative URLs ("/kmsi").
			for _, u := range []*string{&cfg.URLPost, &cfg.URLBeginAuth, &cfg.URLEndAuth, &cfg.URLResume} {
				if *u != "" {
					if abs, err := p.url.Parse(*u); err == nil {
						*u = abs.String()
					}
				}
			}
			p.cfg = &cfg
			var raw map[string]json.RawMessage
			if json.Unmarshal(m[1], &raw) == nil {
				for k := range raw {
					p.keys = append(p.keys, k)
				}
				sort.Strings(p.keys)
			}
		}
	}
	if p.html, err = htmlform.Parse(bytes.NewReader(body)); err != nil {
		return nil, err
	}
	for _, f := range p.html.Forms {
		var names []string
		for _, in := range f.Inputs {
			names = append(names, in.Name)
		}
		u, _ := url.Parse(f.Action)
		act := ""
		if u != nil {
			act = u.Host + u.Path
		}
		p.forms = append(p.forms, fmt.Sprintf("%s%v", act, names))
	}
	return p, nil
}

// autoPost finds the hidden form Entra uses to hand the result back
// (response_mode=form_post): every input hidden, an action set.
func autoPost(h *htmlform.Page) (htmlform.Form, bool) {
	if h == nil {
		return htmlform.Form{}, false
	}
	for _, f := range h.Forms {
		if f.Action != "" && (f.Has("code") || f.Has("id_token") || f.Has("SAMLResponse") || f.Has("state")) {
			return f, true
		}
	}
	return htmlform.Form{}, false
}

func origin(s, def string) (*url.URL, error) {
	if s == "" {
		s = def
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return nil, fmt.Errorf("idp_origin %q must look like %s", s, def)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func same(u, o *url.URL) bool {
	return strings.EqualFold(u.Scheme, o.Scheme) && strings.EqualFold(u.Host, o.Host)
}

// redactErr drops the query from the URL inside a transport error: on the
// way back it holds the authorization code.
func redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redact(ue.URL)
	}
	return err
}

func redact(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
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

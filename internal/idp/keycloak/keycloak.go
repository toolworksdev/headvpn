// Package keycloak completes an SP-initiated SAML login against a Keycloak
// realm over plain HTTP: username/password form, then the OTP form, then the
// auto-submit form that carries the SAMLResponse back to the VPN client.
package keycloak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/toolworksdev/headvpn/internal/htmlform"
	"github.com/toolworksdev/headvpn/internal/saml"
)

// ErrRejected means Keycloak answered the credentials with an error message.
// The caller must not retry automatically: repeated failures lock accounts.
var ErrRejected = errors.New("keycloak rejected the login")

// ErrUnexpectedPage means the page is neither a login, OTP nor SAML post form
// (consent screen, required action, theme we do not know, ...).
var ErrUnexpectedPage = errors.New("keycloak returned a page this tool does not know how to answer")

// Login holds what the realm will ask for.
type Login struct {
	// Origin is the only scheme://host that may receive the credentials.
	Origin   string
	Username string
	Password string
	// OTP returns the current one-time code. Called at most once.
	OTP func() (string, error)
	// Client is optional; a cookie-jar client is built when nil.
	Client *http.Client
	// MaxSteps bounds the number of pages walked (default 6).
	MaxSteps int
}

// Run starts at samlURL and returns the SAML POST form for the VPN client.
func (l *Login) Run(ctx context.Context, samlURL string) (*saml.PostForm, error) {
	origin, err := parseOrigin(l.Origin)
	if err != nil {
		return nil, err
	}
	if err := sameOrigin(origin, samlURL); err != nil {
		return nil, fmt.Errorf("SAML login URL: %w", err)
	}
	client := l.Client
	if client == nil {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{Jar: jar}
	}
	// Never follow a redirect that leaves the IdP: the next request could carry
	// the password to someone else.
	guarded := *client
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return sameOrigin(origin, req.URL.String())
	}

	steps := l.MaxSteps
	if steps == 0 {
		steps = 6
	}
	sentPassword, sentOTP := false, false

	page, base, err := fetch(ctx, &guarded, http.MethodGet, samlURL, nil)
	if err != nil {
		return nil, err
	}
	for i := 0; i < steps; i++ {
		if f, ok := findSAML(page); ok {
			action, err := base.Parse(f.Action)
			if err != nil {
				return nil, fmt.Errorf("SAML form action: %w", err)
			}
			return &saml.PostForm{Action: action.String(), SAMLResponse: f.Value("SAMLResponse"), RelayState: f.Value("RelayState")}, nil
		}
		if f, ok := findLogin(page); ok {
			if sentPassword {
				return nil, rejected(page)
			}
			sentPassword = true
			vals := f.Values()
			vals.Set("username", l.Username)
			vals.Set("password", l.Password)
			page, base, err = submit(ctx, &guarded, origin, base, f, vals)
			if err != nil {
				return nil, err
			}
			continue
		}
		if f, field, ok := findOTP(page); ok {
			if sentOTP {
				return nil, rejected(page)
			}
			if l.OTP == nil {
				return nil, errors.New("keycloak asks for a one-time code and no OTP source is configured")
			}
			code, err := l.OTP()
			if err != nil {
				return nil, fmt.Errorf("one-time code: %w", err)
			}
			sentOTP = true
			vals := f.Values()
			vals.Set(field, code)
			page, base, err = submit(ctx, &guarded, origin, base, f, vals)
			if err != nil {
				return nil, err
			}
			continue
		}
		if len(page.Errors) > 0 {
			return nil, rejected(page)
		}
		return nil, fmt.Errorf("%w (title %q)", ErrUnexpectedPage, page.Title)
	}
	return nil, fmt.Errorf("gave up after %d pages", steps)
}

func rejected(p *htmlform.Page) error {
	if len(p.Errors) > 0 {
		return fmt.Errorf("%w: %s", ErrRejected, strings.Join(p.Errors, "; "))
	}
	return ErrRejected
}

func findSAML(p *htmlform.Page) (htmlform.Form, bool) {
	for _, f := range p.Forms {
		if f.Has("SAMLResponse") {
			return f, true
		}
	}
	return htmlform.Form{}, false
}

func findLogin(p *htmlform.Page) (htmlform.Form, bool) {
	for _, f := range p.Forms {
		if f.ID == "kc-form-login" || (f.Has("username") && f.Has("password")) {
			return f, true
		}
	}
	return htmlform.Form{}, false
}

func findOTP(p *htmlform.Page) (htmlform.Form, string, bool) {
	for _, f := range p.Forms {
		for _, name := range []string{"otp", "totp"} {
			if f.Has(name) {
				return f, name, true
			}
		}
	}
	return htmlform.Form{}, "", false
}

func submit(ctx context.Context, c *http.Client, origin *url.URL, base *url.URL, f htmlform.Form, vals url.Values) (*htmlform.Page, *url.URL, error) {
	action, err := base.Parse(f.Action)
	if err != nil {
		return nil, nil, fmt.Errorf("form action: %w", err)
	}
	if err := sameOrigin(origin, action.String()); err != nil {
		return nil, nil, fmt.Errorf("refusing to post credentials: %w", err)
	}
	return fetch(ctx, c, http.MethodPost, action.String(), vals)
}

func fetch(ctx context.Context, c *http.Client, method, target string, form url.Values) (*htmlform.Page, *url.URL, error) {
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
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return nil, nil, fmt.Errorf("%s %s: HTTP %d", method, redactQuery(target), resp.StatusCode)
	}
	page, err := htmlform.Parse(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, err
	}
	return page, resp.Request.URL, nil
}

func parseOrigin(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("idp_origin %q must look like https://idp.example.com", s)
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("idp_origin %q must use https", s)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func sameOrigin(origin *url.URL, target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if !strings.EqualFold(u.Scheme, origin.Scheme) || !strings.EqualFold(u.Host, origin.Host) {
		return fmt.Errorf("%s://%s is not the trusted IdP origin %s", u.Scheme, u.Host, origin)
	}
	return nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func redactQuery(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i] + "?…"
	}
	return s
}

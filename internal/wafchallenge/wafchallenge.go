// Package wafchallenge gets an HTTP client past an AWS WAF Challenge.
//
// A WebACL rule with the Challenge action answers a request without a valid
// aws-waf-token cookie with HTTP 202, the header "x-amzn-waf-action:
// challenge" and a JavaScript interstitial (an empty body for non-browsers).
// Only a browser can run that script. Transport detects the answer on any
// request, asks a Solver (a headless Chrome/Brave, see Browser) for the
// token, keeps it until it expires, puts it in the client's cookie jar and
// replays the original request once.
//
// The token is a credential: it is never printed nor put in an error.
package wafchallenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CookieName is the cookie AWS WAF reads the token from.
const CookieName = "aws-waf-token"

// ErrUnsolved means a WAF challenge was detected and could not be answered.
var ErrUnsolved = errors.New("WAF challenge sin resolver (AWS WAF challenge not solved)")

// IsChallenge reports whether resp is an AWS WAF Challenge interstitial.
func IsChallenge(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusAccepted &&
		strings.EqualFold(strings.TrimSpace(resp.Header.Get("x-amzn-waf-action")), "challenge")
}

// Token is an aws-waf-token for one host.
type Token struct {
	Value   string    `json:"value"`
	Expires time.Time `json:"expires"`
}

func (t Token) valid(now time.Time) bool {
	return t.Value != "" && now.Add(30*time.Second).Before(t.Expires)
}

// Solver obtains a fresh token by loading page (scheme://host/path, never a
// query string) the way a browser would.
type Solver interface {
	Solve(ctx context.Context, page *url.URL) (Token, error)
}

// Cache keeps tokens per host in memory and, when Dir is set, in Dir (one
// 0600 file per host) so the next run of the tool reuses them.
type Cache struct {
	Dir string
	Now func() time.Time

	mu  sync.Mutex
	mem map[string]Token
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cache) file(host string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(host))
	return filepath.Join(c.Dir, "waf-token-"+safe+".json")
}

// Get returns the cached, unexpired token for host.
func (c *Cache) Get(host string) (Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	host = strings.ToLower(host)
	if t, ok := c.mem[host]; ok && t.valid(c.now()) {
		return t, true
	}
	if c.Dir == "" {
		return Token{}, false
	}
	b, err := os.ReadFile(c.file(host))
	if err != nil {
		return Token{}, false
	}
	var t Token
	if json.Unmarshal(b, &t) != nil || !t.valid(c.now()) {
		return Token{}, false
	}
	if c.mem == nil {
		c.mem = map[string]Token{}
	}
	c.mem[host] = t
	return t, true
}

// Put stores t for host.
func (c *Cache) Put(host string, t Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	host = strings.ToLower(host)
	if c.mem == nil {
		c.mem = map[string]Token{}
	}
	c.mem[host] = t
	if c.Dir == "" {
		return
	}
	if os.MkdirAll(c.Dir, 0o700) != nil {
		return
	}
	b, _ := json.Marshal(t)
	tmp := c.file(host) + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.file(host))
	}
}

// Drop forgets the token for host (the WAF no longer accepts it).
func (c *Cache) Drop(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	host = strings.ToLower(host)
	delete(c.mem, host)
	if c.Dir != "" {
		_ = os.Remove(c.file(host))
	}
}

// Transport answers AWS WAF challenges for the requests it carries.
type Transport struct {
	Base   http.RoundTripper // nil = http.DefaultTransport
	Jar    http.CookieJar    // the client's jar: receives the token
	Solver Solver            // nil = challenges fail with ErrUnsolved
	Cache  *Cache            // nil = in-memory only

	mu sync.Mutex // one solve at a time
}

// Wrap returns a copy of c whose transport answers WAF challenges. A client
// without a jar gets one so the token travels on the following requests.
func Wrap(c *http.Client, s Solver, cache *Cache) *http.Client {
	out := *c
	if out.Jar == nil {
		out.Jar = newJar()
	}
	if cache == nil {
		cache = &Cache{}
	}
	out.Transport = &Transport{Base: c.Transport, Jar: out.Jar, Solver: s, Cache: cache}
	return &out
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) cache() *Cache {
	if t.Cache == nil {
		t.Cache = &Cache{}
	}
	return t.Cache
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	sent := ""
	if tok, ok := t.cache().Get(host); ok {
		req = withToken(req, tok.Value)
		sent = tok.Value
		t.remember(req.URL, tok)
	}
	resp, err := t.base().RoundTrip(req)
	if err != nil || !IsChallenge(resp) {
		return resp, err
	}
	drain(resp)
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return nil, fmt.Errorf("%w: %s %s%s: the request body cannot be replayed", ErrUnsolved, req.Method, host, req.URL.Path)
	}
	tok, err := t.solve(req.Context(), req.URL, sent)
	if err != nil {
		return nil, err
	}
	retry, err := replay(req, tok.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsolved, err)
	}
	resp, err = t.base().RoundTrip(retry)
	if err != nil {
		return nil, err
	}
	if IsChallenge(resp) {
		drain(resp)
		t.cache().Drop(host)
		return nil, fmt.Errorf("%w: %s still challenges with a fresh token", ErrUnsolved, host)
	}
	return resp, nil
}

// solve returns a token newer than the one that was just refused.
func (t *Transport) solve(ctx context.Context, u *url.URL, refused string) (Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	host := u.Host
	if tok, ok := t.cache().Get(host); ok && tok.Value != refused {
		return tok, nil // another request solved it meanwhile
	}
	t.cache().Drop(host)
	if t.Solver == nil {
		return Token{}, fmt.Errorf("%w: %s asks for a browser check and no browser is configured", ErrUnsolved, host)
	}
	page := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	tok, err := t.Solver.Solve(ctx, page)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %s: %v", ErrUnsolved, host, err)
	}
	if tok.Value == "" {
		return Token{}, fmt.Errorf("%w: %s: the browser got no %s", ErrUnsolved, host, CookieName)
	}
	if tok.Expires.IsZero() {
		tok.Expires = time.Now().Add(5 * time.Minute)
	}
	t.cache().Put(host, tok)
	t.remember(u, tok)
	return tok, nil
}

// remember puts the token in the client's jar for that host.
func (t *Transport) remember(u *url.URL, tok Token) {
	if t.Jar == nil {
		return
	}
	t.Jar.SetCookies(&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}, []*http.Cookie{{
		Name: CookieName, Value: tok.Value, Path: "/", Expires: tok.Expires,
		Secure: u.Scheme == "https", HttpOnly: false,
	}})
}

// withToken returns req carrying exactly one aws-waf-token cookie.
func withToken(req *http.Request, value string) *http.Request {
	r := req.Clone(req.Context())
	setCookie(r, value)
	return r
}

func replay(req *http.Request, value string) (*http.Request, error) {
	r := req.Clone(req.Context())
	if req.GetBody != nil {
		b, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		r.Body = b
	}
	setCookie(r, value)
	return r, nil
}

func setCookie(r *http.Request, value string) {
	var keep []string
	for _, c := range r.Cookies() {
		if c.Name != CookieName {
			keep = append(keep, c.Name+"="+c.Value)
		}
	}
	keep = append(keep, CookieName+"="+value)
	r.Header.Set("Cookie", strings.Join(keep, "; "))
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

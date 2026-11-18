package wafchallenge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeWAF challenges every request without aws-waf-token=<good>.
type fakeWAF struct {
	good       string
	challenged atomic.Int32
	served     atomic.Int32
	lastBody   atomic.Value
}

func (f *fakeWAF) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The WAF reads the whole request before answering, so the body of
		// a challenged POST is gone and must be replayed from GetBody.
		b, _ := io.ReadAll(r.Body)
		if c, err := r.Cookie(CookieName); err != nil || c.Value != f.good {
			f.challenged.Add(1)
			w.Header().Set("x-amzn-waf-action", "challenge")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		f.served.Add(1)
		f.lastBody.Store(string(b))
		fmt.Fprint(w, "<html><title>Sign in</title></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

type fakeSolver struct {
	value string
	err   error
	calls atomic.Int32
	pages []string
}

func (s *fakeSolver) Solve(ctx context.Context, page *url.URL) (Token, error) {
	s.calls.Add(1)
	s.pages = append(s.pages, page.String())
	if s.err != nil {
		return Token{}, s.err
	}
	return Token{Value: s.value, Expires: time.Now().Add(time.Hour)}, nil
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, error) {
	t.Helper()
	resp, err := c.Get(u)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

func TestIsChallenge(t *testing.T) {
	h := http.Header{}
	h.Set("X-Amzn-Waf-Action", "Challenge")
	if !IsChallenge(&http.Response{StatusCode: 202, Header: h}) {
		t.Fatal("202 + challenge not detected")
	}
	if IsChallenge(&http.Response{StatusCode: 200, Header: h}) || IsChallenge(&http.Response{StatusCode: 202, Header: http.Header{}}) {
		t.Fatal("false positive")
	}
	h.Set("X-Amzn-Waf-Action", "captcha")
	if IsChallenge(&http.Response{StatusCode: 202, Header: h}) {
		t.Fatal("captcha is not a challenge")
	}
}

func TestChallengeIsSolvedRetriedAndTheTokenLandsInTheJar(t *testing.T) {
	f := &fakeWAF{good: "tok-good"}
	srv := f.server(t)
	s := &fakeSolver{value: "tok-good"}
	c := Wrap(&http.Client{}, s, &Cache{})

	resp, err := get(t, c, srv.URL+"/realms/r/protocol/saml?SAMLRequest=abc")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || f.served.Load() != 1 || f.challenged.Load() != 1 {
		t.Fatalf("status=%d served=%d challenged=%d", resp.StatusCode, f.served.Load(), f.challenged.Load())
	}
	// The browser loads the page without the query (no SAMLRequest/OAuth state).
	if len(s.pages) != 1 || strings.Contains(s.pages[0], "?") || !strings.HasSuffix(s.pages[0], "/realms/r/protocol/saml") {
		t.Fatalf("solver pages %v", s.pages)
	}
	u, _ := url.Parse(srv.URL)
	found := false
	for _, ck := range c.Jar.Cookies(u) {
		found = found || (ck.Name == CookieName && ck.Value == "tok-good")
	}
	if !found {
		t.Fatal("token not stored in the client's cookie jar")
	}
	// Following requests pass without a new challenge nor a new solve.
	if _, err := get(t, c, srv.URL+"/realms/r/login-actions/authenticate"); err != nil {
		t.Fatal(err)
	}
	if s.calls.Load() != 1 || f.challenged.Load() != 1 || f.served.Load() != 2 {
		t.Fatalf("solves=%d challenged=%d served=%d", s.calls.Load(), f.challenged.Load(), f.served.Load())
	}
}

func TestPostBodyIsReplayed(t *testing.T) {
	f := &fakeWAF{good: "tok-good"}
	srv := f.server(t)
	// A base transport that consumes req.Body itself (and ignores GetBody),
	// so only an explicit replay from GetBody can resend the form.
	c := Wrap(&http.Client{Transport: bodyConsumer{}}, &fakeSolver{value: "tok-good"}, nil)
	resp, err := c.PostForm(srv.URL+"/login", url.Values{"otp": {"123456"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || f.lastBody.Load() != "otp=123456" || f.served.Load() != 1 {
		t.Fatalf("status=%d body=%v served=%d", resp.StatusCode, f.lastBody.Load(), f.served.Load())
	}
}

type bodyConsumer struct{}

func (bodyConsumer) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.GetBody = nil
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestTokenIsCachedOnDiskForTheNextRun(t *testing.T) {
	f := &fakeWAF{good: "tok-good"}
	srv := f.server(t)
	dir := t.TempDir()
	first := Wrap(&http.Client{}, &fakeSolver{value: "tok-good"}, &Cache{Dir: dir})
	if _, err := get(t, first, srv.URL+"/a"); err != nil {
		t.Fatal(err)
	}
	// A new process: fresh jar, a browser that would fail.
	dead := &fakeSolver{err: errors.New("no browser")}
	second := Wrap(&http.Client{}, dead, &Cache{Dir: dir})
	resp, err := get(t, second, srv.URL+"/b")
	if err != nil || resp.StatusCode != 200 || dead.calls.Load() != 0 {
		t.Fatalf("resp=%v err=%v solves=%d", resp, err, dead.calls.Load())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "waf-token-*.json"))
	if len(files) != 1 {
		t.Fatalf("cache files %v", files)
	}
	// Windows has no Unix permission bits; elsewhere the token file is private.
	if st, _ := os.Stat(files[0]); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode %v", st.Mode().Perm())
	}
}

func TestExpiredTokenIsNotUsed(t *testing.T) {
	now := time.Now()
	c := &Cache{Dir: t.TempDir(), Now: func() time.Time { return now }}
	c.Put("h", Token{Value: "v", Expires: now.Add(10 * time.Second)})
	if _, ok := c.Get("h"); ok {
		t.Fatal("token about to expire was returned")
	}
}

func TestRefusedCachedTokenIsReplaced(t *testing.T) {
	f := &fakeWAF{good: "tok-new"}
	srv := f.server(t)
	u, _ := url.Parse(srv.URL)
	cache := &Cache{}
	cache.Put(u.Host, Token{Value: "tok-old", Expires: time.Now().Add(time.Hour)})
	s := &fakeSolver{value: "tok-new"}
	resp, err := get(t, Wrap(&http.Client{}, s, cache), srv.URL+"/x")
	if err != nil || resp.StatusCode != 200 || s.calls.Load() != 1 {
		t.Fatalf("resp=%v err=%v solves=%d", resp, err, s.calls.Load())
	}
	if tok, _ := cache.Get(u.Host); tok.Value != "tok-new" {
		t.Fatal("cache kept the refused token")
	}
}

func TestUnsolvedChallengeIsADistinctErrorWithoutTheToken(t *testing.T) {
	f := &fakeWAF{good: "tok-good"}
	srv := f.server(t)
	for name, s := range map[string]Solver{
		"no browser":    nil,
		"browser fails": &fakeSolver{err: errors.New("chrome crashed")},
		"wrong token":   &fakeSolver{value: "tok-wrong-secret"},
	} {
		_, err := get(t, Wrap(&http.Client{}, s, nil), srv.URL+"/x")
		if !errors.Is(err, ErrUnsolved) {
			t.Fatalf("%s: want ErrUnsolved, got %v", name, err)
		}
		if strings.Contains(err.Error(), "tok-") {
			t.Fatalf("%s: error leaks the token: %v", name, err)
		}
	}
	if f.served.Load() != 0 {
		t.Fatalf("served=%d", f.served.Load())
	}
}

// A real headless browser against a page that behaves like the challenge
// interstitial: JavaScript sets the cookie. Skipped where no browser exists.
func TestBrowserSolvesAJavaScriptChallenge(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	b := &Browser{Timeout: 30 * time.Second}
	if _, err := b.Find(); err != nil {
		t.Skip(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(CookieName); err == nil && c.Value == "js-made" {
			fmt.Fprint(w, "<html><title>Sign in</title></html>")
			return
		}
		w.Header().Set("x-amzn-waf-action", "challenge")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `<html><script>setTimeout(function(){document.cookie="aws-waf-token=js-made; path=/; max-age=600";location.reload()},300)</script></html>`)
	}))
	defer srv.Close()
	resp, err := get(t, Wrap(&http.Client{}, b, nil), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

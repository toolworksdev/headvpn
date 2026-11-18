package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/toolworksdev/headvpn/internal/wafchallenge"
)

// wafFront answers like an AWS WAF Challenge rule (202, header, empty body)
// for the requests guard() selects that carry no valid token.
func wafFront(next http.Handler, guard func(*http.Request) bool, challenged *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guard(r) {
			if c, err := r.Cookie(wafchallenge.CookieName); err != nil || c.Value != "good" {
				challenged.Add(1)
				w.Header().Set("x-amzn-waf-action", "challenge")
				w.WriteHeader(http.StatusAccepted)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type tokenSolver struct{ calls atomic.Int32 }

func (s *tokenSolver) Solve(ctx context.Context, page *url.URL) (wafchallenge.Token, error) {
	s.calls.Add(1)
	return wafchallenge.Token{Value: "good", Expires: time.Now().Add(time.Hour)}, nil
}

func wafServer(t *testing.T, f *fakeKC, guard func(*http.Request) bool, challenged *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(wafFront(f.handler(func() string { return srv.URL }), guard, challenged))
	t.Cleanup(srv.Close)
	return srv
}

// The challenge can appear at any step, here only on the OTP post.
func otpStep(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Query().Get("execution") == "d"
}

func TestWAFChallengeOnALaterStepIsSolvedAndTheOTPPostReplayedOnce(t *testing.T) {
	f := &fakeKC{pw: "right", otp: "123456"}
	var challenged atomic.Int32
	srv := wafServer(t, f, otpStep, &challenged)
	calls := 0
	l := login(srv, "right", &calls)
	s := &tokenSolver{}
	l.WAF = s
	form, err := l.Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=x")
	if err != nil {
		t.Fatal(err)
	}
	if form.SAMLResponse != "PHNhbWw+" {
		t.Fatalf("unexpected form %+v", form)
	}
	if challenged.Load() != 1 || s.calls.Load() != 1 {
		t.Fatalf("challenged=%d solves=%d, want 1 and 1", challenged.Load(), s.calls.Load())
	}
	// The challenged post never reached Keycloak; the replay did, once, and
	// the code was asked for once.
	if f.otpPosts.Load() != 1 || calls != 1 {
		t.Fatalf("otpPosts=%d otpCalls=%d, want 1 and 1", f.otpPosts.Load(), calls)
	}
}

func TestWAFChallengeWithoutSolverIsADistinctError(t *testing.T) {
	f := &fakeKC{pw: "right", otp: "123456"}
	var challenged atomic.Int32
	srv := wafServer(t, f, func(*http.Request) bool { return true }, &challenged)
	calls := 0
	_, err := login(srv, "right", &calls).Run(context.Background(), srv.URL+"/realms/r/protocol/saml?SAMLRequest=secret-request")
	if !errors.Is(err, wafchallenge.ErrUnsolved) {
		t.Fatalf("want ErrUnsolved, got %v", err)
	}
	if errors.Is(err, ErrUnexpectedPage) {
		t.Fatalf("a WAF challenge must not read as an unknown page: %v", err)
	}
	if strings.Contains(err.Error(), "secret-request") {
		t.Fatalf("error leaks the query: %v", err)
	}
	if f.hits.Load() != 0 || calls != 0 {
		t.Fatalf("keycloak hits=%d otpCalls=%d, want 0", f.hits.Load(), calls)
	}
}

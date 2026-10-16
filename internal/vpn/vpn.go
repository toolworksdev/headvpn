// Package vpn wires a profile's backend and IdP into connect/status/disconnect.
package vpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/toolworksdev/headvpn/internal/backend/awsofficial"
	"github.com/toolworksdev/headvpn/internal/backend/pritunl"
	"github.com/toolworksdev/headvpn/internal/capture"
	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/idp/entra"
	"github.com/toolworksdev/headvpn/internal/idp/keycloak"
	"github.com/toolworksdev/headvpn/internal/secret"
	"github.com/toolworksdev/headvpn/internal/totp"
)

// Result is what connect/status/disconnect report.
type Result struct {
	Profile string `json:"profile"`
	State   string `json:"state"`
	// Already is true when connect found the tunnel up and did nothing.
	Already bool `json:"already,omitempty"`
	// Via says who answered the IdP: "headvpn" (this tool logged in) or
	// "browser" (the default browser still had a live IdP session).
	// "token" (pritunl reused its stored SSO token) or "person" (a human
	// completed the login URL) are also possible.
	Via string `json:"via,omitempty"`
	// SwitchedFrom lists the profiles connect disconnected first.
	SwitchedFrom []string `json:"switched_from,omitempty"`
	// LoginURL is set when a person must complete a single sign-on.
	LoginURL string `json:"login_url,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Backend is the subset of the AWS client this package needs.
type Backend interface {
	Status(ctx context.Context, profile string) (string, error)
	Start(ctx context.Context, profile string) error
	Stop(ctx context.Context, profile string) error
	WaitFor(ctx context.Context, profile, want string, every time.Duration) (string, error)
}

// Deps are the replaceable parts; Default() fills them for real use.
type Deps struct {
	Backend func(p config.Profile) Backend
	Secrets *secret.Resolver
	// FindURL looks for the SAML login URL the client hands to the browser.
	// It is started BEFORE the client, because the URL is visible only for
	// the instant the client spends launching the browser.
	FindURL func(ctx context.Context, origin string, since time.Time) (string, error)
	HTTP    *http.Client // IdP traffic; nil = default with cookie jar
	Deliver *http.Client // loopback POST of the assertion
	Now     func() time.Time
	Poll    time.Duration
	// CheckOS rejects platforms the backend does not support; nil skips it.
	CheckOS func() error
	// ConfigPath is handed to the root supervisor of the aws-openvpn backend.
	ConfigPath string
	// TOTPState is the directory remembering the last TOTP step per secret
	// across runs; "" keeps it in memory only.
	TOTPState string
	// Pritunl returns the CLI wrapper for the pritunl backend.
	Pritunl func(p config.Profile) PritunlCLI
	// OnLoginURL is told about a login URL a person must open, as soon as it
	// is known (connect then keeps waiting for the tunnel).
	OnLoginURL func(profile, url string)
}

// Default returns production dependencies.
func Default(prompt secret.Prompter) Deps {
	home, _ := os.UserHomeDir()
	return Deps{
		Backend: func(p config.Profile) Backend { return awsofficial.New(p.AWSCLI) },
		Secrets: secret.NewResolver(prompt),
		FindURL: func(ctx context.Context, origin string, since time.Time) (string, error) {
			origin = strings.TrimRight(origin, "/")
			ps := capture.NewProcWatcher(origin, "aws-vpn-client")
			hist := &capture.Finder{Prefix: origin + "/%SAMLRequest=", Since: since, Files: capture.HistoryFiles(home)}
			return capture.First(ctx,
				func(ctx context.Context) (string, error) { return ps.Wait(ctx, time.Millisecond) },
				func(ctx context.Context) (string, error) { return hist.Wait(ctx, 500*time.Millisecond) },
			)
		},
		Deliver: &http.Client{Timeout: 15 * time.Second},
		Pritunl: func(p config.Profile) PritunlCLI { return pritunl.New(p.PritunlCLI) },
		TOTPState: func() string {
			if c, err := os.UserCacheDir(); err == nil {
				return filepath.Join(c, "headvpn")
			}
			return ""
		}(),
		Now:     time.Now,
		Poll:    time.Second,
		CheckOS: awsofficial.Supported,
	}
}

// Status reports the backend state.
func Status(ctx context.Context, name string, p config.Profile, d Deps) Result {
	if p.Backend == "pritunl" {
		return pritunlStatus(ctx, name, p, d)
	}
	if p.Backend == "aws-openvpn" {
		st, err := openvpnStatus(name)
		return result(name, st, err)
	}
	st, err := d.Backend(p).Status(ctx, p.AWSProfile)
	return result(name, st, err)
}

// Disconnect stops the tunnel.
func Disconnect(ctx context.Context, name string, p config.Profile, d Deps) Result {
	if p.Backend == "pritunl" {
		return pritunlDisconnect(ctx, name, p, d)
	}
	if p.Backend == "aws-openvpn" {
		st, err := openvpnDisconnect(ctx, name, d.ConfigPath)
		return result(name, st, err)
	}
	b := d.Backend(p)
	if err := b.Stop(ctx, p.AWSProfile); err != nil {
		return result(name, "", err)
	}
	st, err := b.WaitFor(ctx, p.AWSProfile, awsofficial.StateNotConnected, d.Poll)
	return result(name, st, err)
}

// Connect brings the tunnel up, answering the SAML login without a human.
func Connect(ctx context.Context, name string, p config.Profile, d Deps) (res Result, err error) {
	if p.Backend == "pritunl" {
		return pritunlConnect(ctx, name, p, d)
	}
	if p.Backend == "aws-openvpn" {
		return openvpnConnect(ctx, name, p, d, d.ConfigPath)
	}
	if d.CheckOS != nil {
		if err := d.CheckOS(); err != nil {
			return result(name, "", err), err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout())
	defer cancel()
	b := d.Backend(p)

	st, err := b.Status(ctx, p.AWSProfile)
	if err != nil {
		return result(name, "", err), err
	}
	if st == awsofficial.StateConnected {
		r := result(name, st, nil)
		r.Already = true
		return r, nil
	}

	// Secrets first: fail before touching the client or opening a browser.
	login, err := buildLogin(ctx, p, d)
	if err != nil {
		return result(name, st, err), err
	}

	if st != awsofficial.StateNotConnected {
		// A half-done attempt (WaitingForIdentity, Reconnecting) holds the
		// SAML port and a challenge we did not see; start clean.
		_ = b.Stop(ctx, p.AWSProfile)
		_, _ = b.WaitFor(ctx, p.AWSProfile, awsofficial.StateNotConnected, d.Poll)
	}

	since := d.Now().Add(-2 * time.Second)
	findCtx, stopFind := context.WithTimeout(ctx, 45*time.Second)
	defer stopFind()
	urlCh := make(chan found, 1)
	go func() {
		u, err := d.FindURL(findCtx, p.IdPOrigin, since)
		urlCh <- found{u, err}
	}()
	time.Sleep(d.Poll) // let the watcher take its baseline snapshot first
	if err := b.Start(ctx, p.AWSProfile); err != nil {
		return result(name, "", err), err
	}
	defer func() {
		if err != nil {
			// Do not leave the client waiting for an identity that will not come.
			stopCtx, c := context.WithTimeout(context.Background(), 15*time.Second)
			defer c()
			_ = b.Stop(stopCtx, p.AWSProfile)
		}
	}()

	samlURL, byBrowser, err := findOrBrowser(ctx, b, p.AWSProfile, urlCh, d)
	if err != nil {
		return result(name, "", err), err
	}
	if byBrowser {
		// The default browser still had a live IdP session and answered the
		// SAML request by itself. Nothing left for us to submit.
		r := result(name, awsofficial.StateConnected, nil)
		r.Via = "browser"
		return r, nil
	}

	form, err := login.Run(ctx, samlURL)
	if err != nil {
		return result(name, "", err), err
	}
	if err := form.Deliver(ctx, d.Deliver); err != nil {
		// Measured: when the default browser holds a live IdP session it
		// answers the same request first, and the client closes its port. If
		// the client already moved past WaitingForIdentity, that is a win.
		if cur, serr := b.Status(ctx, p.AWSProfile); serr == nil &&
			cur != awsofficial.StateWaitingForIdentity && cur != awsofficial.StateNotConnected {
			if st, werr := b.WaitFor(ctx, p.AWSProfile, awsofficial.StateConnected, d.Poll); werr == nil {
				r := result(name, st, nil)
				r.Via = "browser"
				return r, nil
			}
		}
		return result(name, "", err), err
	}
	st, err = b.WaitFor(ctx, p.AWSProfile, awsofficial.StateConnected, d.Poll)
	r := result(name, st, err)
	if err == nil {
		r.Via = "headvpn"
	}
	return r, err
}

type found struct {
	url string
	err error
}

// findOrBrowser waits for the SAML URL and, at the same time, watches the
// client: when the browser already holds an IdP session it completes the
// login on its own and the client reaches Connected first.
func findOrBrowser(ctx context.Context, b Backend, profile string, urlCh <-chan found, d Deps) (string, bool, error) {
	tick := time.NewTicker(d.Poll)
	defer tick.Stop()
	for {
		select {
		case f := <-urlCh:
			if f.err != nil {
				// The browser may have finished while every source failed;
				// check once more before giving up.
				if st, err := b.Status(ctx, profile); err == nil && st == awsofficial.StateConnected {
					return "", true, nil
				}
				return "", false, f.err
			}
			return f.url, false, nil
		case <-tick.C:
			if st, err := b.Status(ctx, profile); err == nil && st == awsofficial.StateConnected {
				return "", true, nil
			}
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
	}
}

func buildLogin(ctx context.Context, p config.Profile, d Deps) (*keycloak.Login, error) {
	if p.IdP != "keycloak" {
		return nil, fmt.Errorf("unknown idp %q", p.IdP)
	}
	pw, err := d.Secrets.Resolve(ctx, "password", p.Password)
	if err != nil {
		return nil, err
	}
	l := &keycloak.Login{Origin: p.IdPOrigin, Username: p.Username, Password: pw, Client: d.HTTP}
	if l.OTP, err = otpFunc(ctx, p, d); err != nil {
		return nil, err
	}
	return l, nil
}

// otpFunc returns the code source configured for p, or nil when none is.
func otpFunc(ctx context.Context, p config.Profile, d Deps) (func() (string, error), error) {
	switch {
	case p.TOTPSecret != "":
		seed, err := d.Secrets.Resolve(ctx, "totp_secret", p.TOTPSecret)
		if err != nil {
			return nil, err
		}
		g, err := totp.NewGenerator(seed)
		if err != nil {
			return nil, err
		}
		g.WithClock(d.Now)
		if d.TOTPState != "" {
			sum := sha256.Sum256([]byte(strings.ToUpper(strings.Join(strings.Fields(seed), ""))))
			g.WithState(filepath.Join(d.TOTPState, "totp-"+hex.EncodeToString(sum[:8])))
		}
		return func() (string, error) { return g.Next(ctx) }, nil
	case p.OTP != "":
		ref := p.OTP
		return func() (string, error) { return d.Secrets.Resolve(ctx, "one-time code", ref) }, nil
	}
	return nil, nil
}

func result(name, state string, err error) Result {
	r := Result{Profile: name, State: state}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

// Rejected reports whether err means the IdP refused the credentials; callers
// must not retry those automatically.
func Rejected(err error) bool {
	return errors.Is(err, keycloak.ErrRejected) || errors.Is(err, entra.ErrRejected)
}

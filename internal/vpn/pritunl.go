package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"time"

	"github.com/toolworksdev/headvpn/internal/backend/pritunl"
	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/idp/entra"
)

// ErrLoginRequired means the VPN server wants a single sign-on that this
// profile leaves to a person: open Result.LoginURL in any browser (a phone
// works) before the connect timeout, or run connect again later.
var ErrLoginRequired = errors.New("login required: open login_url in a browser")

// PritunlCLI is the slice of the Pritunl CLI this package uses.
type PritunlCLI interface {
	Find(ctx context.Context, ref string) (pritunl.Profile, error)
	Start(ctx context.Context, id, mode string) (string, error)
	Stop(ctx context.Context, id string) error
	WaitFor(ctx context.Context, id string, want bool, every time.Duration) (pritunl.Profile, error)
}

func pritunlState(p pritunl.Profile) string {
	switch {
	case p.Connected:
		return "Connected"
	case p.RunState == "Active":
		return p.Status // Connecting, Authenticating…
	default:
		return "NotConnected"
	}
}

func pritunlStatus(ctx context.Context, name string, p config.Profile, d Deps) Result {
	pr, err := d.Pritunl(p).Find(ctx, p.PritunlProfile)
	return result(name, pritunlState(pr), err)
}

func pritunlDisconnect(ctx context.Context, name string, p config.Profile, d Deps) Result {
	c := d.Pritunl(p)
	pr, err := c.Find(ctx, p.PritunlProfile)
	if err != nil {
		return result(name, "", err)
	}
	if err := c.Stop(ctx, pr.ID); err != nil {
		return result(name, "", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pr, err = c.WaitFor(ctx, pr.ID, false, d.Poll)
	return result(name, pritunlState(pr), err)
}

func pritunlConnect(ctx context.Context, name string, p config.Profile, d Deps) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout())
	defer cancel()
	c := d.Pritunl(p)
	pr, err := c.Find(ctx, p.PritunlProfile)
	if err != nil {
		return result(name, "", err), err
	}
	if pr.Connected {
		r := result(name, "Connected", nil)
		r.Already = true
		return r, nil
	}
	// Secrets first: fail before touching the client.
	var login *entra.Login
	if p.IdP == "entra" {
		if login, err = entraLogin(ctx, p, d); err != nil {
			return result(name, "", err), err
		}
	}
	if pr.RunState == "Active" {
		// A half-done attempt holds an SSO request we did not see; start clean.
		_ = c.Stop(ctx, pr.ID)
		_, _ = c.WaitFor(ctx, pr.ID, false, d.Poll)
	}
	loginURL, err := c.Start(ctx, pr.ID, p.PritunlMode)
	if err != nil {
		return result(name, "", err), err
	}
	via := "token" // the client's stored SSO token was enough
	if loginURL != "" {
		if login == nil {
			via = "person"
			if d.OnLoginURL != nil {
				d.OnLoginURL(name, loginURL)
			}
		} else {
			via = "headvpn"
			if err := login.Run(ctx, loginURL); err != nil {
				_ = c.Stop(context.Background(), pr.ID)
				return result(name, "", err), err
			}
		}
	}
	pr, err = c.WaitFor(ctx, pr.ID, true, d.Poll)
	if err != nil {
		_ = c.Stop(context.Background(), pr.ID)
		if via == "person" {
			r := result(name, "", fmt.Errorf("%w (not completed within %s)", ErrLoginRequired, p.Timeout()))
			r.LoginURL = loginURL
			return r, ErrLoginRequired
		}
		err = fmt.Errorf("tunnel not up within %s: %w (if the server wanted a single sign-on, pritunl-client older than 1.4.4777 does not report the login URL for user profiles)", p.Timeout(), err)
		return result(name, "", err), err
	}
	r := result(name, "Connected", nil)
	r.Via = via
	return r, nil
}

func entraLogin(ctx context.Context, p config.Profile, d Deps) (*entra.Login, error) {
	pw, err := d.Secrets.Resolve(ctx, "password", p.Password)
	if err != nil {
		return nil, err
	}
	otp, err := otpFunc(ctx, p, d)
	if err != nil {
		return nil, err
	}
	client := d.HTTP
	if client == nil {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	}
	l := &entra.Login{
		Origin: p.IdPOrigin, Username: p.Username, Password: pw, OTP: otp, Client: client,
		// Pritunl's Azure SSO returns through its auth relay before the VPN server.
		Relays: []string{"https://auth.pritunl.com"},
	}
	if os.Getenv("HEADVPN_DEBUG") != "" {
		l.Trace = func(s string) { fmt.Fprintln(os.Stderr, s) }
	}
	return l, nil
}

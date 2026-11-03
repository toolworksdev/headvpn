package vpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/toolworksdev/headvpn/internal/awsconfig"
	"github.com/toolworksdev/headvpn/internal/awssso"
	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/idp/entra"
	"github.com/toolworksdev/headvpn/internal/saml"
)

// SSOResult is what `headvpn sso` reports.
type SSOResult struct {
	Name  string `json:"name"`
	State string `json:"state"`
	// Via is "headvpn" when this tool answered the IdP.
	Via string `json:"via,omitempty"`
	// VerifiedWith is the AWS profile used for sts get-caller-identity, and
	// Identity the ARN it returned: the login is only reported once AWS
	// accepted the new credentials.
	VerifiedWith string `json:"verified_with,omitempty"`
	Identity     string `json:"identity,omitempty"`
	Error        string `json:"error,omitempty"`
}

// SSODeps are the replaceable parts of an SSO login.
type SSODeps struct {
	Deps
	// AWSConfig is the AWS CLI config file; "" = awsconfig.DefaultPath().
	AWSConfig string
	// Command builds a process; nil = exec.CommandContext.
	Command func(ctx context.Context, name string, args ...string) *exec.Cmd
	// Flow tweaks the HTTP flow (tests point it at a fake AWS).
	Flow func(*awssso.Flow)
}

// SSOLogin runs `aws sso login` for name and answers its browser half.
func SSOLogin(ctx context.Context, name string, s config.SSO, d SSODeps) (SSOResult, error) {
	res := SSOResult{Name: name, State: "NotLoggedIn"}
	fail := func(err error) (SSOResult, error) { res.Error = err.Error(); return res, err }

	path := d.AWSConfig
	if path == "" {
		path = awsconfig.DefaultPath()
	}
	f, err := awsconfig.Load(path)
	if err != nil {
		return fail(fmt.Errorf("AWS config: %w", err))
	}
	t, err := f.Resolve(name)
	if err != nil {
		return fail(err)
	}
	// Secrets are resolved before the CLI starts: a missing one fails fast.
	idp, err := ssoIdP(ctx, s, t.Region, d.Deps)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout())
	defer cancel()

	cli := s.AWSCLI
	if cli == "" {
		cli = "aws"
	}
	mk := d.Command
	if mk == nil {
		mk = exec.CommandContext
	}
	args := append([]string{"sso", "login"}, t.LoginArgs...)
	cmd := mk(ctx, cli, append(args, "--no-browser")...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fail(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fail(fmt.Errorf("start %s: %w", cli, err))
	}
	killed := false
	defer func() {
		if !killed && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	authorize, rest, err := readAuthorizeURL(out, t.Region)
	if err != nil {
		return fail(err)
	}
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(rest); done <- string(b) }()

	flow := &awssso.Flow{StartURL: t.StartURL, Region: t.Region, IdP: idp, Client: d.HTTP}
	if flow.Client == nil {
		jar, _ := cookiejar.New(nil)
		flow.Client = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	} else if flow.Client.Jar == nil {
		c := *flow.Client
		c.Jar, _ = cookiejar.New(nil)
		flow.Client = &c
	}
	if os.Getenv("HEADVPN_DEBUG") != "" {
		flow.Trace = func(s string) { fmt.Fprintln(os.Stderr, s) }
	}
	if d.Flow != nil {
		d.Flow(flow)
	}
	if err := flow.Run(ctx, authorize); err != nil {
		return fail(err)
	}

	tail := <-done
	werr := cmd.Wait()
	killed = true
	if werr != nil {
		return fail(fmt.Errorf("aws sso login: %v: %s", werr, firstLine(stderr.String())))
	}
	if !strings.Contains(tail, "Successfully logged into") {
		return fail(errors.New("aws sso login ended without reporting a login"))
	}
	res.State, res.Via = "LoggedIn", "headvpn"

	// The CLI's word is a process state; AWS accepting the token is the effect.
	profile := s.VerifyProfile
	if profile == "" && len(t.Profiles) > 0 {
		profile = t.Profiles[0]
	}
	if profile == "" {
		return res, nil
	}
	res.VerifiedWith = profile
	sts := mk(ctx, cli, "sts", "get-caller-identity", "--profile", profile, "--query", "Arn", "--output", "text")
	var serr strings.Builder
	sts.Stderr = &serr
	arn, err := sts.Output()
	if err != nil {
		return fail(fmt.Errorf("logged in, but sts get-caller-identity --profile %s failed: %s", profile, firstLine(serr.String())))
	}
	res.Identity = strings.TrimSpace(string(arn))
	return res, nil
}

// readAuthorizeURL reads the CLI's output until the authorize URL it wants a
// browser to open, and returns the reader for the rest.
func readAuthorizeURL(r io.Reader, region string) (string, io.Reader, error) {
	br := bufio.NewReader(r)
	prefix := "https://oidc." + region + ".amazonaws.com/authorize?"
	var seen []string
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return line, br, nil
		}
		if line != "" && len(seen) < 5 {
			seen = append(seen, firstLine(line))
		}
		if err != nil {
			if strings.Contains(strings.Join(seen, " "), "user_code") || strings.Contains(strings.Join(seen, " "), "device") {
				return "", nil, errors.New("the aws CLI used the device-code flow: set sso_registration_scopes on the sso-session so it uses the authorization-code flow")
			}
			return "", nil, fmt.Errorf("the aws CLI printed no authorize URL (%s)", strings.Join(seen, " | "))
		}
	}
}

// ssoIdP builds the IdP adapter for an SSO login. The SAML response may only
// go back to this region's AWS sign-in service.
func ssoIdP(ctx context.Context, s config.SSO, region string, d Deps) (awssso.IdP, error) {
	p := s.AsProfile()
	acs := []string{"https://" + region + ".signin.aws.amazon.com", "https://" + region + ".signin.aws"}
	switch s.IdP {
	case "keycloak":
		l, err := buildLogin(ctx, p, d)
		if err != nil {
			return nil, err
		}
		if l.Client == nil {
			jar, _ := cookiejar.New(nil)
			l.Client = &http.Client{Jar: jar, Timeout: 30 * time.Second}
		}
		return func(ctx context.Context, action string, form url.Values) (*saml.PostForm, error) {
			return l.RunPost(ctx, action, form)
		}, nil
	case "entra":
		pw, err := d.Secrets.Resolve(ctx, "password", p.Password)
		if err != nil {
			return nil, err
		}
		otp, err := otpFunc(ctx, p, d)
		if err != nil {
			return nil, err
		}
		jar, _ := cookiejar.New(nil)
		l := &entra.Login{Origin: p.IdPOrigin, Username: p.Username, Password: pw, OTP: otp,
			Client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
		if os.Getenv("HEADVPN_DEBUG") != "" {
			l.Trace = func(s string) { fmt.Fprintln(os.Stderr, s) }
		}
		return func(ctx context.Context, action string, form url.Values) (*saml.PostForm, error) {
			return l.RunSAML(ctx, action, form, acs)
		}, nil
	}
	return nil, fmt.Errorf("unknown idp %q", s.IdP)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

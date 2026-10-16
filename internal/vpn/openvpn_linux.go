//go:build linux

package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/toolworksdev/headvpn/internal/awsovpn/awsclient"
	"github.com/toolworksdev/headvpn/internal/awsovpn/profile"
	"github.com/toolworksdev/headvpn/internal/awsovpn/supervisor"
	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/idp/keycloak"
	"github.com/toolworksdev/headvpn/internal/totp"
)

// The aws-openvpn backend drives the OpenVPN build that AWS ships with its
// Linux client (acvc-openvpn), unmodified, over its management interface:
// the VPN server hands over the SAML URL in a CRV1 challenge, so no browser
// is involved. OpenVPN needs root for the tunnel, so the long-running part
// (`headvpn __supervise`) runs as root and keeps the session up, re-logging
// in when the tunnel drops. `connect` starts it and returns once connected.

// supervisorInput is everything the root supervisor needs, sent by the unprivileged
// `connect` over a pipe on stdin: never argv, never the environment. The
// supervisor reads no file the caller names (config, profile): a sudoers
// rule for `headvpn __supervise` must not let a user make root read
// arbitrary files and echo them back in an error.
type supervisorInput struct {
	Password      string `json:"password"`
	TOTPSecret    string `json:"totp_secret,omitempty"`
	OVPN          []byte `json:"ovpn"`
	AWSOpenVPNDir string `json:"aws_openvpn_dir,omitempty"`
	IdPOrigin     string `json:"idp_origin"`
	Username      string `json:"username"`
	Platform      string `json:"platform,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	FIPS          bool   `json:"fips"`
}

// secrets is the part of the handoff the login needs.
type secrets struct {
	Password   string
	TOTPSecret string
}

const lastErrorFile = "last-error"

func openvpnStatus(name string) (string, error) {
	st, err := supervisor.ReadStatus(supervisor.DefaultRunDir)
	if errors.Is(err, fs.ErrNotExist) {
		return "NotConnected", nil
	}
	if err != nil {
		return "", err
	}
	if st.Profile != name {
		return "NotConnected", nil
	}
	if st.State == "CONNECTED" {
		return "Connected", nil
	}
	return st.State, nil
}

func openvpnConnect(ctx context.Context, name string, p config.Profile, d Deps, cfgPath string) (Result, error) {
	if st, err := supervisor.ReadStatus(supervisor.DefaultRunDir); err == nil {
		if st.Profile == name && st.State == "CONNECTED" {
			r := result(name, "Connected", nil)
			r.Already = true
			return r, nil
		}
		err := fmt.Errorf("another session is running (profile %q, state %s); disconnect it first", st.Profile, st.State)
		return result(name, "", err), err
	}
	// Secrets first, as the invoking user: fail before asking for root.
	pw, err := d.Secrets.Resolve(ctx, "password", p.Password)
	if err != nil {
		return result(name, "", err), err
	}
	h := supervisorInput{
		Password: pw, AWSOpenVPNDir: p.AWSOpenVPNDir, IdPOrigin: p.IdPOrigin, Username: p.Username,
		Platform: p.Platform, ClientVersion: p.ClientVersion, FIPS: p.UseFIPS(),
	}
	if p.TOTPSecret != "" {
		if h.TOTPSecret, err = d.Secrets.Resolve(ctx, "totp_secret", p.TOTPSecret); err != nil {
			return result(name, "", err), err
		}
		if _, err := totp.DecodeSecret(h.TOTPSecret); err != nil {
			return result(name, "", err), err
		}
	}
	// The profile is read as the invoking user, not by root.
	if h.OVPN, err = os.ReadFile(p.OVPN); err != nil {
		return result(name, "", err), err
	}
	if prof, err := profile.Parse(h.OVPN); err != nil {
		err = fmt.Errorf("%s: %w", p.OVPN, err)
		return result(name, "", err), err
	} else if err := prof.Validate(); err != nil {
		err = fmt.Errorf("%s: %w", p.OVPN, err)
		return result(name, "", err), err
	}
	payload, _ := json.Marshal(h)

	self, err := os.Executable()
	if err != nil {
		return result(name, "", err), err
	}
	argv := []string{self, "__supervise", name}
	if os.Geteuid() != 0 {
		argv = append([]string{"sudo", "-n", "--"}, argv...)
	}
	_ = os.Remove(filepath.Join(supervisor.DefaultRunDir, lastErrorFile)) // best effort; root-owned when it exists
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return result(name, "", err), err
	}
	var errBuf limitedBuffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return result(name, "", err), err
	}
	_, _ = stdin.Write(payload)
	_ = stdin.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	ctx, cancel := context.WithTimeout(ctx, p.Timeout())
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case werr := <-exited:
			err := supervisorFailure(werr, errBuf.String())
			return result(name, "", err), err
		case <-tick.C:
			st, err := supervisor.ReadStatus(supervisor.DefaultRunDir)
			if err == nil && st.Profile == name && st.State == "CONNECTED" {
				r := result(name, "Connected", nil)
				r.Via = "headvpn"
				return r, nil
			}
		case <-ctx.Done():
			_ = openvpnStop(context.Background(), cfgPath, name)
			err := fmt.Errorf("timed out after %s waiting for the tunnel", p.Timeout())
			return result(name, "", err), err
		}
	}
}

// supervisorFailure explains why the supervisor exited before connecting.
func supervisorFailure(werr error, stderr string) error {
	if b, err := os.ReadFile(filepath.Join(supervisor.DefaultRunDir, lastErrorFile)); err == nil && len(b) > 0 {
		msg := strings.TrimSpace(string(b))
		if strings.Contains(msg, keycloak.ErrRejected.Error()) {
			return fmt.Errorf("%w: %s", keycloak.ErrRejected, msg)
		}
		return errors.New(msg)
	}
	if stderr != "" {
		return fmt.Errorf("supervisor exited (%v): %s", werr, stderr)
	}
	return fmt.Errorf("supervisor exited before connecting (%v)", werr)
}

func openvpnDisconnect(ctx context.Context, name, cfgPath string) (string, error) {
	if err := openvpnStop(ctx, cfgPath, name); err != nil {
		return "", err
	}
	return "NotConnected", nil
}

// openvpnStop asks the root supervisor to end the session.
func openvpnStop(ctx context.Context, cfgPath, name string) error {
	if os.Geteuid() == 0 {
		return Stop(ctx)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "sudo", "-n", "--", self, "__stop").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudo %s __stop: %v: %s", filepath.Base(self), err, out)
	}
	return nil
}

// Stop signals the running supervisor and waits for it to exit. Root only.
func Stop(ctx context.Context) error {
	st, err := supervisor.ReadStatus(supervisor.DefaultRunDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := syscall.Kill(st.PID, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal supervisor (pid %d): %w", st.PID, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for supervisor.Alive(st.PID) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("supervisor (pid %d) did not exit", st.PID)
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

// Supervise is `headvpn __supervise`: runs as root, reads the secrets from
// stdin and keeps the session up until SIGTERM or a permanent error.
func Supervise(name string, stdin io.Reader) (err error) {
	if os.Geteuid() != 0 {
		return errors.New("__supervise must run as root (start it with: headvpn connect)")
	}
	if err := os.MkdirAll(supervisor.DefaultRunDir, 0o755); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.WriteFile(filepath.Join(supervisor.DefaultRunDir, lastErrorFile), []byte(err.Error()+"\n"), 0o644)
		}
	}()
	var h supervisorInput
	if err := json.NewDecoder(io.LimitReader(stdin, 1<<20)).Decode(&h); err != nil {
		return fmt.Errorf("reading the supervisor input from stdin: %w", err)
	}
	if h.Password == "" {
		return errors.New("no password received")
	}
	sec := secrets{Password: h.Password, TOTPSecret: h.TOTPSecret}
	p := config.Profile{IdPOrigin: h.IdPOrigin, Username: h.Username}
	ovpn := h.OVPN
	prof, err := profile.Parse(ovpn)
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if err := prof.Validate(); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	dir := h.AWSOpenVPNDir
	if dir == "" {
		dir = "/opt/awsvpnclient/Service/Resources/openvpn"
	}
	inst := awsclient.Install{Dir: dir}
	if err := inst.Check(); err != nil {
		return err
	}
	if pids := awsclient.Running(); len(pids) > 0 {
		return fmt.Errorf("acvc-openvpn is already running (pid %d): disconnect the AWS VPN Client first", pids[0])
	}
	release, err := supervisor.Lock(supervisor.DefaultRunDir)
	if err != nil {
		return err
	}
	defer release()

	logf, err := os.OpenFile(filepath.Join(supervisor.DefaultRunDir, "supervise.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	log := slog.New(slog.NewTextHandler(logf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	clientVersion := h.ClientVersion
	if clientVersion == "" {
		clientVersion = awsclient.ClientVersion(ctx)
	}
	platform := h.Platform
	if platform == "" {
		platform = "ubuntu"
	}
	login, err := loginFunc(p, sec)
	if err != nil {
		return err
	}
	return supervisor.New(supervisor.Config{
		Profile:       name,
		OVPN:          ovpn,
		Directives:    prof.Names(),
		IdPOrigin:     p.IdPOrigin,
		Install:       inst,
		ClientVersion: clientVersion,
		Platform:      platform,
		FIPS:          h.FIPS,
		Login:         login,
		Log:           log,
	}).Run(ctx)
}

// loginFunc answers each CRV1 challenge with a Keycloak login. One cookie jar
// for the whole session: after a tunnel drop the IdP's SSO cookie usually
// skips the password and the code.
func loginFunc(p config.Profile, sec secrets) (func(context.Context, *url.URL) (string, error), error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	var gen *totp.Generator
	if sec.TOTPSecret != "" {
		g, err := totp.NewGenerator(sec.TOTPSecret)
		if err != nil {
			return nil, err
		}
		gen = g
	}
	return func(ctx context.Context, u *url.URL) (string, error) {
		l := &keycloak.Login{Origin: p.IdPOrigin, Username: p.Username, Password: sec.Password, Client: client}
		if gen != nil {
			l.OTP = func() (string, error) { return gen.Next(ctx) }
		}
		form, err := l.Run(ctx, u.String())
		if err != nil {
			return "", err
		}
		return form.SAMLResponse, nil
	}, nil
}

// limitedBuffer keeps the first 4 KiB of the supervisor's stderr.
type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := 4096 - len(l.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return string(l.b) }

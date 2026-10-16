//go:build linux

// Package supervisor runs and supervises one acvc-openvpn process per VPN
// session, answering its credential requests with SAML logins and
// restarting it with backoff when it dies.
package supervisor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/toolworksdev/headvpn/internal/awsovpn/awsclient"
	"github.com/toolworksdev/headvpn/internal/awsovpn/crv1"
	"github.com/toolworksdev/headvpn/internal/awsovpn/mgmt"
)

type Config struct {
	Profile       string
	OVPN          []byte   // profile contents (already validated)
	Directives    []string // profile directive names
	IdPOrigin     string
	Install       awsclient.Install
	ClientVersion string
	Platform      string
	FIPS          bool
	RunDir        string

	// Login performs the IdP login for a challenge URL and returns the
	// SAMLResponse. Errors for which errors.Is(err, keycloak.ErrRejected) are final.
	Login func(ctx context.Context, u *url.URL) (string, error)
	Log   *slog.Logger
}

type Supervisor struct {
	cfg    Config
	log    *slog.Logger
	status *statusFile
}

func New(cfg Config) *Supervisor {
	if cfg.RunDir == "" {
		cfg.RunDir = DefaultRunDir
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Supervisor{cfg: cfg, log: cfg.Log, status: newStatusFile(cfg.RunDir, cfg.Profile)}
}

var backoff = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}

// maxAttempts bounds consecutive sessions that never reached CONNECTED.
const maxAttempts = 8

type sessionError struct {
	err   error
	retry bool
}

func (e *sessionError) Error() string { return e.err.Error() }
func (e *sessionError) Unwrap() error { return e.err }

// Run keeps a VPN session up until ctx is cancelled (nil) or a permanent
// error occurs.
func (s *Supervisor) Run(ctx context.Context) error {
	if err := os.MkdirAll(s.cfg.RunDir, 0o755); err != nil {
		return err
	}
	defer s.status.remove()
	defer os.RemoveAll(filepath.Join(s.cfg.RunDir, "private"))
	s.status.set("STARTING", "")
	failures := 0
	for {
		connected, err := s.session(ctx)
		if ctx.Err() != nil {
			s.log.Info("disconnected")
			return nil
		}
		var se *sessionError
		if errors.As(err, &se) && !se.retry {
			return se.err
		}
		if connected {
			failures = 0
		}
		failures++
		if failures >= maxAttempts {
			return fmt.Errorf("giving up after %d attempts: %w", failures, err)
		}
		d := backoff[min(failures-1, len(backoff)-1)]
		s.log.Warn("VPN session ended, restarting", "err", err, "in", d)
		s.status.set("RESTARTING", err.Error())
		select {
		case <-ctx.Done():
			s.log.Info("disconnected")
			return nil
		case <-time.After(d):
		}
	}
}

type authResult struct {
	pw  string
	err error
}

// session runs one acvc-openvpn process until it exits, ctx is cancelled,
// or the machine fails. connected reports whether it ever got CONNECTED.
func (s *Supervisor) session(ctx context.Context) (connected bool, err error) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	priv := filepath.Join(s.cfg.RunDir, "private")
	if err := os.MkdirAll(priv, 0o700); err != nil {
		return false, &sessionError{err, false}
	}
	os.Chmod(priv, 0o700)
	cfgPath := filepath.Join(priv, s.cfg.Profile+".ovpn")
	if err := os.WriteFile(cfgPath, s.cfg.OVPN, 0o600); err != nil {
		return false, &sessionError{err, false}
	}
	sock := filepath.Join(priv, "mgmt.sock")
	os.Remove(sock)

	cmd := s.cfg.Install.Command(awsclient.Options{
		Config: cfgPath, Socket: sock, Directives: s.cfg.Directives,
		ClientVersion: s.cfg.ClientVersion, Platform: s.cfg.Platform,
		LANCIDRs: awsclient.LANCIDRs(), FIPS: s.cfg.FIPS,
	})
	out := &tail{max: 20}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			out.add(sc.Text())
			s.log.Debug("openvpn: " + sc.Text())
		}
		io.Copy(io.Discard, pr)
	}()
	if err := cmd.Start(); err != nil {
		pw.Close()
		return false, &sessionError{fmt.Errorf("start %s: %w", cmd.Path, err), false}
	}
	s.log.Debug("started openvpn", "pid", cmd.Process.Pid)
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		pw.Close()
		close(done)
	}()
	exited := func() error {
		return &sessionError{fmt.Errorf("openvpn exited (%v): %s", waitErr, out.last()), true}
	}

	dialCtx, cancelDial := context.WithTimeout(sessCtx, 15*time.Second)
	go func() {
		select {
		case <-done:
			cancelDial()
		case <-dialCtx.Done():
		}
	}()
	conn, err := mgmt.Dial(dialCtx, sock)
	cancelDial()
	if err != nil {
		select {
		case <-done:
			// Exiting before the management interface is up means bad
			// options or a broken binary: retrying will not help.
			return false, &sessionError{fmt.Errorf("openvpn exited during startup (%v): %s", waitErr, out.last()), false}
		default:
		}
		s.terminate(cmd, done)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, &sessionError{fmt.Errorf("openvpn management interface: %w", err), true}
	}
	defer conn.Close()
	s.log.Debug("management interface connected")

	lines := make(chan string)
	go func() {
		defer close(lines)
		for {
			line, err := conn.ReadLine()
			if err != nil {
				return
			}
			select {
			case lines <- line:
			case <-sessCtx.Done():
				return
			}
		}
	}()

	auths := make(chan authResult, 1)
	m := &machine{idpOrigin: s.cfg.IdPOrigin}
	run := func(acts []action) error {
		for _, a := range acts {
			switch a := a.(type) {
			case sendAction:
				s.log.Debug("management <- " + a.logAs)
				if err := conn.Send(a.cmd); err != nil {
					return &sessionError{fmt.Errorf("management interface: %w", err), true}
				}
			case authAction:
				s.log.Info("VPN server requested SAML login", "idp", a.url.Host)
				s.status.set("AUTHENTICATING", a.url.Host)
				go func() {
					pw, err := s.authenticate(sessCtx, a)
					auths <- authResult{pw, err}
				}()
			case connectedAction:
				connected = true
				s.log.Info("connected", "tunnel_ip", a.st.LocalIP, "server", a.st.RemoteIP)
				s.status.update(func(st *Status) {
					st.State, st.Detail = "CONNECTED", ""
					st.TunnelIP, st.ServerIP = a.st.LocalIP, a.st.RemoteIP
					if st.ConnectedSince == nil {
						now := time.Now()
						st.ConnectedSince = &now
					}
				})
			case stateAction:
				s.onState(a.st)
			case warnAction:
				s.log.Warn(a.msg)
			case failAction:
				return &sessionError{a.err, a.retry}
			}
		}
		return nil
	}

	if err := run(m.start()); err != nil {
		s.stop(conn, cmd, done)
		return false, err
	}
	for {
		select {
		case <-ctx.Done():
			s.log.Info("disconnecting")
			s.status.set("DISCONNECTING", "")
			s.stop(conn, cmd, done)
			return connected, ctx.Err()
		case <-done:
			return connected, exited()
		case line, ok := <-lines:
			if !ok {
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					s.terminate(cmd, done)
				}
				return connected, exited()
			}
			msg := mgmt.Parse(line)
			if msg.Kind != mgmt.Password {
				s.log.Debug("management -> " + line)
			} else {
				s.log.Debug("management -> " + redactChallenge(line))
			}
			if err := run(m.onMessage(msg)); err != nil {
				s.stop(conn, cmd, done)
				return connected, err
			}
		case r := <-auths:
			if err := run(m.onAuth(r.pw, r.err)); err != nil {
				s.stop(conn, cmd, done)
				return connected, err
			}
		}
	}
}

func (s *Supervisor) authenticate(ctx context.Context, a authAction) (string, error) {
	saml, err := s.cfg.Login(ctx, a.url)
	if err != nil {
		return "", err
	}
	s.log.Info("IdP login succeeded", "saml_bytes", len(saml))
	return crv1.Password(a.challenge.StateID, saml)
}

func (s *Supervisor) onState(st mgmt.StateInfo) {
	switch st.Name {
	case "RECONNECTING":
		if st.Desc != "auth-failure" {
			s.log.Warn("connection lost, reconnecting", "reason", st.Desc)
		}
	case "EXITING":
		s.log.Debug("openvpn exiting", "reason", st.Desc)
	default:
		s.log.Debug("openvpn state", "state", st.Name, "detail", st.Desc)
	}
	s.status.set(st.Name, st.Desc)
}

// stop asks OpenVPN to exit cleanly (routes removed, configure-dns down)
// and kills it if it does not.
func (s *Supervisor) stop(conn *mgmt.Conn, cmd *exec.Cmd, done <-chan struct{}) {
	if err := conn.Send("signal SIGTERM"); err != nil {
		cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		s.log.Warn("openvpn did not exit, killing it")
		cmd.Process.Kill()
		<-done
	}
}

func (s *Supervisor) terminate(cmd *exec.Cmd, done <-chan struct{}) {
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-done
	}
}

// redactChallenge drops the SAML request from logged challenges.
func redactChallenge(line string) string {
	if i := strings.Index(line, "?SAMLRequest="); i >= 0 {
		return line[:i] + "?SAMLRequest=…"
	}
	return line
}

// tail keeps the last lines of OpenVPN's output for error messages.
type tail struct {
	mu    sync.Mutex
	max   int
	lines []string
}

func (t *tail) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
	if len(t.lines) > t.max {
		t.lines = t.lines[1:]
	}
}

// last returns the most relevant recent output line.
func (t *tail) last() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.lines) - 1; i >= 0; i-- {
		if l := t.lines[i]; strings.Contains(l, "ERROR") || strings.Contains(l, "error") || strings.Contains(l, "Exiting") {
			return l
		}
	}
	if len(t.lines) == 0 {
		return "no output"
	}
	return t.lines[len(t.lines)-1]
}

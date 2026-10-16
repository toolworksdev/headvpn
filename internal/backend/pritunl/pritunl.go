// Package pritunl drives the official Pritunl client through its CLI
// (`pritunl-client`), unmodified. The client service keeps the tunnel and
// the SSO token; when a single sign-on is needed the CLI prints the login
// URL instead of requiring a browser, which is what makes it usable headless.
package pritunl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DefaultCLI is where the official installers put the CLI.
func DefaultCLI() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Applications/Pritunl.app/Contents/Resources/pritunl-client"
	case "windows":
		return `C:\Program Files (x86)\Pritunl\pritunl-client.exe`
	default:
		return "pritunl-client"
	}
}

// Profile is one entry of `pritunl-client list -j`.
type Profile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RunState      string `json:"run_state"`
	Connected     bool   `json:"connected"`
	Status        string `json:"status"`
	ClientAddress string `json:"client_address"`
}

// Runner runs the CLI and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Client wraps the CLI.
type Client struct {
	CLI string
	Run Runner
}

// New returns a client for cli ("" = DefaultCLI).
func New(cli string) *Client {
	if cli == "" {
		cli = DefaultCLI()
	}
	return &Client{CLI: cli, Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}}
}

// ErrServiceDown means the client's background service is not running.
var ErrServiceDown = errors.New("pritunl: the Pritunl client service is not running")

// ErrNoProfile means no profile matched the configured id or name.
var ErrNoProfile = errors.New("pritunl: no such profile")

// List returns the profiles the client knows.
func (c *Client) List(ctx context.Context) ([]Profile, error) {
	out, err := c.Run(ctx, c.CLI, "list", "-j")
	if err != nil {
		if strings.Contains(string(out), "pritunl.sock") || strings.Contains(string(out), "pritunl.auth") {
			// Measured on macOS: opening the Pritunl app does not bring a
			// stopped service back; only an administrator can.
			return nil, fmt.Errorf("%w (macOS: sudo launchctl bootstrap system /Library/LaunchDaemons/com.pritunl.service.plist; Linux: sudo systemctl start pritunl-client)", ErrServiceDown)
		}
		return nil, fmt.Errorf("pritunl-client list: %v: %s", err, firstLine(out))
	}
	var ps []Profile
	if err := json.Unmarshal(out, &ps); err != nil {
		return nil, fmt.Errorf("pritunl-client list: unexpected output: %s", firstLine(out))
	}
	return ps, nil
}

// Find returns the profile whose id or name equals ref.
func (c *Client) Find(ctx context.Context, ref string) (Profile, error) {
	ps, err := c.List(ctx)
	if err != nil {
		return Profile{}, err
	}
	var hit []Profile
	for _, p := range ps {
		if p.ID == ref || p.Name == ref {
			hit = append(hit, p)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return Profile{}, fmt.Errorf("%w %q (pritunl-client list shows %d)", ErrNoProfile, ref, len(ps))
	default:
		return Profile{}, fmt.Errorf("pritunl: %d profiles match %q; use the id", len(hit), ref)
	}
}

// Start asks the service to connect. It returns the single sign-on URL when
// the server wants an interactive login, or "" when the stored token was
// enough. The CLI waits up to ~10 s for the URL before returning.
func (c *Client) Start(ctx context.Context, id, mode string) (string, error) {
	args := []string{"start", id}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	out, err := c.Run(ctx, c.CLI, args...)
	if err != nil {
		return "", fmt.Errorf("pritunl-client start: %v: %s", err, firstLine(out))
	}
	return loginURL(string(out)), nil
}

// Stop disconnects the profile.
func (c *Client) Stop(ctx context.Context, id string) error {
	out, err := c.Run(ctx, c.CLI, "stop", id)
	if err != nil {
		return fmt.Errorf("pritunl-client stop: %v: %s", err, firstLine(out))
	}
	return nil
}

// WaitFor polls until the profile is connected (want=true) or fully
// disconnected (want=false).
func (c *Client) WaitFor(ctx context.Context, id string, want bool, every time.Duration) (Profile, error) {
	for {
		p, err := c.Find(ctx, id)
		if err == nil {
			if want && p.Connected {
				return p, nil
			}
			if !want && !p.Connected && p.RunState != "Active" {
				return p, nil
			}
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(every):
		}
	}
}

// loginURL picks the URL the CLI prints after
// "Single sign-on authentication required, open link to complete authentication:".
func loginURL(out string) string {
	if !strings.Contains(strings.ToLower(out), "single sign-on") {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "https://") && !strings.ContainsAny(line, " \t") {
			return line
		}
	}
	return ""
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

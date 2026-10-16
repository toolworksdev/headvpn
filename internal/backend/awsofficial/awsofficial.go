// Package awsofficial drives the official AWS VPN Client (6.x) through its
// own CLI, so routes, DNS and the tunnel stay in AWS's hands. This tool only
// answers the SAML step that the client would otherwise hand to a human.
package awsofficial

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

// DefaultCLI is where the 6.x installer puts the CLI on macOS.
const DefaultCLI = "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/MacOS/aws-vpn-client"

// States reported by `aws-vpn-client get-connection-status`.
const (
	StateNotConnected       = "NotConnected"
	StateConnected          = "Connected"
	StateWaitingForIdentity = "WaitingForIdentity"
)

// Client wraps the CLI.
type Client struct {
	Path string
	// Run is replaceable in tests; it returns stdout and stderr.
	Run func(ctx context.Context, path string, args ...string) (stdout, stderr []byte, err error)
}

// New returns a client for the default CLI location.
func New(path string) *Client {
	if path == "" {
		path = DefaultCLI
	}
	return &Client{Path: path, Run: run}
}

func run(ctx context.Context, path string, args ...string) ([]byte, []byte, error) {
	var out, errb strings.Builder
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return []byte(out.String()), []byte(errb.String()), err
}

// Supported reports whether this backend can work on the current OS.
func Supported() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("aws-official backend is only implemented for macOS (got %s)", runtime.GOOS)
	}
	return nil
}

// Status returns the connection state of a client profile.
func (c *Client) Status(ctx context.Context, profile string) (string, error) {
	out, errb, err := c.Run(ctx, c.Path, "get-connection-status", "--profile-name", profile)
	if err != nil {
		return "", cliError("get-connection-status", out, errb, err)
	}
	var st struct {
		State string `json:"connection-status"`
	}
	if err := json.Unmarshal(out, &st); err != nil || st.State == "" {
		return "", fmt.Errorf("get-connection-status: unexpected output %q", truncate(out))
	}
	return st.State, nil
}

// Start asks the client to connect. With a SAML profile the client answers
// WaitingForIdentity and opens the IdP in the default browser.
func (c *Client) Start(ctx context.Context, profile string) error {
	out, errb, err := c.Run(ctx, c.Path, "connect", "--profile-name", profile)
	if err != nil {
		return cliError("connect", out, errb, err)
	}
	return nil
}

// Stop disconnects the profile.
func (c *Client) Stop(ctx context.Context, profile string) error {
	out, errb, err := c.Run(ctx, c.Path, "disconnect", "--profile-name", profile)
	if err != nil {
		return cliError("disconnect", out, errb, err)
	}
	return nil
}

// WaitFor polls until the profile reaches want, fails, or ctx ends.
func (c *Client) WaitFor(ctx context.Context, profile, want string, every time.Duration) (string, error) {
	last := ""
	for {
		st, err := c.Status(ctx, profile)
		if err == nil {
			last = st
			if st == want {
				return st, nil
			}
			if want == StateConnected && st == StateNotConnected {
				return st, errors.New("the client gave up the connection (NotConnected)")
			}
		}
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("timed out waiting for %s (last state %q)", want, last)
		case <-time.After(every):
		}
	}
}

func cliError(op string, out, errb []byte, err error) error {
	var msg struct {
		Message string `json:"message"`
	}
	for _, b := range [][]byte{errb, out} {
		if json.Unmarshal(b, &msg) == nil && msg.Message != "" {
			return fmt.Errorf("aws-vpn-client %s: %s", op, msg.Message)
		}
	}
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("aws-vpn-client not found: install AWS VPN Client 6.x or set aws_cli in the profile")
	}
	return fmt.Errorf("aws-vpn-client %s: %v %s", op, err, truncate(errb))
}

func truncate(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

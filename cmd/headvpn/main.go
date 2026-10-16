// Command headvpn brings corporate VPNs up and down without a human at the
// browser, so scripts and AI agents can use them.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/secret"
	"github.com/toolworksdev/headvpn/internal/vpn"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes are part of the contract with callers.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitRejected = 3 // the IdP refused the credentials: do NOT retry automatically
	exitLogin    = 4 // a person must open login_url (pritunl without an idp)
)

const usage = `headvpn — connect a VPN without a human at the browser

Usage:
  headvpn connect <profile>      [--json] [--config path]
  headvpn status [<profile>]     [--json] [--config path]
  headvpn disconnect <profile>   [--json] [--config path]
  headvpn secret set <service>/<account>
  headvpn profiles               [--config path]
  headvpn version

Exit codes: 0 ok · 1 error · 2 usage · 3 credentials rejected (do not retry)
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	cfgPath := fs.String("config", config.DefaultPath(), "config file")
	// Allow flags after positional arguments: `connect work --json`.
	var pos []string
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return exitUsage
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}

	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "headvpn", version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "secret":
		return secretCmd(pos, stdout, stderr)
	case "__supervise":
		// Internal: the root half of the aws-openvpn backend, started by
		// connect. Everything it needs arrives on stdin; it reads no file
		// the caller names.
		if len(pos) != 1 {
			return exitUsage
		}
		if err := vpn.Supervise(pos[0], os.Stdin); err != nil {
			fmt.Fprintln(stderr, "headvpn:", err)
			return exitError
		}
		return exitOK
	case "__stop":
		// Internal: ends the root supervisor of the aws-openvpn backend.
		if err := vpn.Stop(context.Background()); err != nil {
			fmt.Fprintln(stderr, "headvpn:", err)
			return exitError
		}
		return exitOK
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "headvpn:", err)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	deps := vpn.Default(promptTTY)
	if abs, err := filepath.Abs(*cfgPath); err == nil {
		deps.ConfigPath = abs
	}
	if p, ok := cfg.Profiles[firstOr(pos, "")]; ok && p.Backend == "aws-openvpn" {
		deps.CheckOS = nil
	}
	deps.OnLoginURL = func(profile, u string) {
		// Printed at once on stderr: connect keeps waiting on stdout's result.
		if *asJSON {
			b, _ := json.Marshal(map[string]string{"event": "login_required", "profile": profile, "login_url": u})
			fmt.Fprintln(stderr, string(b))
			return
		}
		fmt.Fprintf(stderr, "%s: single sign-on required, open in any browser:\n%s\n", profile, u)
	}

	switch cmd {
	case "profiles":
		for _, n := range cfg.Names() {
			p := cfg.Profiles[n]
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", n, p.Backend, p.IdP)
		}
		return exitOK
	case "status":
		names := pos
		if len(names) == 0 {
			names = cfg.Names()
		}
		code := exitOK
		var all []vpn.Result
		for _, n := range names {
			p, ok := cfg.Profiles[n]
			if !ok {
				fmt.Fprintf(stderr, "headvpn: no profile %q\n", n)
				return exitUsage
			}
			r := vpn.Status(ctx, n, p, deps)
			if r.Error != "" {
				code = exitError
			}
			all = append(all, r)
		}
		emit(stdout, *asJSON, all...)
		return code
	case "connect", "disconnect":
		if len(pos) != 1 {
			fmt.Fprintf(stderr, "usage: headvpn %s <profile>\n", cmd)
			return exitUsage
		}
		p, ok := cfg.Profiles[pos[0]]
		if !ok {
			fmt.Fprintf(stderr, "headvpn: no profile %q\n", pos[0])
			return exitUsage
		}
		var r vpn.Result
		var err error
		if cmd == "connect" {
			var switched []string
			switched, err = vpn.SwitchFrom(ctx, cfg.Profiles, pos[0], deps)
			if err == nil {
				r, err = vpn.Connect(ctx, pos[0], p, deps)
			} else {
				r = vpn.Result{Profile: pos[0], Error: err.Error()}
			}
			r.SwitchedFrom = switched
		} else {
			r = vpn.Disconnect(ctx, pos[0], p, deps)
			if r.Error != "" {
				err = errors.New(r.Error)
			}
		}
		emit(stdout, *asJSON, r)
		switch {
		case err == nil:
			return exitOK
		case vpn.Rejected(err):
			return exitRejected
		case errors.Is(err, vpn.ErrLoginRequired):
			return exitLogin
		default:
			return exitError
		}
	}
	fmt.Fprint(stderr, usage)
	return exitUsage
}

func emit(w io.Writer, asJSON bool, rs ...vpn.Result) {
	if asJSON {
		enc := json.NewEncoder(w)
		if len(rs) == 1 {
			_ = enc.Encode(rs[0])
		} else {
			_ = enc.Encode(rs)
		}
		return
	}
	for _, r := range rs {
		line := r.Profile + "\t" + r.State
		if r.Already {
			line += "\t(already connected)"
		}
		if len(r.SwitchedFrom) > 0 {
			line += "\t(disconnected first: " + strings.Join(r.SwitchedFrom, ", ") + ")"
		}
		if r.Error != "" {
			line += "\terror: " + r.Error
		}
		fmt.Fprintln(w, line)
	}
}

// secretCmd stores a value in the OS keychain without it touching argv,
// the shell history or this process's output.
func secretCmd(pos []string, stdout, stderr io.Writer) int {
	if len(pos) != 2 || pos[0] != "set" {
		fmt.Fprintln(stderr, "usage: headvpn secret set <service>/<account>")
		return exitUsage
	}
	service, account, ok := strings.Cut(pos[1], "/")
	if !ok || service == "" || account == "" {
		fmt.Fprintln(stderr, "usage: headvpn secret set <service>/<account>")
		return exitUsage
	}
	argv := secret.StoreArgs(service, account)
	if argv == nil {
		fmt.Fprintln(stderr, "headvpn: no keychain support on this OS; use env: or cmd: references")
		return exitError
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, stdout, stderr
	if err := c.Run(); err != nil {
		fmt.Fprintln(stderr, "headvpn:", err)
		return exitError
	}
	fmt.Fprintf(stdout, "stored keychain:%s/%s\n", service, account)
	return exitOK
}

func promptTTY(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("%s: no terminal to prompt on", label)
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return strings.TrimSpace(string(b)), err
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}

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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/htmlform"
	"github.com/toolworksdev/headvpn/internal/secret"
	"github.com/toolworksdev/headvpn/internal/vpn"
	"github.com/toolworksdev/headvpn/internal/wafchallenge"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// currentVersion is the release version, or the module version when the
// binary came from `go install ...@vX.Y.Z`.
func currentVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

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
  headvpn waf-check <https-url>  (is an AWS WAF Challenge in the way? never prints the token)
  headvpn disconnect <profile>   [--json] [--config path]
  headvpn sso <name>             [--json] [--config path]
      runs ` + "`aws sso login`" + ` for the [sso-session] (or [profile]) <name> of
      ~/.aws/config and answers the browser half; <name> must have an
      [sso.<name>] table in the config
  headvpn kibana <name> <path>   [--body file|-] [--config path]
      logs in to the Kibana app of [kibana.<name>] with SAML and sends
      GET <path> (read only) through its console proxy; the Elasticsearch
      response goes to stdout. --body sends a JSON body (e.g. a _search query)
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
	bodyPath := fs.String("body", "", "kibana: JSON body file, or - for stdin")
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
		fmt.Fprintln(stdout, "headvpn", currentVersion())
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
	case "waf-check":
		// Diagnostic: does an AWS WAF Challenge stand in front of this URL,
		// and can the headless browser get past it? Sends no credentials and
		// never prints the token.
		if len(pos) != 1 {
			fmt.Fprintln(stderr, "usage: headvpn waf-check <https-url>")
			return exitUsage
		}
		if err := wafCheck(context.Background(), pos[0], stdout); err != nil {
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
		for _, n := range sortedKeys(cfg.SSO) {
			fmt.Fprintf(stdout, "%s\taws-sso\t%s\n", n, cfg.SSO[n].IdP)
		}
		for _, n := range sortedKeys(cfg.Kibana) {
			fmt.Fprintf(stdout, "%s\tkibana\t%s\n", n, cfg.Kibana[n].IdP)
		}
		return exitOK
	case "sso":
		if len(pos) != 1 {
			fmt.Fprintln(stderr, "usage: headvpn sso <name>")
			return exitUsage
		}
		s, ok := cfg.SSO[pos[0]]
		if !ok {
			fmt.Fprintf(stderr, "headvpn: no [sso.%s] in %s: only the logins listed there can be answered\n", pos[0], *cfgPath)
			return exitUsage
		}
		r, err := vpn.SSOLogin(ctx, pos[0], s, vpn.SSODeps{Deps: deps})
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(r)
		} else {
			line := r.Name + "\t" + r.State
			if r.Identity != "" {
				line += "\t" + r.Identity
			}
			if r.Error != "" {
				line += "\terror: " + r.Error
			}
			fmt.Fprintln(stdout, line)
		}
		switch {
		case err == nil:
			return exitOK
		case vpn.Rejected(err):
			return exitRejected
		default:
			return exitError
		}
	case "kibana":
		if len(pos) != 2 {
			fmt.Fprintln(stderr, "usage: headvpn kibana <name> <path> [--body file|-]")
			return exitUsage
		}
		k, ok := cfg.Kibana[pos[0]]
		if !ok {
			fmt.Fprintf(stderr, "headvpn: no [kibana.%s] in %s: only the apps listed there can be logged in to\n", pos[0], *cfgPath)
			return exitUsage
		}
		var body []byte
		if *bodyPath != "" {
			var err error
			if *bodyPath == "-" {
				body, err = io.ReadAll(os.Stdin)
			} else {
				body, err = os.ReadFile(*bodyPath)
			}
			if err != nil {
				fmt.Fprintln(stderr, "headvpn:", err)
				return exitUsage
			}
		}
		return kibanaGet(ctx, k, pos[1], body, deps, stdout, stderr)
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

func sortedKeys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}

func wafCheck(ctx context.Context, target string, w io.Writer) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("waf-check needs an https URL, got %q", target)
	}
	show := u.Host + u.Path
	get := func(c *http.Client) (*http.Response, *htmlform.Page, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "text/html")
		resp, err := c.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		page, err := htmlform.Parse(io.LimitReader(resp.Body, 4<<20))
		return resp, page, err
	}
	describe := func(label string, resp *http.Response, page *htmlform.Page) {
		var forms []string
		for _, f := range page.Forms {
			forms = append(forms, firstOr([]string{f.ID}, "?"))
		}
		end := resp.Request.URL
		fmt.Fprintf(w, "%s: GET %s -> %d at %s x-amzn-waf-action=%q title=%q forms=%v\n", label, show,
			resp.StatusCode, end.Host+end.Path, resp.Header.Get("x-amzn-waf-action"), page.Title, forms)
	}
	plain := &http.Client{Timeout: 30 * time.Second}
	resp, page, err := get(plain)
	if err != nil {
		return err
	}
	describe("without token", resp, page)
	if !wafchallenge.IsChallenge(resp) {
		fmt.Fprintln(w, "no WAF challenge for this URL from this address")
		return nil
	}
	start := time.Now()
	c := wafchallenge.Wrap(plain, &wafchallenge.Browser{}, &wafchallenge.Cache{})
	resp, page, err = get(c)
	if err != nil {
		return err
	}
	describe(fmt.Sprintf("with token (%.1fs)", time.Since(start).Seconds()), resp, page)
	return nil
}

package wafchallenge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func newJar() *cookiejar.Jar {
	j, _ := cookiejar.New(nil)
	return j
}

// Browser solves challenges with a headless Chromium-family browser driven
// over the DevTools protocol on a pipe (--remote-debugging-pipe): no port is
// opened and nothing beyond the standard library is needed.
type Browser struct {
	// Path to the browser executable; "" = HEADVPN_BROWSER or the first one
	// found among Chrome, Brave, Chromium and Edge.
	Path string
	// Timeout bounds one solve (default 45 s).
	Timeout time.Duration
}

// Candidates lists where browsers are looked for, in order.
func Candidates() []string {
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		var out []string
		for _, app := range []string{
			"Google Chrome.app/Contents/MacOS/Google Chrome",
			"Brave Browser.app/Contents/MacOS/Brave Browser",
			"Chromium.app/Contents/MacOS/Chromium",
			"Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		} {
			out = append(out, filepath.Join("/Applications", app), filepath.Join(home, "Applications", app))
		}
		return out
	}
	return []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge", "chrome"}
}

// Find returns the browser to use or an error naming what was tried.
func (b *Browser) Find() (string, error) {
	if b.Path != "" {
		return b.Path, nil
	}
	if p := os.Getenv("HEADVPN_BROWSER"); p != "" {
		return p, nil
	}
	for _, c := range Candidates() {
		if filepath.IsAbs(c) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no Chrome/Brave/Chromium/Edge found (set HEADVPN_BROWSER)")
}

// Solve loads page in a throwaway headless profile and waits until the
// challenge script sets the aws-waf-token cookie for its host.
func (b *Browser) Solve(ctx context.Context, page *url.URL) (Token, error) {
	exe, err := b.Find()
	if err != nil {
		return Token{}, err
	}
	timeout := b.Timeout
	if timeout == 0 {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "headvpn-waf-")
	if err != nil {
		return Token{}, err
	}
	defer os.RemoveAll(dir)

	// fd 3: commands to the browser; fd 4: answers from it.
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return Token{}, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		cmdR.Close()
		cmdW.Close()
		return Token{}, err
	}
	args := []string{
		"--headless=new", "--remote-debugging-pipe", "--user-data-dir=" + dir,
		"--no-first-run", "--no-default-browser-check", "--disable-extensions",
		"--disable-background-networking", "--disable-sync", "--disable-component-update",
		"--password-store=basic", "--use-mock-keychain", "about:blank",
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		args = append(args, "--no-sandbox")
	}
	// Extra flags for hosts that need them, e.g. --no-sandbox for an unpacked
	// Chrome on Ubuntu 23.10+ (AppArmor blocks its user-namespace sandbox).
	args = append(args, strings.Fields(os.Getenv("HEADVPN_BROWSER_FLAGS"))...)
	cmd := exec.Command(exe, args...)
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	stderr := &tail{}
	cmd.Stdout, cmd.Stderr = io.Discard, stderr
	if err := cmd.Start(); err != nil {
		cmdR.Close()
		cmdW.Close()
		outR.Close()
		outW.Close()
		return Token{}, fmt.Errorf("start %s: %w", filepath.Base(exe), err)
	}
	cmdR.Close()
	outW.Close()
	cdp := newCDP(cmdW, outR)
	defer func() {
		_, _ = cdp.call(context.Background(), "", "Browser.close", nil, 2*time.Second)
		cmdW.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		outR.Close()
	}()

	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := cdp.do(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &created); err != nil {
		if last := stderr.last(); last != "" {
			return Token{}, fmt.Errorf("%w (%s says: %s)", err, filepath.Base(exe), last)
		}
		return Token{}, err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := cdp.do(ctx, "", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil {
		return Token{}, err
	}
	// Look like the browser it is, not "HeadlessChrome".
	var ver struct {
		UserAgent string `json:"userAgent"`
	}
	if cdp.do(ctx, "", "Browser.getVersion", nil, &ver) == nil && ver.UserAgent != "" {
		ua := strings.Replace(ver.UserAgent, "HeadlessChrome", "Chrome", 1)
		_ = cdp.do(ctx, attached.SessionID, "Emulation.setUserAgentOverride", map[string]any{"userAgent": ua}, nil)
	}
	if err := cdp.do(ctx, attached.SessionID, "Page.navigate", map[string]any{"url": page.String()}, nil); err != nil {
		return Token{}, err
	}
	host := strings.ToLower(page.Hostname())
	for {
		var got struct {
			Cookies []struct {
				Name, Value, Domain string
				Expires             float64
			} `json:"cookies"`
		}
		if err := cdp.do(ctx, "", "Storage.getCookies", nil, &got); err != nil {
			return Token{}, err
		}
		for _, c := range got.Cookies {
			if c.Name == CookieName && c.Value != "" && domainMatch(host, c.Domain) {
				t := Token{Value: c.Value}
				if c.Expires > 0 {
					t.Expires = time.Unix(int64(c.Expires), 0)
				}
				return t, nil
			}
		}
		select {
		case <-ctx.Done():
			return Token{}, fmt.Errorf("no %s after %s in the headless browser", CookieName, timeout)
		case <-time.After(400 * time.Millisecond):
		}
	}
}

// tail keeps the first meaningful line the browser wrote to stderr.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.buf) < 8<<10 {
		t.buf = append(t.buf, p...)
	}
	return len(p), nil
}

func (t *tail) last() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range strings.Split(string(t.buf), "\n") {
		if strings.Contains(l, "FATAL") || strings.Contains(l, "ERROR") {
			if len(l) > 240 {
				l = l[:240] + "…"
			}
			return strings.TrimSpace(l)
		}
	}
	return ""
}

func domainMatch(host, domain string) bool {
	d := strings.TrimPrefix(strings.ToLower(domain), ".")
	return host == d || strings.HasSuffix(host, "."+d)
}

// cdp is a minimal DevTools protocol client over the pipe transport
// (JSON messages separated by NUL bytes).
type cdp struct {
	w io.Writer

	mu      sync.Mutex
	next    int
	waiting map[int]chan cdpMsg
	dead    chan struct{}
}

type cdpMsg struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func newCDP(w io.Writer, r io.Reader) *cdp {
	c := &cdp{w: w, waiting: map[int]chan cdpMsg{}, dead: make(chan struct{})}
	go func() {
		defer close(c.dead)
		br := bufio.NewReaderSize(r, 1<<20)
		for {
			b, err := br.ReadBytes(0)
			if err != nil {
				return
			}
			var m cdpMsg
			if json.Unmarshal(b[:len(b)-1], &m) != nil || m.ID == 0 {
				continue // events
			}
			c.mu.Lock()
			ch := c.waiting[m.ID]
			delete(c.waiting, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}()
	return c
}

func (c *cdp) do(ctx context.Context, session, method string, params any, out any) error {
	res, err := c.call(ctx, session, method, params, 0)
	if err != nil {
		return err
	}
	if out != nil && len(res) > 0 {
		return json.Unmarshal(res, out)
	}
	return nil
}

func (c *cdp) call(ctx context.Context, session, method string, params any, limit time.Duration) (json.RawMessage, error) {
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	c.mu.Lock()
	c.next++
	id := c.next
	ch := make(chan cdpMsg, 1)
	c.waiting[id] = ch
	c.mu.Unlock()
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if session != "" {
		msg["sessionId"] = session
	}
	b, _ := json.Marshal(msg)
	if _, err := c.w.Write(append(b, 0)); err != nil {
		return nil, fmt.Errorf("devtools %s: %w", method, err)
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, fmt.Errorf("devtools %s: %s", method, m.Error.Message)
		}
		return m.Result, nil
	case <-c.dead:
		return nil, fmt.Errorf("devtools %s: the browser closed the pipe", method)
	case <-ctx.Done():
		return nil, fmt.Errorf("devtools %s: %w", method, ctx.Err())
	}
}

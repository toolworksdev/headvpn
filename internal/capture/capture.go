// Package capture finds the SAML login URL that a VPN client handed to the
// default browser.
//
// Why: the AWS VPN Client 6.x CLI on macOS does not print the SAML URL and
// does not honour $BROWSER; it calls /usr/bin/open. Its daemon only answers
// callers signed by AWS (SecCode requirement on Team ID 94KV3E626L), so the
// URL cannot be asked for over its socket either. What remains observable is
// the browser history, which Chromium-family browsers write within seconds.
package capture

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound means no matching URL appeared before the deadline.
var ErrNotFound = errors.New("SAML login URL not found in browser history")

// chromiumEpoch converts Unix time to Chromium's microseconds since 1601-01-01.
func chromiumEpoch(t time.Time) int64 {
	return t.UnixMicro() + 11644473600*1_000_000
}

// HistoryFiles lists Chromium-family history databases under home.
func HistoryFiles(home string) []string {
	roots := []string{
		"Library/Application Support/BraveSoftware/Brave-Browser",
		"Library/Application Support/Google/Chrome",
		"Library/Application Support/Microsoft Edge",
		"Library/Application Support/Arc/User Data",
		"Library/Application Support/Chromium",
		".config/BraveSoftware/Brave-Browser",
		".config/google-chrome",
		".config/microsoft-edge",
		".config/chromium",
	}
	var out []string
	for _, r := range roots {
		for _, prof := range []string{"Default", "Profile *"} {
			m, _ := filepath.Glob(filepath.Join(home, r, prof, "History"))
			out = append(out, m...)
		}
	}
	return out
}

// Finder polls browser history for a URL that starts with Prefix and was
// visited at or after Since.
type Finder struct {
	Prefix string
	Since  time.Time
	Files  []string
	// Query is replaceable in tests; it returns matching URLs, newest first.
	Query func(ctx context.Context, db string, prefix string, since int64) ([]string, error)
}

// Wait polls until a URL appears or ctx expires.
func (f *Finder) Wait(ctx context.Context, every time.Duration) (string, error) {
	if len(f.Files) == 0 {
		return "", fmt.Errorf("%w: no Chromium-family browser history found (Brave, Chrome, Edge, Arc, Chromium)", ErrNotFound)
	}
	q := f.Query
	if q == nil {
		q = querySQLite
	}
	since := chromiumEpoch(f.Since)
	var lastErr error
	for {
		for _, db := range f.Files {
			urls, err := q(ctx, db, f.Prefix, since)
			if err != nil {
				lastErr = err
				continue
			}
			if len(urls) > 0 {
				return urls[0], nil
			}
		}
		select {
		case <-ctx.Done():
			if errors.Is(lastErr, fs.ErrPermission) {
				exe, _ := os.Executable()
				return "", fmt.Errorf("%w: macOS blocked reading the browser history (%v); grant Full Disk Access to %s in System Settings → Privacy & Security", ErrNotFound, lastErr, exe)
			}
			if lastErr != nil {
				return "", fmt.Errorf("%w (last error: %v)", ErrNotFound, lastErr)
			}
			return "", ErrNotFound
		case <-time.After(every):
		}
	}
}

// querySQLite copies the database (the browser keeps it locked) and asks the
// system sqlite3 for matching URLs.
func querySQLite(ctx context.Context, db, prefix string, since int64) ([]string, error) {
	tmp, err := os.MkdirTemp("", "headvpn-history-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	dst := filepath.Join(tmp, "History")
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(db + suffix)
		if err != nil {
			if suffix == "" {
				return nil, err
			}
			continue
		}
		if err := os.WriteFile(dst+suffix, b, 0o600); err != nil {
			return nil, err
		}
	}
	like := strings.ReplaceAll(prefix, "'", "''") + "%"
	sql := "select url from urls where url like '" + like + "' and last_visit_time >= " +
		strconv.FormatInt(since, 10) + " order by last_visit_time desc limit 1;"
	out, err := exec.CommandContext(ctx, "sqlite3", "-readonly", dst, sql).Output()
	if err != nil {
		return nil, fmt.Errorf("sqlite3 %s: %w", filepath.Base(filepath.Dir(db)), err)
	}
	var urls []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			urls = append(urls, l)
		}
	}
	return urls, nil
}

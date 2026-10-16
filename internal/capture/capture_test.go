package capture

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWaitReturnsFirstMatch(t *testing.T) {
	calls := 0
	f := &Finder{
		Prefix: "https://idp.example.com/realms/r/protocol/saml?SAMLRequest=",
		Since:  time.Unix(1000, 0),
		Files:  []string{"a", "b"},
		Query: func(ctx context.Context, db, prefix string, since int64) ([]string, error) {
			calls++
			if since != chromiumEpoch(time.Unix(1000, 0)) {
				t.Fatalf("since=%d", since)
			}
			if db == "b" && calls > 2 {
				return []string{prefix + "abc"}, nil
			}
			return nil, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	u, err := f.Wait(ctx, 10*time.Millisecond)
	if err != nil || u != f.Prefix+"abc" {
		t.Fatalf("got %q, %v", u, err)
	}
}

func TestWaitTimesOutWithoutFiles(t *testing.T) {
	f := &Finder{Prefix: "x"}
	if _, err := f.Wait(context.Background(), time.Millisecond); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestWaitTimesOut(t *testing.T) {
	f := &Finder{Prefix: "x", Files: []string{"a"},
		Query: func(context.Context, string, string, int64) ([]string, error) { return nil, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := f.Wait(ctx, 10*time.Millisecond); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

// Real sqlite3 against a Chromium-shaped table: the prefix and the time
// filter both have to bite.
func TestQuerySQLiteAgainstChromiumSchema(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 not installed")
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "History")
	since := chromiumEpoch(time.Unix(2000, 0))
	stmts := "create table urls(id integer primary key, url text, last_visit_time integer);" +
		"insert into urls(url,last_visit_time) values" +
		"('https://idp.example.com/realms/r/protocol/saml?SAMLRequest=OLD'," + itoa(since-1) + ")," +
		"('https://evil.example.com/realms/r/protocol/saml?SAMLRequest=EVIL'," + itoa(since+5) + ")," +
		"('https://idp.example.com/realms/r/protocol/saml?SAMLRequest=NEW'," + itoa(since+1) + ");"
	if out, err := exec.Command("sqlite3", db, stmts).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	urls, err := querySQLite(context.Background(), db, "https://idp.example.com/realms/r/protocol/saml?SAMLRequest=", since)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || urls[0] != "https://idp.example.com/realms/r/protocol/saml?SAMLRequest=NEW" {
		t.Fatalf("got %v", urls)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestPermissionDeniedSaysWhatToGrant(t *testing.T) {
	f := &Finder{Prefix: "x", Files: []string{"a"},
		Query: func(context.Context, string, string, int64) ([]string, error) {
			return nil, &fs.PathError{Op: "open", Path: "History", Err: fs.ErrPermission}
		}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := f.Wait(ctx, 5*time.Millisecond)
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "Full Disk Access") {
		t.Fatalf("got %v", err)
	}
}

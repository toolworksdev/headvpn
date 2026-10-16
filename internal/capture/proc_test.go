package capture

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const origin = "https://idp.example.com"
const samlURL = origin + "/realms/r/protocol/saml?SAMLRequest=abc"

// scripted returns the process table one scan at a time.
func scripted(scans ...[]Process) func(context.Context) ([]Process, error) {
	i := 0
	return func(context.Context) ([]Process, error) {
		s := scans[min(i, len(scans)-1)]
		i++
		return s, nil
	}
}

var cli = Process{UID: 501, PID: 100, PPID: 1, Args: "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/MacOS/aws-vpn-client connect --profile-name work"}

func watcher(list func(context.Context) ([]Process, error)) *ProcWatcher {
	return &ProcWatcher{Origin: origin, Parent: "aws-vpn-client", List: list, UID: 501}
}

func wait(t *testing.T, w *ProcWatcher) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	return w.Wait(ctx, time.Millisecond)
}

func TestCatchesOpenLaunchedByTheClient(t *testing.T) {
	open := Process{UID: 501, PID: 101, PPID: 100, Args: "/usr/bin/open " + samlURL}
	u, err := wait(t, watcher(scripted([]Process{cli}, []Process{cli, open})))
	if err != nil || u != samlURL {
		t.Fatalf("got %q, %v", u, err)
	}
}

func TestIgnoresWhatExistedBeforeTheRun(t *testing.T) {
	stale := Process{UID: 501, PID: 90, PPID: 100, Args: "/usr/bin/open " + samlURL}
	if _, err := wait(t, watcher(scripted([]Process{cli, stale}))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("accepted a process from before the run: %v", err)
	}
}

func TestRejectsLookalikes(t *testing.T) {
	cases := map[string]Process{
		"other user":                       {UID: 502, PID: 101, PPID: 100, Args: "/usr/bin/open " + samlURL},
		"other parent":                     {UID: 501, PID: 101, PPID: 1, Args: "/usr/bin/open " + samlURL},
		"other origin":                     {UID: 501, PID: 101, PPID: 100, Args: "/usr/bin/open https://evil.example.com/realms/r/protocol/saml?SAMLRequest=abc"},
		"origin as prefix of another host": {UID: 501, PID: 101, PPID: 100, Args: "/usr/bin/open https://idp.example.com.evil.io/x?SAMLRequest=abc"},
		"not open":                         {UID: 501, PID: 101, PPID: 100, Args: "/usr/bin/curl " + samlURL},
		"no SAML":                          {UID: 501, PID: 101, PPID: 100, Args: "/usr/bin/open " + origin + "/realms/r/account"},
	}
	for name, p := range cases {
		if u, err := wait(t, watcher(scripted([]Process{cli}, []Process{cli, p}))); err == nil {
			t.Errorf("%s: accepted %q", name, u)
		}
	}
}

func TestFirstReturnsTheWinnerAndReportsAllFailures(t *testing.T) {
	slow := func(ctx context.Context) (string, error) { <-ctx.Done(); return "", ctx.Err() }
	fast := func(context.Context) (string, error) { return samlURL, nil }
	u, err := First(context.Background(), slow, fast)
	if err != nil || u != samlURL {
		t.Fatalf("got %q, %v", u, err)
	}
	a := func(context.Context) (string, error) { return "", errors.New("history: denied") }
	b := func(context.Context) (string, error) { return "", errors.New("ps: nothing") }
	_, err = First(context.Background(), a, b)
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "denied") || !strings.Contains(err.Error(), "nothing") {
		t.Fatalf("got %v", err)
	}
}

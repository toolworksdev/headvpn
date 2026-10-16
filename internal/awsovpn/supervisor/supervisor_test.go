//go:build linux

package supervisor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/toolworksdev/headvpn/internal/awsovpn/awsclient"
)

const testSAML = "PHNhbWxwOlJlc3BvbnNlPjwvc2FtbHA6UmVzcG9uc2U+"

// The test binary doubles as a fake acvc-openvpn: Install.Dir points at a
// symlink to it, and it recognizes the OpenVPN command line.
func TestMain(m *testing.M) {
	if slices.Contains(os.Args, "--management-query-passwords") {
		os.Exit(fakeOpenVPN(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeOpenVPN speaks just enough of the management protocol to run the AWS
// SAML exchange. The profile selects a scenario via "# scenario: <name>".
func fakeOpenVPN(args []string) int {
	var sock, cfg string
	for i, a := range args {
		switch a {
		case "--management":
			sock = args[i+1]
		case "--config":
			cfg = args[i+1]
		}
	}
	conf, _ := os.ReadFile(cfg)
	scenario := ""
	if _, s, ok := strings.Cut(string(conf), "# scenario: "); ok {
		scenario, _, _ = strings.Cut(s, "\n")
	}
	if scenario == "bad-options" {
		fmt.Println("Options error: Unrecognized option or missing or extra parameter(s) in x.ovpn:1: bogus (2.6.12)")
		fmt.Println("Use --help for more information.")
		return 1
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return 1
	}
	defer l.Close()
	c, err := l.Accept()
	if err != nil {
		return 1
	}
	w := func(s string) { fmt.Fprint(c, s+"\r\n") }
	w(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	w(">HOLD:Waiting for hold release:0")
	needAuth := ">PASSWORD:Need 'Auth' username/password"

	round, released := 0, false
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "hold release" && !released:
			released = true
			w("SUCCESS: hold release succeeded")
			w(needAuth)
		case strings.HasPrefix(line, `password "Auth" `):
			pw, _ := strconv.Unquote(strings.TrimPrefix(line, `password "Auth" `))
			w("SUCCESS: 'Auth' password entered, but not yet verified")
			switch {
			case pw == "ACS::35001":
				round++
				w(">STATE:1,AUTH,,,,,,")
				w(fmt.Sprintf(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:sid%d:b'Ti9B':%s/realms/r/protocol/saml?SAMLRequest=x']", round, originFromConf(conf)))
				w(">STATE:1,RECONNECTING,auth-failure,,,,,")
				w(needAuth)
			case pw == fmt.Sprintf("CRV1::sid%d::%s", round, url.QueryEscape(testSAML)):
				w(">STATE:2,CONNECTED,SUCCESS,10.0.0.5,203.0.113.10,443,,")
				if scenario == "ping-restart" && round == 1 {
					w(">STATE:3,RECONNECTING,ping-restart,,,,,")
					w(needAuth)
				}
			default:
				w(">PASSWORD:Verification Failed: 'Auth' ['Invalid username or password']")
				w(needAuth)
			}
		case line == "signal SIGTERM":
			w(">STATE:4,EXITING,SIGTERM,,,,,")
			return 0
		default:
			w("SUCCESS: ok")
		}
	}
	return 1
}

func originFromConf(conf []byte) string {
	_, s, _ := strings.Cut(string(conf), "# origin: ")
	o, _, _ := strings.Cut(s, "\n")
	return o
}

func newTestSupervisor(t *testing.T, scenario string, logins *atomic.Int32) (*Supervisor, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.Symlink(self, filepath.Join(dir, "acvc-openvpn"))
	runDir, err := os.MkdirTemp("", "hvpn") // short path: unix socket paths are limited to 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runDir) })
	origin := "https://keycloak.example.com"
	return New(Config{
		Profile:       "test",
		OVPN:          []byte("client\n# scenario: " + scenario + "\n# origin: " + origin + "\n"),
		Directives:    []string{"client"},
		IdPOrigin:     origin,
		Install:       awsclient.Install{Dir: dir},
		ClientVersion: "5.3.2",
		Platform:      "ubuntu",
		RunDir:        runDir,
		Login: func(ctx context.Context, u *url.URL) (string, error) {
			if u.Host != "keycloak.example.com" || u.Query().Get("SAMLRequest") != "x" {
				return "", fmt.Errorf("unexpected login URL %s", u)
			}
			logins.Add(1)
			return testSAML, nil
		},
	}), runDir
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func connected(runDir string) func() bool {
	return func() bool {
		st, err := ReadStatus(runDir)
		return err == nil && st.State == "CONNECTED" && st.TunnelIP == "10.0.0.5"
	}
}

func TestSessionConnectAndDisconnect(t *testing.T) {
	var logins atomic.Int32
	s, runDir := newTestSupervisor(t, "basic", &logins)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()

	waitFor(t, "CONNECTED", connected(runDir))
	if logins.Load() != 1 {
		t.Fatalf("logins = %d", logins.Load())
	}
	if fi, err := os.Stat(filepath.Join(runDir, "private")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("private dir: %v %v", fi, err)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := ReadStatus(runDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("status not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "private")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("private dir not removed: %v", err)
	}
}

func TestSessionReauthAfterPingRestart(t *testing.T) {
	var logins atomic.Int32
	s, runDir := newTestSupervisor(t, "ping-restart", &logins)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()

	waitFor(t, "second login", func() bool { return logins.Load() == 2 })
	waitFor(t, "CONNECTED again", connected(runDir))
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestSessionBadOptionsIsPermanent(t *testing.T) {
	var logins atomic.Int32
	s, _ := newTestSupervisor(t, "bad-options", &logins)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "Options error") {
		t.Fatalf("err = %v", err)
	}
}

func TestLock(t *testing.T) {
	dir := t.TempDir()
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second lock: %v", err)
	}
	release()
	release2, err := Lock(dir)
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	release2()
}

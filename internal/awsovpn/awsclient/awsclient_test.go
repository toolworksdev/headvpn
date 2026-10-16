//go:build linux

package awsclient

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const realDir = "/opt/awsvpnclient/Service/Resources/openvpn"

func TestArgsMatchAWSService(t *testing.T) {
	in := Install{Dir: realDir}
	args := in.Args(Options{
		Config: "/run/headvpn/private/work.ovpn", Socket: "/run/headvpn/private/mgmt.sock",
		Directives: []string{"client", "dev", "ca"}, ClientVersion: "5.3.2", Platform: "ubuntu",
		LANCIDRs: []string{"198.51.100.0/24", "172.17.0.0/16"},
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--config /run/headvpn/private/work.ovpn",
		"--management /run/headvpn/private/mgmt.sock unix",
		"--management-query-passwords --management-hold",
		"--auth-retry interact",
		"--connect-retry 5 5 --connect-timeout 5 --disable-dco --push-peer-info",
		"--setenv UV_AWS_CLIENT_APP_VER 5.3.2 --setenv UV_AWS_CLIENT_PLATFORM ubuntu",
		"--setenv UV_AWS_CLIENT_LAN_CIDRS 198.51.100.0/24,172.17.0.0/16",
		"--setenv UV_AWS_CLIENT_OVPN_FLAGS client,dev,ca",
		"--up " + realDir + "/configure-dns --down " + realDir + "/configure-dns --up-restart --down-pre --script-security 2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q\n%s", want, joined)
		}
	}
	// --config must come first so later options override the profile.
	if args[0] != "--config" {
		t.Errorf("first arg = %s", args[0])
	}
	noLAN := strings.Join(in.Args(Options{}), " ")
	if strings.Contains(noLAN, "UV_AWS_CLIENT_LAN_CIDRS") {
		t.Error("empty LAN CIDRs should not be sent")
	}
}

func TestCommandEnvAndDir(t *testing.T) {
	in := Install{Dir: realDir}
	cmd := in.Command(Options{FIPS: true})
	if cmd.Dir != realDir {
		t.Errorf("Dir = %s (the relative ELF interpreter needs cwd = install dir)", cmd.Dir)
	}
	if !slices.Contains(cmd.Env, "OPENSSL_CONF="+realDir+"/openssl.cnf") || len(cmd.Env) != 3 {
		t.Errorf("env = %v", cmd.Env)
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Error("openvpn must run in its own process group")
	}
	if cmd := in.Command(Options{}); len(cmd.Env) != 1 {
		t.Errorf("non-FIPS env = %v", cmd.Env)
	}
}

func TestCheckRejectsUserOwnedInstall(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{binaryName, dnsScriptName} {
		os.WriteFile(filepath.Join(dir, f), []byte("#!/bin/sh\n"), 0o755)
	}
	err := Install{Dir: dir}.Check()
	if os.Geteuid() != 0 && (err == nil || !strings.Contains(err.Error(), "not owned by root")) {
		t.Errorf("user-owned install accepted: %v", err)
	}
	if err := (Install{Dir: filepath.Join(dir, "missing")}).Check(); err == nil {
		t.Error("missing install accepted")
	}
}

func TestRealInstall(t *testing.T) {
	in := Install{Dir: realDir}
	if _, err := os.Stat(in.Binary()); err != nil {
		t.Skip("AWS VPN Client not installed")
	}
	if err := in.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	v, err := in.Version(context.Background())
	if err != nil || !strings.HasPrefix(v, "OpenVPN 2.6") {
		t.Fatalf("Version = %q, %v", v, err)
	}
	t.Logf("%s; awsvpnclient %s; LAN %v", v, ClientVersion(context.Background()), LANCIDRs())
}

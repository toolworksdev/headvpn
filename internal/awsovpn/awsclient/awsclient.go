//go:build linux

// Package awsclient runs the OpenVPN build bundled with the AWS VPN Client
// (acvc-openvpn) the same way the AWS VPN Client service does.
//
// acvc-openvpn is OpenVPN 2.6 patched by AWS to accept the large CRV1
// password that carries the SAML assertion. It is linked against a bundled
// musl whose ELF interpreter path is relative, so it must be started with
// its own directory as working directory.
package awsclient

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	binaryName    = "acvc-openvpn"
	dnsScriptName = "configure-dns"
	// Reported when the awsvpnclient package version cannot be determined.
	fallbackClientVersion = "5.3.2"
)

type Install struct {
	Dir string
}

func (in Install) Binary() string    { return filepath.Join(in.Dir, binaryName) }
func (in Install) DNSScript() string { return filepath.Join(in.Dir, dnsScriptName) }

// Check makes sure the binary and DNS script exist and that neither they nor
// any parent directory can be modified by non-root users: they run as root.
func (in Install) Check() error {
	for _, p := range []string{in.Binary(), in.DNSScript()} {
		st, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("AWS VPN Client not found (%w); install the awsvpnclient package or set aws_openvpn_dir", err)
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%s is not an executable file", p)
		}
	}
	for _, p := range []string{in.Binary(), in.DNSScript(), in.Dir} {
		for d := p; ; d = filepath.Dir(d) {
			if err := rootOwned(d); err != nil {
				return err
			}
			if d == "/" || d == "." {
				break
			}
		}
	}
	return nil
}

func rootOwned(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys := st.Sys().(*syscall.Stat_t)
	if sys.Uid != 0 {
		return fmt.Errorf("refusing to run as root: %s is not owned by root", path)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	// The awsvpnclient package installs its directories 0775 root:root,
	// so group write is fine as long as the group is root.
	perm := st.Mode().Perm()
	if perm&0o002 != 0 && st.Mode()&os.ModeSticky == 0 || perm&0o020 != 0 && sys.Gid != 0 {
		return fmt.Errorf("refusing to run as root: %s is writable by non-root users", path)
	}
	return nil
}

// Version returns the first line of "acvc-openvpn --version".
func (in Install) Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, in.Binary(), "--version")
	cmd.Dir = in.Dir
	out, _ := cmd.CombinedOutput() // --version exits non-zero
	line, _, _ := strings.Cut(string(out), "\n")
	if !strings.HasPrefix(line, "OpenVPN ") {
		return "", fmt.Errorf("%s --version: unexpected output %q", in.Binary(), strings.TrimSpace(string(out)))
	}
	return line, nil
}

// ClientVersion returns the installed awsvpnclient package version.
func ClientVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", "awsvpnclient").Output()
	if v := strings.TrimSpace(string(out)); err == nil && v != "" {
		return v
	}
	return fallbackClientVersion
}

// LANCIDRs lists the IPv4 networks of interfaces that are up and have a
// carrier, which the AWS client reports to the endpoint as
// UV_AWS_CLIENT_LAN_CIDRS. Idle docker bridges are skipped, as it does.
func LANCIDRs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cidrs []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagRunning == 0 || ifc.Flags&net.FlagLoopback != 0 || strings.HasPrefix(ifc.Name, "tun") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			n := (&net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}).String()
			if !slices.Contains(cidrs, n) {
				cidrs = append(cidrs, n)
			}
		}
	}
	return cidrs
}

// Running returns the PIDs of running acvc-openvpn processes (the AWS VPN
// Client GUI kills them all when it connects, so we must not run alongside).
func Running() []int {
	entries, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range entries {
		var pid int
		if _, err := fmt.Sscan(e.Name(), &pid); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err == nil && strings.TrimSpace(string(comm)) == binaryName {
			pids = append(pids, pid)
		}
	}
	return pids
}

type Options struct {
	Config        string   // .ovpn copy (absolute path)
	Socket        string   // management unix socket (absolute path)
	Directives    []string // directive names in the profile
	ClientVersion string
	Platform      string
	LANCIDRs      []string
	FIPS          bool
}

// Args mirrors the AWS VPN Client service's command line, except that the
// management interface is a root-only unix socket instead of TCP 8096.
func (in Install) Args(o Options) []string {
	args := []string{
		"--config", o.Config,
		"--management", o.Socket, "unix",
		"--management-query-passwords",
		"--management-hold",
		"--auth-retry", "interact",
		"--auth-nocache",
		"--connect-retry", "5", "5",
		"--connect-timeout", "5",
		"--disable-dco",
		"--push-peer-info",
		"--setenv", "UV_AWS_CLIENT_APP_VER", o.ClientVersion,
		"--setenv", "UV_AWS_CLIENT_PLATFORM", o.Platform,
	}
	if len(o.LANCIDRs) > 0 {
		args = append(args, "--setenv", "UV_AWS_CLIENT_LAN_CIDRS", strings.Join(o.LANCIDRs, ","))
	}
	return append(args,
		"--setenv", "UV_AWS_CLIENT_OVPN_FLAGS", strings.Join(o.Directives, ","),
		"--up", in.DNSScript(),
		"--down", in.DNSScript(),
		"--up-restart",
		"--down-pre",
		"--script-security", "2",
		// Windows-only option the endpoint pushes; on Linux it only logs an error.
		"--pull-filter", "ignore", "block-outside-dns",
	)
}

func (in Install) Command(o Options) *exec.Cmd {
	cmd := exec.Command(in.Binary(), in.Args(o)...)
	cmd.Dir = in.Dir
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if o.FIPS {
		cmd.Env = append(cmd.Env,
			"OPENSSL_CONF="+filepath.Join(in.Dir, "openssl.cnf"),
			"OPENSSL_MODULES="+in.Dir,
		)
	}
	// Own process group: terminal signals go to headvpn, which shuts OpenVPN
	// down over the management interface so routes and DNS are restored.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	return cmd
}

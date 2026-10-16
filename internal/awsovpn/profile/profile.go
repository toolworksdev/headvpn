// Package profile parses and vets AWS Client VPN .ovpn profiles.
//
// headvpn runs OpenVPN as root, so a profile is code: directives such as "up",
// "plugin" or "tls-verify" would let a crafted .ovpn run anything. Only the
// directives an AWS Client VPN client profile needs are accepted.
package profile

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

type Directive struct {
	Name   string
	Args   []string
	Inline bool // <name>...</name> block
}

type Profile struct {
	Directives []Directive
}

func Parse(data []byte) (*Profile, error) {
	p := &Profile{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	inline := ""
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if inline != "" {
			if line == "</"+inline+">" {
				inline = ""
			}
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			inline = line[1 : len(line)-1]
			p.Directives = append(p.Directives, Directive{Name: inline, Inline: true})
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "--"))
		p.Directives = append(p.Directives, Directive{Name: f[0], Args: f[1:]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if inline != "" {
		return nil, fmt.Errorf("unterminated <%s> block", inline)
	}
	return p, nil
}

// Names returns directive names in file order without duplicates, the format
// the AWS client reports in UV_AWS_CLIENT_OVPN_FLAGS.
func (p *Profile) Names() []string {
	var names []string
	for _, d := range p.Directives {
		if !slices.Contains(names, d.Name) {
			names = append(names, d.Name)
		}
	}
	return names
}

func (p *Profile) Has(name string) bool {
	return slices.ContainsFunc(p.Directives, func(d Directive) bool { return d.Name == name })
}

var allowed = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`
		client tls-client pull dev dev-type proto remote remote-random-hostname remote-random
		resolv-retry nobind persist-key persist-tun float topology
		remote-cert-tls remote-cert-eku remote-cert-ku verify-x509-name ns-cert-type
		cipher data-ciphers data-ciphers-fallback ncp-ciphers auth
		tls-version-min tls-version-max tls-cipher tls-ciphersuites tls-groups key-direction
		ca cert key tls-auth tls-crypt tls-crypt-v2 extra-certs
		verb mute mute-replay-warnings
		auth-user-pass auth-retry auth-nocache static-challenge
		reneg-sec reneg-bytes reneg-pkts hand-window tran-window
		tun-mtu link-mtu mssfix fragment sndbuf rcvbuf txqueuelen
		ping ping-restart ping-exit keepalive inactive
		connect-retry connect-retry-max connect-timeout server-poll-timeout explicit-exit-notify
		pull-filter route route-ipv6 route-nopull route-metric route-delay redirect-gateway
		block-outside-dns dhcp-option compress comp-lzo allow-compression push-peer-info`) {
		allowed[n] = true
	}
}

var directiveName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// Validate checks that the profile only uses allowed directives and is a
// SAML profile (auth-user-pass with no file, so credentials come from the
// management interface).
func (p *Profile) Validate() error {
	var bad []string
	other := 0
	for _, d := range p.Directives {
		if allowed[d.Name] {
			continue
		}
		// Only echo names that look like OpenVPN directives: the text of a
		// file that is not a profile (a password hash, a key) must never end
		// up in an error message.
		if !directiveName.MatchString(d.Name) {
			other++
			continue
		}
		if !slices.Contains(bad, d.Name) {
			bad = append(bad, d.Name)
		}
	}
	if other > 0 {
		bad = append(bad, fmt.Sprintf("%d line(s) that are not OpenVPN directives", other))
	}
	if len(bad) > 0 {
		return fmt.Errorf("profile uses directives headvpn does not allow (it runs OpenVPN as root): %s", strings.Join(bad, ", "))
	}
	if !p.Has("remote") {
		return fmt.Errorf("profile has no remote")
	}
	for _, d := range p.Directives {
		if d.Name == "auth-user-pass" {
			if len(d.Args) > 0 && !d.Inline {
				return fmt.Errorf("auth-user-pass must not reference a file in a SAML profile")
			}
			return nil
		}
	}
	return fmt.Errorf("profile has no auth-user-pass: not a federated (SAML) AWS Client VPN profile")
}

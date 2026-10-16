// Package config reads ~/.config/headvpn/config.toml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Profile is one VPN the tool can bring up.
type Profile struct {
	// Backend: "aws-official" (AWS VPN Client 6.x on macOS) or "aws-openvpn"
	// (the OpenVPN shipped with AWS VPN Client 5.x for Linux).
	Backend string `toml:"backend"`
	// AWSProfile is the profile name inside the AWS VPN Client (aws-official).
	AWSProfile string `toml:"aws_profile"`
	// AWSCLI overrides the path to the aws-vpn-client CLI (aws-official).
	AWSCLI string `toml:"aws_cli"`

	// OVPN is the client profile exported from AWS (aws-openvpn).
	OVPN string `toml:"ovpn"`
	// AWSOpenVPNDir holds acvc-openvpn and configure-dns (aws-openvpn).
	AWSOpenVPNDir string `toml:"aws_openvpn_dir"`
	// Platform is reported to the endpoint as UV_AWS_CLIENT_PLATFORM.
	Platform string `toml:"platform"`
	// ClientVersion is reported as UV_AWS_CLIENT_APP_VER (default: installed package).
	ClientVersion string `toml:"client_version"`
	// FIPS loads AWS's bundled OpenSSL FIPS configuration, like the GUI (default true).
	FIPS *bool `toml:"fips"`

	// PritunlProfile is the profile id or exact name in `pritunl-client list` (pritunl).
	PritunlProfile string `toml:"pritunl_profile"`
	// PritunlCLI overrides the path to pritunl-client (pritunl).
	PritunlCLI string `toml:"pritunl_cli"`
	// PritunlMode is "ovpn" or "wg"; empty lets the client decide (pritunl).
	PritunlMode string `toml:"pritunl_mode"`

	// IdP: "keycloak", "entra" (pritunl only), or empty (pritunl only: the
	// login URL is handed to a person).
	IdP       string `toml:"idp"`
	IdPOrigin string `toml:"idp_origin"`
	Username  string `toml:"username"`
	// Secret references (keychain:, env:, cmd:, prompt:). Never literal values.
	Password   string `toml:"password"`
	TOTPSecret string `toml:"totp_secret"`
	// OTP is an alternative to TOTPSecret, e.g. "prompt:" to type the code.
	OTP string `toml:"otp"`

	ConnectTimeout duration `toml:"connect_timeout"`

	// Exclusive (default true): connecting this profile first disconnects
	// any other connected profile. Two profiles stay up together only when
	// both set exclusive = false.
	Exclusive *bool `toml:"exclusive"`
}

// IsExclusive reports whether the profile may not share the machine with
// another connected profile.
func (p Profile) IsExclusive() bool { return p.Exclusive == nil || *p.Exclusive }

type duration struct{ time.Duration }

func (d *duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	d.Duration = v
	return err
}

// Timeout returns the connect timeout or a default.
func (p Profile) Timeout() time.Duration {
	if p.ConnectTimeout.Duration > 0 {
		return p.ConnectTimeout.Duration
	}
	return 2 * time.Minute
}

// Config is the whole file.
type Config struct {
	Profiles map[string]Profile `toml:"profiles"`
}

// DefaultPath is $XDG_CONFIG_HOME/headvpn/config.toml or ~/.config/headvpn/config.toml.
func DefaultPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "headvpn", "config.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "headvpn", "config.toml")
}

// Load reads and validates the file.
func Load(path string) (*Config, error) {
	var c Config
	if err := checkPerm(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no config at %s (see README: Configuration)", path)
		}
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", path, und)
	}
	for name, p := range c.Profiles {
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
	}
	return &c, nil
}

// UseFIPS reports whether AWS's FIPS OpenSSL configuration is loaded.
func (p Profile) UseFIPS() bool { return p.FIPS == nil || *p.FIPS }

// Names returns the profile names, sorted.
func (c *Config) Names() []string {
	var n []string
	for k := range c.Profiles {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func (p Profile) validate() error {
	switch p.Backend {
	case "aws-official":
		if p.AWSProfile == "" {
			return errors.New("aws_profile is required")
		}
	case "aws-openvpn":
		if !strings.HasPrefix(p.OVPN, "/") { // a Linux path, whatever OS validates the file
			return errors.New("ovpn must be the absolute path of the client profile exported from AWS")
		}
		if p.OTP == "prompt:" {
			return errors.New("aws-openvpn runs in the background: otp = \"prompt:\" cannot be answered; use totp_secret")
		}
	case "pritunl":
		if p.PritunlProfile == "" {
			return errors.New("pritunl_profile is required (id or name from `pritunl-client list`)")
		}
		if p.PritunlMode != "" && p.PritunlMode != "ovpn" && p.PritunlMode != "wg" {
			return fmt.Errorf("pritunl_mode %q must be ovpn or wg", p.PritunlMode)
		}
	case "":
		return errors.New("backend is required")
	default:
		return fmt.Errorf("unknown backend %q", p.Backend)
	}
	switch p.IdP {
	case "":
		if p.Backend != "pritunl" {
			return errors.New("idp is required")
		}
	case "entra":
		if p.Backend != "pritunl" {
			return errors.New("idp entra is supported with backend pritunl only")
		}
		if p.Username == "" || p.Password == "" {
			return errors.New("entra needs username and password")
		}
		if p.TOTPSecret == "" && p.OTP == "" {
			return errors.New("entra needs totp_secret or otp (only verification codes can be answered)")
		}
		if p.TOTPSecret != "" && p.OTP != "" {
			return errors.New("set totp_secret or otp, not both")
		}
	case "keycloak":
		if p.IdPOrigin == "" || p.Username == "" || p.Password == "" {
			return errors.New("keycloak needs idp_origin, username and password")
		}
		if p.TOTPSecret != "" && p.OTP != "" {
			return errors.New("set totp_secret or otp, not both")
		}
	default:
		return fmt.Errorf("unknown idp %q", p.IdP)
	}
	return nil
}

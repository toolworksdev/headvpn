//go:build !linux

package vpn

import (
	"context"
	"errors"
	"io"

	"github.com/toolworksdev/headvpn/internal/config"
)

var errOpenVPNLinuxOnly = errors.New("the aws-openvpn backend runs on Linux only")

func openvpnStatus(name string) (string, error) { return "", errOpenVPNLinuxOnly }

func openvpnConnect(ctx context.Context, name string, p config.Profile, d Deps, cfgPath string) (Result, error) {
	return result(name, "", errOpenVPNLinuxOnly), errOpenVPNLinuxOnly
}

func openvpnDisconnect(ctx context.Context, name, cfgPath string) (string, error) {
	return "", errOpenVPNLinuxOnly
}

// Stop is only meaningful on Linux.
func Stop(ctx context.Context) error { return errOpenVPNLinuxOnly }

// Supervise is only meaningful on Linux.
func Supervise(name string, stdin io.Reader) error { return errOpenVPNLinuxOnly }

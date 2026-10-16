//go:build !darwin && !linux

package secret

import (
	"context"
	"errors"
)

var errNoKeychain = errors.New("keychain: references are not supported on this OS yet (use env: or cmd: instead)")

func (r *Resolver) keychain(ctx context.Context, service, account string) (string, error) {
	return "", errNoKeychain
}

// StoreArgs is not available on this OS.
func StoreArgs(service, account string) []string { return nil }

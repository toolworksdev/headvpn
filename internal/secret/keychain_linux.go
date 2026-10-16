//go:build linux

package secret

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// keychain reads from the Secret Service (GNOME Keyring, KWallet) through
// `secret-tool`, using the attributes service=<service> account=<account>.
func (r *Resolver) keychain(ctx context.Context, service, account string) (string, error) {
	out, err := r.run(ctx, "secret-tool", "lookup", "service", service, "account", account)
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 && len(out) == 0 {
		// secret-tool says nothing and exits 1 when no item matches.
		return "", fmt.Errorf("keychain %s/%s: %w", service, account, ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("keychain %s/%s (secret-tool): %w", service, account, err)
	}
	v := strings.TrimRight(string(out), "\r\n")
	if v == "" {
		return "", fmt.Errorf("keychain %s/%s: %w", service, account, ErrNotFound)
	}
	return v, nil
}

// StoreArgs returns the interactive command that stores an item.
func StoreArgs(service, account string) []string {
	return []string{"secret-tool", "store", "--label", service + "/" + account, "service", service, "account", account}
}

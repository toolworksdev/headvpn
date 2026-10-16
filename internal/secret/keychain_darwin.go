//go:build darwin

package secret

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// keychain reads a generic password from the login keychain with the system
// `security` tool.
//
// Limitation: the item's access list sees `/usr/bin/security` as the reader,
// so any process running as the same user can read the same item. Restricting
// it to this binary needs the native Security framework (cgo) — not done yet.
func (r *Resolver) keychain(ctx context.Context, service, account string) (string, error) {
	out, err := r.run(ctx, "/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w")
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 44 {
			return "", fmt.Errorf("keychain %s/%s: %w", service, account, ErrNotFound)
		}
		return "", fmt.Errorf("keychain %s/%s: %w", service, account, err)
	}
	v := strings.TrimRight(string(out), "\r\n")
	if v == "" {
		return "", fmt.Errorf("keychain %s/%s: %w", service, account, ErrNotFound)
	}
	return v, nil
}

// StoreArgs returns the command that stores a keychain item interactively:
// `security ... -w` with no value prompts twice on the terminal, so the value
// never appears in argv or shell history.
func StoreArgs(service, account string) []string {
	return []string{"/usr/bin/security", "add-generic-password", "-U", "-s", service, "-a", account, "-w"}
}

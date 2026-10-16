// Package secret resolves secret references from the config file.
//
// A config file never holds a secret value. It holds a reference:
//
//	keychain:<service>/<account>   OS keychain (macOS Keychain, Linux Secret Service)
//	env:<NAME>                     environment variable
//	cmd:<command line>             stdout of a command (1Password `op read`, `pass`, ...)
//	prompt:                        ask on the terminal
//
// Literal values are rejected on purpose: a password pasted into a TOML file
// ends up in backups, dotfile repos and screenshots.
package secret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrNotFound means the reference is well formed but holds nothing.
var ErrNotFound = errors.New("secret not found")

// Prompter asks the user for a value when the reference is "prompt:".
type Prompter func(label string) (string, error)

// Resolver turns references into values.
type Resolver struct {
	Prompt Prompter
	// run executes a command and returns stdout; replaceable in tests.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// getenv is replaceable in tests.
	getenv func(string) string
}

// NewResolver returns a resolver backed by the real OS.
func NewResolver(p Prompter) *Resolver {
	return &Resolver{Prompt: p, run: runCommand, getenv: os.Getenv}
}

// Resolve returns the value behind ref. label is only used for prompts and errors.
func (r *Resolver) Resolve(ctx context.Context, label, ref string) (string, error) {
	scheme, rest, ok := strings.Cut(ref, ":")
	if !ok || ref == "" {
		return "", fmt.Errorf("%s: %q is not a secret reference (use keychain:, env:, cmd: or prompt:)", label, redact(ref))
	}
	switch scheme {
	case "keychain":
		service, account, ok := strings.Cut(rest, "/")
		if !ok || service == "" || account == "" {
			return "", fmt.Errorf("%s: keychain reference must be keychain:<service>/<account>", label)
		}
		return r.keychain(ctx, service, account)
	case "env":
		v := r.getenv(rest)
		if v == "" {
			return "", fmt.Errorf("%s: env %s: %w", label, rest, ErrNotFound)
		}
		return v, nil
	case "cmd":
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return "", fmt.Errorf("%s: empty cmd: reference", label)
		}
		out, err := r.run(ctx, fields[0], fields[1:]...)
		if err != nil {
			return "", fmt.Errorf("%s: cmd %s: %w", label, fields[0], err)
		}
		v := strings.TrimRight(string(out), "\r\n")
		if v == "" {
			return "", fmt.Errorf("%s: cmd %s: %w", label, fields[0], ErrNotFound)
		}
		return v, nil
	case "prompt":
		if r.Prompt == nil {
			return "", fmt.Errorf("%s: prompt: needs a terminal", label)
		}
		return r.Prompt(label)
	default:
		return "", fmt.Errorf("%s: unknown secret scheme %q (literal values are not accepted)", label, scheme)
	}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = nil
	return cmd.Output()
}

// redact keeps error messages from echoing a value that was pasted where a
// reference was expected.
func redact(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "…"
}

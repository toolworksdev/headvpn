package secret

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fake(env map[string]string, out string, err error) *Resolver {
	return &Resolver{
		getenv: func(k string) string { return env[k] },
		run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte(out), err
		},
	}
}

func TestLiteralValuesAreRejected(t *testing.T) {
	r := fake(nil, "", nil)
	for _, ref := range []string{"hunter2", "", "plain:hunter2"} {
		_, err := r.Resolve(context.Background(), "password", ref)
		if err == nil {
			t.Fatalf("Resolve(%q) accepted a literal", ref)
		}
		if ref != "" && strings.Contains(err.Error(), ref) {
			t.Fatalf("error echoes the value: %v", err)
		}
	}
}

func TestEnv(t *testing.T) {
	r := fake(map[string]string{"VPN_PW": "s3cret"}, "", nil)
	v, err := r.Resolve(context.Background(), "password", "env:VPN_PW")
	if err != nil || v != "s3cret" {
		t.Fatalf("got %q, %v", v, err)
	}
	if _, err := r.Resolve(context.Background(), "password", "env:MISSING"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing env: want ErrNotFound, got %v", err)
	}
}

func TestCmdTrimsNewlineAndRejectsEmpty(t *testing.T) {
	r := fake(nil, "s3cret\n", nil)
	v, err := r.Resolve(context.Background(), "password", "cmd:op read op://vault/item/password")
	if err != nil || v != "s3cret" {
		t.Fatalf("got %q, %v", v, err)
	}
	r = fake(nil, "\n", nil)
	if _, err := r.Resolve(context.Background(), "password", "cmd:pass show vpn"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty output: want ErrNotFound, got %v", err)
	}
}

func TestKeychainNeedsServiceAndAccount(t *testing.T) {
	r := fake(nil, "x", nil)
	for _, ref := range []string{"keychain:", "keychain:svc", "keychain:/acct", "keychain:svc/"} {
		if _, err := r.Resolve(context.Background(), "password", ref); err == nil {
			t.Fatalf("Resolve(%q) accepted a malformed reference", ref)
		}
	}
}

func TestPromptWithoutTerminalFails(t *testing.T) {
	r := fake(nil, "", nil)
	if _, err := r.Resolve(context.Background(), "otp", "prompt:"); err == nil {
		t.Fatal("prompt: without a prompter must fail")
	}
}

//go:build linux

package secret

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSecretServiceRoundTrip needs a running, unlocked Secret Service
// (CI starts gnome-keyring for it). Opt-in so `go test ./...` on a desktop
// never writes to the user's keyring.
func TestSecretServiceRoundTrip(t *testing.T) {
	if os.Getenv("HEADVPN_SECRET_SERVICE_TEST") != "1" {
		t.Skip("set HEADVPN_SECRET_SERVICE_TEST=1 with an unlocked Secret Service")
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	want := hex.EncodeToString(b)
	account := "item-" + want[:8]

	store := exec.Command(StoreArgs("headvpn-ci", account)[0], StoreArgs("headvpn-ci", account)[1:]...)
	store.Stdin = strings.NewReader(want)
	if out, err := store.CombinedOutput(); err != nil {
		t.Fatalf("secret-tool store: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("secret-tool", "clear", "service", "headvpn-ci", "account", account).Run() })

	r := NewResolver(nil)
	got, err := r.Resolve(context.Background(), "test", "keychain:headvpn-ci/"+account)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("read back %d chars, want the stored %d", len(got), len(want))
	}

	_, err = r.Resolve(context.Background(), "test", "keychain:headvpn-ci/absent-"+want[:8])
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing item: err=%v, want ErrNotFound", err)
	}
}

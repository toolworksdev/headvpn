package totp

import (
	"context"
	"encoding/base32"
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratorNeverRepeatsACode(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	g, err := NewGenerator(secret)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(59, 0)
	var slept time.Duration
	g.now = func() time.Time { return clock }
	g.sleep = func(ctx context.Context, d time.Duration) error { slept += d; clock = clock.Add(d); return nil }

	first, _ := g.Next(context.Background())
	second, _ := g.Next(context.Background())
	if first != "287082" {
		t.Fatalf("first=%s, want RFC vector 287082", first)
	}
	if second == first {
		t.Fatal("returned the same code twice")
	}
	if slept != time.Second { // from t=59 to the next window at t=60
		t.Fatalf("slept %s, want 1s", slept)
	}
}

func TestStateCarriesTheLastStepAcrossRuns(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	state := filepath.Join(t.TempDir(), "last")
	clock := time.Unix(59, 0)
	var slept time.Duration
	run := func() string {
		g, _ := NewGenerator(secret)
		g.WithState(state).WithClock(func() time.Time { return clock })
		g.sleep = func(ctx context.Context, d time.Duration) error { slept += d; clock = clock.Add(d); return nil }
		c, err := g.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := run()
	second := run() // a new process, same 30 s window
	if first == second || slept != time.Second {
		t.Fatalf("second run reused the code (first=%s second=%s slept=%s)", first, second, slept)
	}
}

func TestGeneratorRejectsBadSecret(t *testing.T) {
	if _, err := NewGenerator("!!"); err == nil {
		t.Fatal("accepted a bad secret")
	}
}

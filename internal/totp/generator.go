package totp

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Generator hands out codes and never the same one twice: IdPs reject a
// code that was already accepted, so a re-login inside the same 30 s window
// waits for the next window instead of failing (and counting as a bad try).
type Generator struct {
	key      []byte
	mu       sync.Mutex
	used     bool
	lastStep uint64
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	state    string // file remembering the last step across runs; "" = memory only
}

// WithState makes the generator remember the last step in path, so that a
// second run inside the same 30 s window waits instead of sending a code the
// IdP already accepted (measured: Keycloak rejects it as invalid, and the
// rejection counts towards brute-force lockout).
func (g *Generator) WithState(path string) *Generator { g.state = path; return g }

// WithClock replaces the clock (tests).
func (g *Generator) WithClock(now func() time.Time) *Generator { g.now = now; return g }

// NewGenerator returns a generator for a base32 secret.
func NewGenerator(secret string) (*Generator, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return nil, err
	}
	return &Generator{key: key, now: time.Now, sleep: sleepCtx}, nil
}

// Next returns a 6-digit code that has not been returned before.
func (g *Generator) Next(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	step := uint64(now.Unix()) / uint64(Step/time.Second)
	if last, ok := g.load(); ok && (!g.used || last > g.lastStep) {
		g.lastStep, g.used = last, true
	}
	if g.used && step <= g.lastStep {
		next := time.Unix(int64((g.lastStep+1)*uint64(Step/time.Second)), 0)
		if err := g.sleep(ctx, next.Sub(now)); err != nil {
			return "", err
		}
		step = g.lastStep + 1
	}
	g.lastStep, g.used = step, true
	g.save(step)
	return At(g.key, time.Unix(int64(step*uint64(Step/time.Second)), 0), 6), nil
}

func (g *Generator) load() (uint64, bool) {
	if g.state == "" {
		return 0, false
	}
	b, err := os.ReadFile(g.state)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil
}

func (g *Generator) save(step uint64) {
	if g.state == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(g.state), 0o700)
	_ = os.WriteFile(g.state, []byte(strconv.FormatUint(step, 10)+"\n"), 0o600)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

package awsofficial

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func fakeCLI(states []string, fail map[string]string) *Client {
	i := 0
	return &Client{Path: "aws-vpn-client", Run: func(ctx context.Context, path string, args ...string) ([]byte, []byte, error) {
		if msg, ok := fail[args[0]]; ok {
			return nil, []byte(`{"status":"Error","message":"` + msg + `"}`), errors.New("exit status 2")
		}
		if args[0] == "get-connection-status" {
			s := states[min(i, len(states)-1)]
			i++
			return []byte(`{"connection-status":"` + s + `"}`), nil, nil
		}
		return []byte(`{"status":"WaitingForIdentity"}`), nil, nil
	}}
}

func TestStatusParsesRealOutput(t *testing.T) {
	c := fakeCLI([]string{"WaitingForIdentity"}, nil)
	st, err := c.Status(context.Background(), "p")
	if err != nil || st != StateWaitingForIdentity {
		t.Fatalf("got %q, %v", st, err)
	}
}

func TestCLIErrorMessageIsSurfaced(t *testing.T) {
	c := fakeCLI(nil, map[string]string{"connect": "Profile not found"})
	err := c.Start(context.Background(), "p")
	if err == nil || !strings.Contains(err.Error(), "Profile not found") {
		t.Fatalf("got %v", err)
	}
}

func TestWaitForConnected(t *testing.T) {
	c := fakeCLI([]string{"WaitingForIdentity", "Connecting", "Connected"}, nil)
	st, err := c.WaitFor(context.Background(), "p", StateConnected, time.Millisecond)
	if err != nil || st != StateConnected {
		t.Fatalf("got %q, %v", st, err)
	}
}

func TestWaitForStopsWhenClientGivesUp(t *testing.T) {
	c := fakeCLI([]string{"Connecting", "NotConnected"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.WaitFor(ctx, "p", StateConnected, time.Millisecond); err == nil || ctx.Err() != nil {
		t.Fatalf("want an immediate failure, got %v (ctx %v)", err, ctx.Err())
	}
}

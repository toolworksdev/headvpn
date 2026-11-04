package main

import (
	"context"
	"fmt"
	"io"

	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/kibana"
	"github.com/toolworksdev/headvpn/internal/vpn"
)

// kibanaGet logs in to one [kibana.<name>] app and sends one read-only
// request. The response body goes to stdout untouched; nothing secret is
// ever printed (no password, code, cookie or assertion).
func kibanaGet(ctx context.Context, k config.Kibana, path string, body []byte, deps vpn.Deps, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, k.Timeout())
	defer cancel()
	c, err := kibana.New(k.URL, k.IdPOrigin)
	if err != nil {
		fmt.Fprintln(stderr, "headvpn:", err)
		return exitError
	}
	idp, err := vpn.KibanaIdP(ctx, k, deps)
	if err != nil {
		fmt.Fprintln(stderr, "headvpn:", err)
		return exitError
	}
	if err := c.Login(ctx, idp); err != nil {
		fmt.Fprintln(stderr, "headvpn:", err)
		if vpn.Rejected(err) {
			return exitRejected
		}
		return exitError
	}
	status, out, err := c.Get(ctx, path, body)
	if err != nil {
		fmt.Fprintln(stderr, "headvpn:", err)
		return exitError
	}
	_, _ = stdout.Write(out)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		fmt.Fprintln(stdout)
	}
	if status/100 != 2 {
		fmt.Fprintf(stderr, "headvpn: GET %s answered HTTP %d\n", path, status)
		return exitError
	}
	return exitOK
}

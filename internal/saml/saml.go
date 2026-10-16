// Package saml delivers an IdP's SAML POST form to the VPN client's local
// assertion consumer (http://127.0.0.1:35001 for AWS Client VPN).
package saml

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// PostForm is the auto-submit form an IdP returns after a successful login.
type PostForm struct {
	Action       string
	SAMLResponse string
	RelayState   string
}

// Deliver posts the form to its action, which must be a loopback address:
// the assertion is a bearer credential and must not leave the machine.
func (f *PostForm) Deliver(ctx context.Context, c *http.Client) error {
	if f.SAMLResponse == "" {
		return fmt.Errorf("SAML post form without SAMLResponse")
	}
	u, err := url.Parse(f.Action)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("SAML form action %q is not http(s)", u.Scheme)
	}
	ip := net.ParseIP(u.Hostname())
	if !(u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return fmt.Errorf("refusing to send the SAML assertion to %s: only a loopback consumer is accepted", u.Host)
	}
	vals := url.Values{"SAMLResponse": {f.SAMLResponse}}
	if f.RelayState != "" {
		vals.Set("RelayState", f.RelayState)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(vals.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("deliver SAML response to %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("deliver SAML response to %s: HTTP %d", u.Host, resp.StatusCode)
	}
	return nil
}

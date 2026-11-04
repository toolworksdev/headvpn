// Package kibana logs in to a Kibana (or OpenSearch Dashboards) app that uses
// SAML, and sends read-only requests through its console proxy.
//
// Guards, each with a test that fails when it is removed:
//   - the app must be https;
//   - the app's SAML login must redirect to the configured IdP origin, or the
//     IdP is never asked;
//   - the SAML assertion is delivered only to the app's own origin (https);
//   - requests go out as GET only: the console proxy is a full Elasticsearch
//     client, and the caller's role may well be allowed to write.
package kibana

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/toolworksdev/headvpn/internal/saml"
)

// IdP answers the IdP half of the login: it starts at the IdP's login URL
// (SAML redirect binding) and returns the response form, unposted.
type IdP func(ctx context.Context, loginURL string) (*saml.PostForm, error)

// MaxBody bounds a response kept in memory.
const MaxBody = 64 << 20

// Client is one app session.
type Client struct {
	base      *url.URL
	idpOrigin *url.URL
	http      *http.Client
}

// New checks the URLs and builds a client with its own cookie jar.
func New(base, idpOrigin string) (*Client, error) {
	b, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || b.Scheme != "https" || b.Host == "" {
		return nil, fmt.Errorf("kibana url must be https, got %q", base)
	}
	o, err := url.Parse(idpOrigin)
	if err != nil || o.Scheme != "https" || o.Host == "" {
		return nil, fmt.Errorf("idp_origin must be https, got %q", idpOrigin)
	}
	jar, _ := cookiejar.New(nil)
	c := &Client{base: b, idpOrigin: o}
	c.http = &http.Client{Jar: jar, Timeout: 60 * time.Second,
		// Follow redirects only inside the app: the one that leaves (to the
		// IdP) is read by Login, not followed.
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if !sameOrigin(r.URL, b) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		}}
	return c, nil
}

// SetTransport lets tests trust their TLS server.
func (c *Client) SetTransport(t http.RoundTripper) { c.http.Transport = t }

// Login runs the SAML login and keeps the app's session cookie.
func (c *Client) Login(ctx context.Context, idp IdP) error {
	next := c.base.Path + "/"
	start := c.base.String() + "/auth/saml/login?nextUrl=" + url.QueryEscape(next)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, start, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kibana saml login: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode/100 != 3 || loc == "" {
		return fmt.Errorf("kibana saml login answered %d without a redirect to the IdP (only the redirect binding is supported)", resp.StatusCode)
	}
	lu, err := resp.Request.URL.Parse(loc)
	if err != nil {
		return err
	}
	if !sameOrigin(lu, c.idpOrigin) {
		return fmt.Errorf("kibana sends the login to %s, not to idp_origin %s: refusing", lu.Host, c.idpOrigin.Host)
	}
	form, err := idp(ctx, lu.String())
	if err != nil {
		return err
	}
	if form == nil || form.SAMLResponse == "" {
		return errors.New("the IdP returned no SAMLResponse")
	}
	acs, err := url.Parse(form.Action)
	if err != nil || !sameOrigin(acs, c.base) {
		host := ""
		if acs != nil {
			host = acs.Host
		}
		return fmt.Errorf("refusing to send the SAML assertion to %s: only %s is accepted", host, c.base.Host)
	}
	v := url.Values{"SAMLResponse": {form.SAMLResponse}}
	if form.RelayState != "" {
		v.Set("RelayState", form.RelayState)
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, acs.String(), strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kibana assertion consumer: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("kibana rejected the SAML assertion: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Get sends GET <path> (with an optional JSON body, e.g. a _search query)
// through the console proxy and returns the Elasticsearch status and body.
func (c *Client) Get(ctx context.Context, path string, body []byte) (int, []byte, error) {
	path = strings.TrimLeft(strings.TrimSpace(path), "/")
	if path == "" {
		return 0, nil, errors.New("empty path")
	}
	q := url.Values{"path": {path}, "method": {http.MethodGet}}
	var rd io.Reader
	if len(body) > 0 {
		rd = strings.NewReader(string(body))
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+"/api/console/proxy?"+q.Encode(), rd)
	// Kibana checks kbn-xsrf; OpenSearch Dashboards checks osd-xsrf.
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("osd-xsrf", "true")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(b) > MaxBody {
		return resp.StatusCode, nil, fmt.Errorf("response larger than %d bytes: narrow the query", MaxBody)
	}
	return resp.StatusCode, b, nil
}

func sameOrigin(u, origin *url.URL) bool {
	return u != nil && u.Scheme == "https" && strings.EqualFold(u.Host, origin.Host) && origin.Scheme == "https"
}

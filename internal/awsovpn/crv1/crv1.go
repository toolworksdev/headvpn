// Package crv1 handles the OpenVPN dynamic challenge/response protocol as
// AWS Client VPN uses it for SAML federated authentication.
//
// Flow: the client authenticates with username "N/A" and password
// ACSPassword. The server rejects it with
//
//	AUTH_FAILED,CRV1:R:<state id>:<base64 user>:<IdP SAML URL>
//
// and the client re-authenticates with Password(stateID, samlResponse).
package crv1

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	// Username sent in both authentication attempts.
	Username = "N/A"
	// ACSPassword tells the endpoint we want SAML and that the IdP should
	// post the assertion to http://127.0.0.1:35001/ (which we never listen
	// on: the assertion is read from Keycloak's response instead).
	ACSPassword = "ACS::35001"

	// maxPassword keeps the management "password" command under the
	// 128 KiB line/password buffers of AWS's patched OpenVPN.
	maxPassword = 128*1024 - 64
)

type Challenge struct {
	Flags    string // "R" = response required
	StateID  string
	Username string // base64 of the username, AWS sends b'Ti9B' ("N/A")
	Text     string // challenge text: the IdP SAML redirect URL
}

// Parse extracts a challenge from s, which may be the bare "CRV1:..." string
// or any line containing it, such as the management interface's
//
//	>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:...']
func Parse(s string) (Challenge, error) {
	i := strings.Index(s, "CRV1:")
	if i < 0 {
		return Challenge{}, errors.New("no CRV1 challenge found")
	}
	s = strings.TrimSuffix(strings.TrimSpace(s[i:]), "']")
	parts := strings.SplitN(s, ":", 5)
	if len(parts) != 5 || parts[2] == "" || parts[4] == "" {
		return Challenge{}, errors.New("malformed CRV1 challenge")
	}
	return Challenge{Flags: parts[1], StateID: parts[2], Username: parts[3], Text: parts[4]}, nil
}

// URL returns the challenge text as a URL after checking that it points at
// the trusted IdP origin (scheme://host[:port]). The VPN server decides
// where we send our Keycloak password, so a mismatch must be fatal.
func (c Challenge) URL(trustedOrigin string) (*url.URL, error) {
	u, err := url.Parse(c.Text)
	if err != nil {
		return nil, fmt.Errorf("challenge URL: %w", err)
	}
	want, err := url.Parse(trustedOrigin)
	if err != nil || want.Scheme == "" || want.Host == "" {
		return nil, fmt.Errorf("invalid idp_origin %q", trustedOrigin)
	}
	if u.Scheme != "https" || !SameOrigin(u, want) {
		return nil, fmt.Errorf("VPN server sent login URL for %s://%s, which is not the trusted idp_origin %s",
			u.Scheme, u.Host, trustedOrigin)
	}
	return u, nil
}

// SameOrigin reports whether a and b share scheme and host (including port).
func SameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// Password builds the CRV1 response. Like the AWS client, the SAMLResponse
// is sent form-urlencoded.
func Password(stateID, samlResponse string) (string, error) {
	pw := "CRV1::" + stateID + "::" + url.QueryEscape(samlResponse)
	if len(pw) > maxPassword {
		return "", fmt.Errorf("SAML response too large (%d bytes, max %d)", len(pw), maxPassword)
	}
	return pw, nil
}

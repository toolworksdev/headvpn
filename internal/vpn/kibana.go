package vpn

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/toolworksdev/headvpn/internal/config"
	"github.com/toolworksdev/headvpn/internal/kibana"
	"github.com/toolworksdev/headvpn/internal/saml"
)

// KibanaIdP resolves the secrets of a [kibana.<name>] table and returns the
// IdP half of its SAML login. Secrets are resolved here, before any request,
// so a missing one fails fast.
func KibanaIdP(ctx context.Context, k config.Kibana, d Deps) (kibana.IdP, error) {
	l, err := buildLogin(ctx, k.AsProfile(), d)
	if err != nil {
		return nil, err
	}
	if l.Client == nil {
		jar, _ := cookiejar.New(nil)
		l.Client = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	}
	return func(ctx context.Context, loginURL string) (*saml.PostForm, error) {
		return l.Run(ctx, loginURL)
	}, nil
}

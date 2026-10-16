//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/toolworksdev/headvpn/internal/awsovpn/crv1"
	"github.com/toolworksdev/headvpn/internal/awsovpn/mgmt"
	"github.com/toolworksdev/headvpn/internal/idp/keycloak"
)

// The machine is a pure reducer over management-interface messages. It
// reproduces the AWS VPN Client's exchange with acvc-openvpn:
//
//	>PASSWORD:Need 'Auth' username/password      -> N/A / ACS::35001
//	>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:<sid>:...:<url>']
//	                                             -> Keycloak login (async)
//	>PASSWORD:Need 'Auth' username/password      -> N/A / CRV1::<sid>::<saml>
//	>STATE:...,CONNECTED,SUCCESS,...
//
// After a ping-restart OpenVPN asks for credentials again (auth-nocache) and
// the same cycle runs inside the same process.

type action interface{ isAction() }

type sendAction struct{ cmd, logAs string }
type authAction struct {
	challenge crv1.Challenge
	url       *url.URL
}
type connectedAction struct{ st mgmt.StateInfo }
type stateAction struct{ st mgmt.StateInfo }
type warnAction struct{ msg string }
type failAction struct {
	err   error
	retry bool // restart OpenVPN (true) or give up (false)
}

func (sendAction) isAction()      {}
func (authAction) isAction()      {}
func (connectedAction) isAction() {}
func (stateAction) isAction()     {}
func (warnAction) isAction()      {}
func (failAction) isAction()      {}

// maxRejections is how many authentication rejections in a row the VPN
// server may send before headvpn stops instead of looping.
const maxRejections = 3

type machine struct {
	idpOrigin string

	pending  string // CRV1 password ready for the next credential request
	authBusy bool   // Keycloak login running
	waiting  bool   // OpenVPN asked for credentials while authBusy
	sentCRV1 bool   // the last password sent was a CRV1 response
	rejected int    // consecutive rejections
}

func (m *machine) start() []action {
	// "hold off" keeps OpenVPN from holding again on every soft restart.
	return []action{send("state on"), send("hold off"), send("hold release")}
}

func (m *machine) onMessage(msg mgmt.Message) []action {
	switch msg.Kind {
	case mgmt.Hold:
		return []action{send("hold release")}
	case mgmt.Password:
		return m.onPassword(msg.Body)
	case mgmt.State:
		st := mgmt.ParseState(msg.Body)
		if st.Name == "CONNECTED" {
			m.rejected = 0
			return []action{connectedAction{st}}
		}
		return []action{stateAction{st}}
	case mgmt.Fatal:
		return fail(errors.New("openvpn: "+msg.Body), true)
	case mgmt.Error:
		return []action{warnAction{"openvpn management: " + msg.Body}}
	}
	return nil
}

func (m *machine) onPassword(body string) []action {
	switch {
	case strings.HasPrefix(body, "Need 'Auth'"):
		if m.pending != "" {
			pw := m.pending
			m.pending, m.sentCRV1 = "", true
			return creds(pw)
		}
		if m.authBusy {
			m.waiting = true
			return nil
		}
		m.sentCRV1 = false
		return creds(crv1.ACSPassword)

	case strings.HasPrefix(body, "Verification Failed: 'Auth'"):
		if !strings.Contains(body, "CRV1:") {
			reason := failureReason(body)
			if a := m.reject("VPN server rejected authentication: " + reason); a != nil {
				return a
			}
			return []action{warnAction{"VPN server rejected authentication (" + reason + "), retrying"}}
		}
		if m.sentCRV1 {
			if a := m.reject("VPN server did not accept the SAML response"); a != nil {
				return a
			}
		}
		ch, err := crv1.Parse(body)
		if err != nil {
			return fail(err, true)
		}
		u, err := ch.URL(m.idpOrigin)
		if err != nil {
			return fail(err, false)
		}
		m.authBusy, m.pending = true, ""
		return []action{authAction{challenge: ch, url: u}}
	}
	return fail(fmt.Errorf("unsupported credential request from OpenVPN: %s", body), false)
}

// onAuth delivers the result of a Keycloak login started by an authAction.
// pw is the complete CRV1 password.
func (m *machine) onAuth(pw string, err error) []action {
	m.authBusy = false
	if err != nil {
		return fail(err, !errors.Is(err, keycloak.ErrRejected))
	}
	if m.waiting {
		m.waiting, m.sentCRV1 = false, true
		return creds(pw)
	}
	m.pending = pw
	return nil
}

func (m *machine) reject(msg string) []action {
	m.rejected++
	m.sentCRV1 = false
	if m.rejected >= maxRejections {
		return fail(fmt.Errorf("%s (%d times in a row, giving up)", msg, m.rejected), false)
	}
	return nil
}

func send(cmd string) sendAction { return sendAction{cmd: cmd, logAs: cmd} }

func creds(pw string) []action {
	return []action{
		sendAction{cmd: `username "Auth" ` + mgmt.Quote(crv1.Username), logAs: `username "Auth" N/A`},
		sendAction{cmd: `password "Auth" ` + mgmt.Quote(pw), logAs: `password "Auth" [redacted]`},
	}
}

func fail(err error, retry bool) []action { return []action{failAction{err: err, retry: retry}} }

// failureReason extracts the server's reason from
// "Verification Failed: 'Auth' ['Invalid username or password']".
func failureReason(body string) string {
	if _, r, ok := strings.Cut(body, "['"); ok {
		return strings.TrimSuffix(r, "']")
	}
	return "authentication failed"
}

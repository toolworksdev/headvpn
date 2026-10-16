package vpn

import (
	"context"
	"testing"

	"github.com/toolworksdev/headvpn/internal/config"
)

func switchSetup() (map[string]config.Profile, Deps, *fakePritunl, *fakeBackend) {
	pr := &fakePritunl{connected: true, active: true}
	aws := &fakeBackend{states: []string{"NotConnected"}}
	d, _ := pritunlDeps(pr)
	d.Backend = func(config.Profile) Backend { return aws }
	all := map[string]config.Profile{
		"office": {Backend: "pritunl", PritunlProfile: "vpn (ana)"},
		"work":   {Backend: "aws-official", AWSProfile: "work", IdP: "keycloak"},
	}
	return all, d, pr, aws
}

func TestConnectingOneVPNDisconnectsTheOther(t *testing.T) {
	all, d, pr, _ := switchSetup()
	got, err := SwitchFrom(context.Background(), all, "work", d)
	if err != nil || len(got) != 1 || got[0] != "office" {
		t.Fatalf("switched=%v err=%v, want [office]", got, err)
	}
	if pr.connected || pr.stops != 1 {
		t.Fatalf("pritunl still up (stops=%d)", pr.stops)
	}
}

func TestNothingToSwitchWhenTheOtherIsDown(t *testing.T) {
	all, d, pr, _ := switchSetup()
	pr.connected, pr.active = false, false
	got, err := SwitchFrom(context.Background(), all, "work", d)
	if err != nil || len(got) != 0 || pr.stops != 0 {
		t.Fatalf("switched=%v err=%v stops=%d", got, err, pr.stops)
	}
}

func TestProfilesThatBothAllowItCoexist(t *testing.T) {
	all, d, pr, _ := switchSetup()
	no := false
	for n, p := range all {
		p.Exclusive = &no
		all[n] = p
	}
	if got, _ := SwitchFrom(context.Background(), all, "work", d); len(got) != 0 || !pr.connected {
		t.Fatalf("disconnected %v although both profiles set exclusive = false", got)
	}
	// One exclusive side is enough to switch.
	p := all["work"]
	p.Exclusive = nil
	all["work"] = p
	if got, _ := SwitchFrom(context.Background(), all, "work", d); len(got) != 1 {
		t.Fatalf("an exclusive target must still switch: %v", got)
	}
}

func TestTheReverseDirectionToo(t *testing.T) {
	all, d, pr, aws := switchSetup()
	pr.connected, pr.active = false, false
	aws.states = []string{"Connected", "NotConnected"}
	got, err := SwitchFrom(context.Background(), all, "office", d)
	if err != nil || len(got) != 1 || got[0] != "work" || aws.stops.Load() != 1 {
		t.Fatalf("switched=%v err=%v stops=%d", got, err, aws.stops.Load())
	}
}

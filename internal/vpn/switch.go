package vpn

import (
	"context"
	"fmt"
	"sort"

	"github.com/toolworksdev/headvpn/internal/config"
)

// SwitchFrom disconnects every other configured profile that is connected
// and may not coexist with name, so that connecting name does not stack two
// tunnels (e.g. Pritunl up while AWS Client VPN comes up). Two profiles may
// coexist only when both set `exclusive = false`.
//
// A profile whose status cannot be read (its client is not installed on
// this machine) cannot be connected either, and is skipped. A connected
// profile that fails to disconnect stops the switch: connecting on top of it
// is exactly what this guards against.
func SwitchFrom(ctx context.Context, all map[string]config.Profile, name string, d Deps) ([]string, error) {
	target, ok := all[name]
	if !ok {
		return nil, fmt.Errorf("no profile %q", name)
	}
	var others []string
	for n := range all {
		if n != name {
			others = append(others, n)
		}
	}
	sort.Strings(others)
	var switched []string
	for _, n := range others {
		p := all[n]
		if !target.IsExclusive() && !p.IsExclusive() {
			continue
		}
		st := Status(ctx, n, p, d)
		if st.Error != "" || st.State != "Connected" {
			continue
		}
		r := Disconnect(ctx, n, p, d)
		if r.Error != "" {
			return switched, fmt.Errorf("disconnecting %q before connecting %q: %s", n, name, r.Error)
		}
		if r.State != "NotConnected" {
			return switched, fmt.Errorf("disconnecting %q before connecting %q: still %s", n, name, r.State)
		}
		switched = append(switched, n)
	}
	return switched, nil
}

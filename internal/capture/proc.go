package capture

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Process is one row of the process table.
type Process struct {
	UID, PID, PPID int
	Args           string
}

// ProcWatcher catches the URL while the VPN client hands it to the browser.
//
// Measured with AWS VPN Client 6.x on macOS: `aws-vpn-client connect` runs
// `/usr/bin/open <saml-url>` about 1 s after it starts, and that argv is
// visible in the process table to the same user. No browser data is read, so
// no Full Disk Access is needed. The process is short-lived, hence the tight
// polling interval.
type ProcWatcher struct {
	// Origin is the IdP origin; only URLs under it are accepted.
	Origin string
	// Parent must appear in the argv of the parent process (the VPN CLI).
	Parent string
	// List is replaceable in tests.
	List func(ctx context.Context) ([]Process, error)
	UID  int
}

// NewProcWatcher returns a watcher for URLs under origin opened by a child of
// a process whose argv contains parent.
func NewProcWatcher(origin, parent string) *ProcWatcher {
	return &ProcWatcher{Origin: strings.TrimRight(origin, "/"), Parent: parent, List: defaultLister(), UID: os.Getuid()}
}

// Wait polls until a matching `open` appears or ctx ends. Processes that
// already existed on the first scan are ignored: the URL must belong to the
// connection this run started.
func (w *ProcWatcher) Wait(ctx context.Context, every time.Duration) (string, error) {
	seen := map[int]bool{}
	first := true
	for {
		procs, err := w.List(ctx)
		if err == nil {
			byPID := make(map[int]Process, len(procs))
			for _, p := range procs {
				byPID[p.PID] = p
			}
			for _, p := range procs {
				if first {
					seen[p.PID] = true
					continue
				}
				if seen[p.PID] {
					continue
				}
				if u, ok := w.match(p, byPID); ok {
					return u, nil
				}
			}
			first = false
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("%w: no `open` of a SAML URL under %s was seen", ErrNotFound, w.Origin)
		case <-time.After(every):
		}
	}
}

func (w *ProcWatcher) match(p Process, byPID map[int]Process) (string, bool) {
	if p.UID != w.UID {
		return "", false
	}
	fields := strings.Fields(p.Args)
	if len(fields) < 2 || fields[0] != "/usr/bin/open" {
		return "", false
	}
	if w.Parent != "" {
		parent, ok := byPID[p.PPID]
		if !ok || !strings.Contains(parent.Args, w.Parent) {
			return "", false
		}
	}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, w.Origin+"/") && strings.Contains(f, "SAMLRequest=") {
			return f, true
		}
	}
	return "", false
}

// First runs every source concurrently and returns the first URL found. It
// fails only when all of them fail, reporting each error.
func First(ctx context.Context, sources ...func(context.Context) (string, error)) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		u   string
		err error
	}
	ch := make(chan res, len(sources))
	for _, s := range sources {
		go func(s func(context.Context) (string, error)) {
			u, err := s(ctx)
			ch <- res{u, err}
		}(s)
	}
	var errs []string
	for range sources {
		r := <-ch
		if r.err == nil {
			return r.u, nil
		}
		errs = append(errs, r.err.Error())
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, strings.Join(errs, " | "))
}

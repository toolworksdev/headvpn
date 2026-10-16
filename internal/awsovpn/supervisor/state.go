//go:build linux

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// DefaultRunDir holds the lock, the status file (world-readable, so
// "headvpn status" works without root) and a root-only private/ directory for
// the management socket and the profile copy.
const DefaultRunDir = "/run/headvpn"

// Status is what "headvpn status" shows. It never contains secrets.
type Status struct {
	Profile        string     `json:"profile"`
	PID            int        `json:"pid"`
	State          string     `json:"state"`
	Detail         string     `json:"detail,omitempty"`
	TunnelIP       string     `json:"tunnel_ip,omitempty"`
	ServerIP       string     `json:"server_ip,omitempty"`
	Updated        time.Time  `json:"updated"`
	ConnectedSince *time.Time `json:"connected_since,omitempty"`
}

func statusPath(runDir string) string { return filepath.Join(runDir, "status.json") }

// ReadStatus returns the running instance's status, or fs.ErrNotExist if
// no live instance is found.
func ReadStatus(runDir string) (*Status, error) {
	data, err := os.ReadFile(statusPath(runDir))
	if err != nil {
		return nil, err
	}
	st := &Status{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	if !Alive(st.PID) {
		return nil, fs.ErrNotExist
	}
	return st, nil
}

// Alive reports whether a process with this pid exists.
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

type statusFile struct {
	path string
	mu   sync.Mutex
	st   Status
}

func newStatusFile(runDir, profile string) *statusFile {
	return &statusFile{path: statusPath(runDir), st: Status{Profile: profile, PID: os.Getpid()}}
}

func (f *statusFile) update(fn func(*Status)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.st)
	f.st.Updated = time.Now()
	data, _ := json.MarshalIndent(f.st, "", "  ")
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err == nil {
		os.Rename(tmp, f.path)
	}
}

func (f *statusFile) set(state, detail string) {
	f.update(func(s *Status) {
		s.State, s.Detail = state, detail
		if state != "CONNECTED" {
			s.ConnectedSince = nil
		}
	})
}

func (f *statusFile) remove() { os.Remove(f.path) }

// Lock makes sure only one headvpn runs at a time (the AWS endpoint pushes a
// full tunnel, so two sessions would fight over routes and DNS).
func Lock(runDir string) (release func(), err error) {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(runDir, "headvpn.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		pid := "?"
		if st, err := ReadStatus(runDir); err == nil {
			pid = strconv.Itoa(st.PID)
		}
		return nil, fmt.Errorf("headvpn is already running (pid %s); stop it with: headvpn disconnect", pid)
	}
	return func() { f.Close() }, nil
}

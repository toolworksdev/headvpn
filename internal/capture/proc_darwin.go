//go:build darwin

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"

	"golang.org/x/sys/unix"
)

// listNative reads the process table straight from the kernel. Spawning
// /bin/ps costs ~30 ms per scan, which is longer than `open` lives on a fast
// Mac (measured: missed on a recent Apple Silicon machine, caught on an older
// one). A sysctl scan takes well under a millisecond. Arguments are fetched only for processes whose name
// can matter, to keep each scan cheap.
func listNative(ctx context.Context) ([]Process, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	procs := make([]Process, 0, len(kps))
	for i := range kps {
		kp := &kps[i]
		comm := cstr(kp.Proc.P_comm[:])
		p := Process{
			UID:  int(kp.Eproc.Ucred.Uid),
			PID:  int(kp.Proc.P_pid),
			PPID: int(kp.Eproc.Ppid),
			Args: comm,
		}
		if comm == "open" || strings.HasPrefix(comm, "aws-vpn-client") {
			if args, err := procArgs(p.PID); err == nil {
				p.Args = args
			}
		}
		procs = append(procs, p)
	}
	return procs, nil
}

// procArgs returns argv joined by spaces, from kern.procargs2:
// int32 argc, exec path, NUL padding, then argc NUL-terminated strings.
func procArgs(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(buf) < 4 {
		return "", unix.EINVAL
	}
	argc := int(binary.LittleEndian.Uint32(buf[:4]))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0) // end of exec path
	if i < 0 {
		return "", unix.EINVAL
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	args := make([]string, 0, argc)
	for len(args) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			args = append(args, string(rest))
			break
		}
		args = append(args, string(rest[:j]))
		rest = rest[j+1:]
	}
	return strings.Join(args, " "), nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func defaultLister() func(context.Context) ([]Process, error) { return listNative }

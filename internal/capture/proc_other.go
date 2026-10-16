//go:build !darwin

package capture

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

func defaultLister() func(context.Context) ([]Process, error) { return listPS }

func listPS(ctx context.Context) ([]Process, error) {
	out, err := exec.CommandContext(ctx, "/bin/ps", "-axww", "-o", "uid=,pid=,ppid=,args=").Output()
	if err != nil {
		return nil, err
	}
	var procs []Process
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		uid, e1 := strconv.Atoi(f[0])
		pid, e2 := strconv.Atoi(f[1])
		ppid, e3 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		procs = append(procs, Process{UID: uid, PID: pid, PPID: ppid, Args: strings.Join(f[3:], " ")})
	}
	return procs, sc.Err()
}

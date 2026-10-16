//go:build darwin

package capture

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The native lister must see a short-lived child's full argv, the way
// aws-vpn-client's `open` appears. /bin/sleep stands in for it.
func TestNativeListerSeesArgsOfOwnChild(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(50 * time.Millisecond)
	procs, err := listNative(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range procs {
		if p.PID == cmd.Process.Pid {
			if p.UID != os.Getuid() || p.PPID != os.Getpid() || !strings.HasPrefix(p.Args, "sleep") {
				t.Fatalf("got %+v", p)
			}
			return
		}
	}
	t.Fatal("child not listed")
}

func TestProcArgsParsesArgv(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(50 * time.Millisecond)
	args, err := procArgs(cmd.Process.Pid)
	if err != nil || args != "/bin/sleep 2" {
		t.Fatalf("got %q, %v", args, err)
	}
}

func BenchmarkListNative(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := listNative(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

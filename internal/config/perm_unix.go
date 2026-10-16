//go:build !windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

// checkPerm refuses a config another local user could edit: `cmd:` secret
// references are run as the user who runs headvpn, so a writable config is
// code execution as that user.
func checkPerm(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %o): chmod 600 it", path, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s belongs to uid %d, not to the user running headvpn", path, sys.Uid)
	}
	return nil
}

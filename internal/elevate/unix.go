//go:build !windows

package elevate

import (
	"fmt"
	"os"
	"syscall"
)

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// checkDir makes sure the request directory is private: owned by a regular
// user and not writable by anyone else, so nobody can swap in another request.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("helper directory %s must be a private directory", dir)
	}
	if os.Geteuid() == 0 && st.Uid == 0 {
		return nil
	}
	if int(st.Uid) != os.Getuid() && os.Geteuid() != 0 {
		return fmt.Errorf("helper directory %s isn't owned by this user", dir)
	}
	return nil
}

//go:build !linux && !darwin && !windows

package recovery

import (
	"os"
	"path/filepath"
	"syscall"
)

func stateDir() string { return filepath.Join(os.TempDir(), "mkconnect") }

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func currentRules() ([]Rule, error)   { return nil, nil }
func undo(*Journal) ([]string, error) { return nil, nil }

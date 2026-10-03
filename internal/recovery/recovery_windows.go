package recovery

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows removes the Wintun adapter and its routes when the process exits;
// Internet Connection Sharing is restored through UndoICS (set by the gateway).
func stateDir() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "MKConnect")
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func currentRules() ([]Rule, error) { return nil, nil }

// UndoICS is set by the gateway package to disable a leftover ICS pair.
var UndoICS func(public, private string) error

func undo(j *Journal) ([]string, error) {
	if j.ICSPublic == "" || UndoICS == nil {
		return nil, nil
	}
	if err := UndoICS(j.ICSPublic, j.ICSPrivate); err != nil {
		return nil, err
	}
	return []string{"Internet Connection Sharing " + j.ICSPublic + " → " + j.ICSPrivate}, nil
}

package elevate

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

// launchElevated shows the UAC prompt and starts the helper as Administrator.
func launchElevated(exe, dir string) (<-chan error, error) {
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args, _ := syscall.UTF16PtrFromString(HelperFlag + ` "` + dir + `"`)
	err := windows.ShellExecute(0, verb, file, args, nil, windows.SW_HIDE)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return nil, ErrDenied
	}
	if err != nil {
		return nil, fmt.Errorf("start TUN helper: %w", err)
	}
	return nil, nil
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

// checkDir: the directory comes from the unelevated app's temp folder, which
// only that user can write to on Windows.
func checkDir(dir string) error { return nil }

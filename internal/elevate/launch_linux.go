package elevate

import (
	"errors"
	"fmt"
	"os/exec"
)

// launchElevated asks polkit (pkexec) for permission and runs the helper as
// root. pkexec only returns when the helper exits.
func launchElevated(exe, dir string) (<-chan error, error) {
	if _, err := exec.LookPath("pkexec"); err != nil {
		return nil, fmt.Errorf("TUN mode needs root: install polkit (pkexec) or start MKConnect with sudo")
	}
	cmd := exec.Command("pkexec", exe, HelperFlag, dir)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		var exit *exec.ExitError
		if errors.As(err, &exit) && (exit.ExitCode() == 126 || exit.ExitCode() == 127) {
			err = ErrDenied // dialog dismissed or authentication failed
		}
		exited <- err
	}()
	return exited, nil
}

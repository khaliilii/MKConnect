package recovery

import (
	"os/exec"
	"syscall"
)

// macOS removes a utun and its routes when the process holding it exits, so
// only settings MKConnect changed need restoring.
func stateDir() string { return "/var/run/mkconnect" }

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func currentRules() ([]Rule, error) { return nil, nil }

func undo(j *Journal) ([]string, error) {
	var cleaned []string
	if j.MacForwarding != "" {
		if err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding="+j.MacForwarding).Run(); err != nil {
			return cleaned, err
		}
		cleaned = append(cleaned, "net.inet.ip.forwarding="+j.MacForwarding)
	}
	return cleaned, nil
}

package recovery

import (
	"fmt"
	"os/exec"
	"strings"
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
	for service, servers := range j.MacDNS {
		// Left pointing into a tunnel that is gone, the service would have no
		// DNS at all: put back what it had.
		args := append([]string{"-setdnsservers", service}, strings.Fields(servers)...)
		if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
			return cleaned, fmt.Errorf("restore DNS of %s: %v: %s", service, err, strings.TrimSpace(string(out)))
		}
		cleaned = append(cleaned, "DNS of "+service+" = "+servers)
	}
	return cleaned, nil
}

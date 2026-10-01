package gateway

import (
	"fmt"
	"os/exec"
	"strings"
)

// On macOS forwarded packets follow the TUN default routes into sing-box.
func enable(s *Session, _ []string, _ string) error {
	out, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").Output()
	if err != nil {
		return err
	}
	old := strings.TrimSpace(string(out))
	if old == "1" {
		return nil
	}
	if out, err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").CombinedOutput(); err != nil {
		return fmt.Errorf("enable IP forwarding (needs root): %v: %s", err, strings.TrimSpace(string(out)))
	}
	s.onStop(func() error {
		return exec.Command("sysctl", "-w", "net.inet.ip.forwarding="+old).Run()
	})
	return nil
}

func hint(shared []string) string {
	return "Devices on " + strings.Join(shared, ", ") + " must use this Mac as their gateway (" +
		strings.Join(gatewayAddrs(shared), ", ") + ") and a public DNS server such as 1.1.1.1. " +
		"With macOS Internet Sharing on that interface they get the gateway automatically."
}

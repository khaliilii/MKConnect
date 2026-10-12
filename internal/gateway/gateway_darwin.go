package gateway

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/khaliilii/MKConnect/internal/recovery"
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
	recovery.Record(func(j *recovery.Journal) { j.MacForwarding = old })
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

// diagnose checks the things that silently break sharing on macOS: IP
// forwarding and a packet filter that drops forwarded packets.
func diagnose(shared []string, _ string) []string {
	var out []string
	if v, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").Output(); err == nil &&
		strings.TrimSpace(string(v)) != "1" {
		out = append(out, "IP forwarding is off: packets from the shared interfaces are dropped")
	}
	// pf is normally disabled on macOS; when something enabled it (a firewall,
	// macOS Internet Sharing, another VPN) its rules decide whether forwarded
	// packets live, which is worth saying before the user hunts elsewhere.
	if v, err := exec.Command("pfctl", "-s", "info").Output(); err == nil &&
		strings.Contains(string(v), "Status: Enabled") {
		out = append(out, "the macOS packet filter (pf) is enabled: if devices can't reach the internet, "+
			"check its rules with `sudo pfctl -s rules`")
	}
	for _, name := range shared {
		if strings.HasPrefix(name, "bridge") {
			continue // macOS Internet Sharing: it hands out addresses itself
		}
		out = append(out, "devices on "+name+" need this Mac as their gateway: set it by hand, or turn on "+
			"System Settings → General → Sharing → Internet Sharing for that interface")
	}
	return out
}

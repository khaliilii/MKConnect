package gateway

import (
	"fmt"
	"os"
	"strings"
)

const ipForward = "/proc/sys/net/ipv4/ip_forward"

// On Linux sing-box's auto_redirect (nftables) does the routing; the kernel
// only has to forward packets from the shared interfaces.
func enable(s *Session, _ []string, _ string) error {
	return setSysctl(s, ipForward, "1")
}

func setSysctl(s *Session, path, value string) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(old)) == value {
		return nil
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("enable IP forwarding (needs root): %w", err)
	}
	s.onStop(func() error { return os.WriteFile(path, old, 0o644) })
	return nil
}

func hint(shared []string) string {
	return "Devices on " + strings.Join(shared, ", ") + " must use this machine as their gateway (" +
		strings.Join(gatewayAddrs(shared), ", ") + ") and a public DNS server such as 1.1.1.1, " +
		"which is answered through the tunnel."
}

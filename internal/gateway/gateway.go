// Package gateway shares the TUN tunnel with devices on other network
// interfaces (Ethernet, a second Wi-Fi, a hotspot), so they reach the internet
// through MKConnect without any proxy settings.
//
// TUN interfaces are layer 3 and can't be bridged with Ethernet. Instead the
// machine acts as a router: traffic forwarded from the shared interfaces
// follows the TUN routes into sing-box, which terminates every connection
// itself, so no NAT is needed on Linux and macOS. Windows uses Internet
// Connection Sharing, which also hands out addresses (192.168.137.x) via DHCP.
package gateway

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// Interface is a network interface that can be shared.
type Interface struct {
	Name  string
	Addrs []string // IPv4 addresses with prefix, e.g. 192.168.1.10/24
}

func (i Interface) String() string {
	if len(i.Addrs) == 0 {
		return i.Name
	}
	return i.Name + " (" + strings.Join(i.Addrs, ", ") + ")"
}

// Interfaces lists interfaces that can be shared: up, not loopback, not a tunnel.
func Interfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || isTunnel(ifc) {
			continue
		}
		it := Interface{Name: ifc.Name}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				it.Addrs = append(it.Addrs, n.String())
			}
		}
		// Devices need this machine's address as their gateway, except with
		// Windows ICS, which assigns one (192.168.137.1) itself.
		if len(it.Addrs) == 0 && runtime.GOOS != "windows" {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

func isTunnel(ifc net.Interface) bool {
	if ifc.Flags&net.FlagPointToPoint != 0 {
		return true
	}
	name := strings.ToLower(ifc.Name)
	for _, p := range []string{"utun", "tun", "wg", "awdl", "llw", "anpi", "gif", "stf", "mkconnect", "sing-box"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Session is an active share; Stop restores the previous system state.
type Session struct {
	stops []func() error
}

// Stop undoes everything Enable changed, in reverse order.
func (s *Session) Stop() error {
	var errs []string
	for i := len(s.stops) - 1; i >= 0; i-- {
		if err := s.stops[i](); err != nil {
			errs = append(errs, err.Error())
		}
	}
	s.stops = nil
	if len(errs) > 0 {
		return fmt.Errorf("gateway cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Session) onStop(f func() error) { s.stops = append(s.stops, f) }

// Enable starts sharing the tunnel (TUN interface tunName) with the given
// interfaces. Needs root / Administrator. The caller must Stop the session.
func Enable(shared []string, tunName string) (*Session, error) {
	if len(shared) == 0 {
		return &Session{}, nil
	}
	known, _ := Interfaces()
	for _, name := range shared {
		found := false
		for _, k := range known {
			found = found || k.Name == name
		}
		if !found {
			return nil, fmt.Errorf("network interface %q not found or down", name)
		}
	}
	s := &Session{}
	if err := enable(s, shared, tunName); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

// Hint tells the user how devices on the shared interfaces connect.
func Hint(shared []string) string {
	if len(shared) == 0 {
		return ""
	}
	return hint(shared)
}

// gatewayAddrs returns "iface: ip" pairs for the hint text.
func gatewayAddrs(shared []string) []string {
	known, _ := Interfaces()
	var out []string
	for _, k := range known {
		for _, name := range shared {
			if k.Name != name {
				continue
			}
			for _, a := range k.Addrs {
				ip, _, _ := strings.Cut(a, "/")
				out = append(out, name+": "+ip)
			}
		}
	}
	return out
}

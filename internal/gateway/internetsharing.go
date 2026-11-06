package gateway

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// macOS Internet Sharing doesn't follow the routing table: its own pf rule
// ("pass on bridge100 ... rtable N") sends what its devices send to the
// interface it shares from, past the TUN routes, so a shared device reaches
// the filtered network directly (and with the kill switch on, nothing at all).
// The rules below come first and send those packets into the tunnel instead.

// sharingAnchor is where they go: the system evaluates every anchor under
// com.apple before Internet Sharing's own.
const sharingAnchor = "com.apple/mkconnect-share"

// SharedNet is a network Internet Sharing serves.
type SharedNet struct {
	Iface  string // bridge100
	Subnet string // 192.168.2.0/24
}

// sharedNets finds them among ifaces: Internet Sharing's bridges start at 100
// (bridge0 is Thunderbolt's) and have an address.
func sharedNets(ifaces []net.Interface) []SharedNet {
	var out []SharedNet
	for _, ifc := range ifaces {
		var n int
		if _, err := fmt.Sscanf(ifc.Name, "bridge%d", &n); err != nil || n < 100 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				sub := net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}
				out = append(out, SharedNet{ifc.Name, sub.String()})
			}
		}
	}
	return out
}

// sharingRules are the pf rules for nets: what stays on this machine or the
// shared network first, then everything else into the tunnel. The state pf
// keeps brings the answers back; sing-box accepts any source address.
func sharingRules(nets []SharedNet, tun, tunGateway string) string {
	var b strings.Builder
	b.WriteString("# MKConnect: Internet Sharing's devices go through the tunnel\n")
	for _, n := range nets {
		fmt.Fprintf(&b, "pass in quick on %s inet to { %s, 224.0.0.0/4, 255.255.255.255 } keep state\n", n.Iface, n.Subnet)
		fmt.Fprintf(&b, "pass in quick on %s route-to (%s %s) inet from %s to any keep state\n", n.Iface, tun, tunGateway, n.Subnet)
	}
	return b.String()
}

// sameNets reports whether two lists are the same, in any order.
func sameNets(a, b []SharedNet) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(n SharedNet) bool { return !slices.Contains(b, n) })
}

package engine

import (
	"fmt"
	"net"
	"strings"
)

// Another VPN that already carries the system's traffic would swallow ours:
// the routes our TUN adds are the same ones it has installed, so they're
// ignored and the traffic stays on the other tunnel, and disconnecting would
// remove the shared routes and break that VPN as well. So TUN mode refuses to
// start while another tunnel interface holds a default route.

// defaultRoute is an IPv4 route that covers (half of) the internet.
type defaultRoute struct {
	Interface string
	PrefixLen int // 0 = default route, 1 = 0.0.0.0/1 or 128.0.0.0/1
}

// Interface names of tunnels, by platform convention.
var tunnelPrefixes = []string{"utun", "tun", "tap", "ppp", "ipsec", "wg", "nordlynx", "proton"}

func tunnelInterface(name string) bool {
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// foreignTunnel returns the tunnel interface that carries a default route,
// or "" when the default route is on a physical interface.
func foreignTunnel(routes []defaultRoute) string {
	for _, r := range routes {
		if r.PrefixLen <= 1 && tunnelInterface(r.Interface) {
			return r.Interface
		}
	}
	return ""
}

// Processes of VPN apps that take over the system's routes.
var knownVPNApps = []string{"hiddify", "nekoray", "nekobox", "sing-box", "clash", "mihomo", "openvpn", "wireguard", "v2rayn", "v2raya", "outline"}

// checkOtherVPN returns an error when another VPN owns the system's traffic.
// When the routes can't be read, the connection goes ahead.
func checkOtherVPN() error {
	iface, err := tunnelDefaultRoute()
	if err != nil || iface == "" {
		// An interface that already has our tunnel address is just as bad: the
		// routes "via <address>" would lead into it instead of into our TUN.
		if iface = interfaceWithAddress(tunAddresses()); iface == "" {
			return nil
		}
	}
	msg := fmt.Sprintf("another VPN is active (interface %s)", iface)
	if apps := runningVPNApps(); len(apps) > 0 {
		msg += ", probably " + strings.Join(apps, " or ")
	}
	return fmt.Errorf("%s. Disconnect it first: while it runs the system traffic stays on it and MKConnect can't take it over", msg)
}

// interfaceWithAddress returns the interface that has one of the addresses.
func interfaceWithAddress(addrs []string) string {
	want := map[string]bool{}
	for _, a := range addrs {
		if ip, _, err := net.ParseCIDR(a); err == nil {
			want[ip.String()] = true
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		ifAddrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifAddrs {
			if ipn, ok := a.(*net.IPNet); ok && want[ipn.IP.String()] {
				return i.Name
			}
		}
	}
	return ""
}

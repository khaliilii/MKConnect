package engine

import (
	"math/bits"
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// tunnelDefaultRoute reads the routing table and returns the tunnel interface
// that carries a default route, if any.
func tunnelDefaultRoute() (string, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return "", err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return "", err
	}
	var routes []defaultRoute
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&unix.RTF_UP == 0 || rm.Flags&unix.RTF_HOST != 0 || len(rm.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} && dst.IP != [4]byte{128, 0, 0, 0} {
			continue
		}
		ones := 0
		if mask, ok := rm.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); ok {
			for _, b := range mask.IP {
				ones += bits.OnesCount8(b)
			}
		}
		if ones > 1 {
			continue
		}
		iface, err := net.InterfaceByIndex(rm.Index)
		if err != nil {
			continue
		}
		routes = append(routes, defaultRoute{Interface: iface.Name, PrefixLen: ones})
	}
	return foreignTunnel(routes), nil
}

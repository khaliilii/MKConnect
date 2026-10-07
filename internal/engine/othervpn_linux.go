package engine

import (
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// tunnelDefaultRoute reads the main routing table and returns the tunnel
// interface that carries a default route, if any. Another sing-box's policy
// routing (table 2022) counts as well.
func tunnelDefaultRoute() (string, error) {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, r := range rules {
		if r.Table == 2022 {
			return "sing-box routing rules", nil
		}
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return "", err
	}
	var routes []defaultRoute
	for _, r := range list {
		ones := 0
		if r.Dst != nil {
			ones, _ = r.Dst.Mask.Size()
		}
		if ones > 1 {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			continue
		}
		routes = append(routes, defaultRoute{Interface: link.Attrs().Name, PrefixLen: ones})
	}
	return foreignTunnel(routes), nil
}

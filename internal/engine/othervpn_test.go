package engine

import "testing"

func TestForeignTunnel(t *testing.T) {
	cases := []struct {
		name   string
		routes []defaultRoute
		want   string
	}{
		{"physical default", []defaultRoute{{"en0", 0}}, ""},
		{"no default at all", nil, ""},
		{"utun default (macOS)", []defaultRoute{{"en0", 0}, {"utun4", 0}}, "utun4"},
		{"split default (OpenVPN, sing-box)", []defaultRoute{{"en0", 0}, {"utun9", 1}}, "utun9"},
		{"linux tun", []defaultRoute{{"eth0", 0}, {"tun0", 1}}, "tun0"},
		{"wireguard", []defaultRoute{{"wg0", 0}}, "wg0"},
		{"tunnel with a narrower route only", []defaultRoute{{"eth0", 0}}, ""},
	}
	for _, c := range cases {
		if got := foreignTunnel(c.routes); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestTunnelDefaultRouteOnThisMachine(t *testing.T) {
	// Whatever the result, reading the routing table must work.
	iface, err := tunnelDefaultRoute()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tunnel with a default route: %q; running VPN apps: %v", iface, runningVPNApps())
}

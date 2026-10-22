package engine

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// trafficCounter is implemented by engines that count proxied bytes.
type trafficCounter interface {
	Traffic() (up, down int64)
}

// Session describes a running connection.
type Session struct {
	Core     string   // core actually carrying the traffic
	Inbounds []string // where local traffic enters
	Outbound string   // the server it leaves through

	counter   trafficCounter
	trafficFn func() (up, down int64, ok bool)
}

// NewSession describes a connection run elsewhere (e.g. by an elevated helper
// process); traffic reports its byte counters.
func NewSession(core string, inbounds []string, outbound string, traffic func() (up, down int64, ok bool)) *Session {
	return &Session{Core: core, Inbounds: inbounds, Outbound: outbound, trafficFn: traffic}
}

// Traffic returns bytes sent and received through the server so far. ok is
// false when the core can't report it (external binaries).
func (s *Session) Traffic() (up, down int64, ok bool) {
	if s.trafficFn != nil {
		return s.trafficFn()
	}
	if s.counter == nil {
		return 0, 0, false
	}
	up, down = s.counter.Traffic()
	return up, down, true
}

func newSession(p *profile.Profile, s *profile.Settings, primary Engine) *Session {
	core := s.Core
	switch {
	case p.Type == profile.TypeSSH && (s.Core == profile.CoreXray || (s.Core == profile.CoreExternal && s.ExternalKind == profile.CoreXray)):
		core = "ssh (built-in)"
	case s.Core == profile.CoreExternal:
		core = "external " + s.ExternalKind
	}

	// sing-box's mixed inbound and Xray's socks inbound both answer HTTP
	// proxy requests too; only the built-in SSH client is SOCKS5 alone.
	proxy := "SOCKS5 + HTTP"
	if core == "ssh (built-in)" {
		proxy = "SOCKS5"
	}
	addr := net.JoinHostPort(s.ListenAddress(), strconv.Itoa(s.ListenPort))
	inbounds := []string{fmt.Sprintf("%s %s", proxy, addr)}
	if s.AllowLAN {
		inbounds[0] += " (LAN)"
	}
	if s.Mode == profile.ModeTUN {
		inbounds = append(inbounds, "TUN "+tunAddresses(s.IPv6)[0]+" (all system traffic)")
		if len(s.ShareInterfaces) > 0 {
			inbounds = append(inbounds, "Gateway for devices on "+strings.Join(s.ShareInterfaces, ", "))
		}
	}

	out := []string{strings.ToUpper(p.Type[:1]) + p.Type[1:], p.Address()}
	if p.Transport.Network != "" {
		out = append(out, p.Transport.Network)
	} else if p.Transport.HeaderType == "http" {
		out = append(out, "tcp+http")
	}
	if p.TLS.Mode != "" {
		out = append(out, p.TLS.Mode)
	}
	if p.Type == profile.TypeSSH && p.UDPGWPort > 0 {
		u := fmt.Sprintf("udpgw :%d", p.UDPGWPort)
		if p.UDPGWDNS {
			u += " + transparent DNS"
		}
		out = append(out, u)
	}

	session := &Session{Core: core, Inbounds: inbounds, Outbound: strings.Join(out, " · ")}
	if c, ok := primary.(trafficCounter); ok {
		session.counter = c
	}
	return session
}

// ProxyProtocols names what the local proxy speaks: SOCKS5 and HTTP, except
// for the built-in SSH client, which serves SOCKS5 only.
func (s *Session) ProxyProtocols() string {
	if s.Core == "ssh (built-in)" {
		return "SOCKS5"
	}
	return "SOCKS5 + HTTP"
}

// LANAddresses returns the addresses other devices on the network can use as
// their proxy, when LAN sharing is on.
func LANAddresses(s *profile.Settings) []string {
	if !s.AllowLAN {
		return nil
	}
	addrs, _ := net.InterfaceAddrs()
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, net.JoinHostPort(n.IP.String(), strconv.Itoa(s.ListenPort)))
	}
	return out
}

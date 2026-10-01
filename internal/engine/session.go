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

	counter trafficCounter
}

// Traffic returns bytes sent and received through the server so far. ok is
// false when the core can't report it (external binaries).
func (s *Session) Traffic() (up, down int64, ok bool) {
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

	proxy := "SOCKS5"
	if strings.HasPrefix(core, profile.CoreSingBox) || core == "external "+profile.CoreSingBox {
		proxy = "SOCKS5 + HTTP"
	}
	addr := net.JoinHostPort(s.ListenAddress(), strconv.Itoa(s.ListenPort))
	inbounds := []string{fmt.Sprintf("%s %s", proxy, addr)}
	if s.AllowLAN {
		inbounds[0] += " (LAN)"
	}
	if s.Mode == profile.ModeTUN {
		inbounds = append(inbounds, "TUN 172.19.0.1/30 (all system traffic)")
		if len(s.ShareInterfaces) > 0 {
			inbounds = append(inbounds, "Gateway for devices on "+strings.Join(s.ShareInterfaces, ", "))
		}
	}

	out := []string{strings.ToUpper(p.Type[:1]) + p.Type[1:], p.Address()}
	if p.Transport.Network != "" {
		out = append(out, p.Transport.Network)
	}
	if p.TLS.Mode != "" {
		out = append(out, p.TLS.Mode)
	}

	session := &Session{Core: core, Inbounds: inbounds, Outbound: strings.Join(out, " · ")}
	if c, ok := primary.(trafficCounter); ok {
		session.counter = c
	}
	return session
}

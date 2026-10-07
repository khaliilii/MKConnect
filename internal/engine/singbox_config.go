package engine

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// obj is shorthand for a JSON object in generated configs.
type obj = map[string]any

const (
	tagProxy  = "proxy"
	tagDirect = "direct"
	tagLocal  = "local"
	tagRemote = "remote"
)

var privateCIDRs = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

// tunOptions describes the virtual interface for TUN mode.
type tunOptions struct {
	// ExcludeAddrs are routed around the TUN (the proxy server itself, so the
	// core's own connection doesn't loop back into the tunnel).
	ExcludeAddrs []string
	// Gateway routes traffic forwarded from other interfaces (gateway mode).
	Gateway bool
}

// TUNName is the name of the TUN interface on systems that allow choosing it
// (Windows needs a fixed name to set up Internet Connection Sharing).
const TUNName = "MKConnect"

// tunAddresses are the TUN interface's addresses. They are deliberately not
// sing-box's defaults (172.19.0.1, fdfe:dcba:9876::1): other sing-box based
// apps (Hiddify, nekoray, ...) use those, and when such an app's interface is
// still around, routes "via 172.19.0.1" lead into it instead of into ours.
func tunAddresses() []string { return []string{"172.19.77.1/30", "fd6d:6b63:6f6e::1/126"} }

// singBoxConfig builds a complete sing-box config that exposes a mixed
// (SOCKS5 + HTTP) proxy and, when tun is set, a TUN interface.
func singBoxConfig(p *profile.Profile, s *profile.Settings, tun *tunOptions) (obj, error) {
	out, err := singBoxOutbound(p)
	if err != nil {
		return nil, err
	}
	out["tag"] = tagProxy
	return singBoxBase(s, out, tun), nil
}

// singBoxTUNConfig builds a sing-box config that only provides the TUN
// interface and forwards everything to another core's local SOCKS5 proxy.
func singBoxTUNConfig(s *profile.Settings, socksPort int, tun *tunOptions) obj {
	out := obj{
		"type":        "socks",
		"tag":         tagProxy,
		"server":      "127.0.0.1",
		"server_port": socksPort,
		"version":     "5",
	}
	if s.ProxyUser != "" {
		out["username"], out["password"] = s.ProxyUser, s.ProxyPass
	}
	cfg := singBoxBase(s, out, tun)
	// The other core already serves the proxy port; drop our own mixed inbound.
	cfg["inbounds"] = cfg["inbounds"].([]obj)[1:]
	return cfg
}

func singBoxBase(s *profile.Settings, proxyOut obj, tun *tunOptions) obj {
	mixed := obj{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      s.ListenAddress(),
		"listen_port": s.ListenPort,
	}
	if s.ProxyUser != "" {
		mixed["users"] = []obj{{"username": s.ProxyUser, "password": s.ProxyPass}}
	}
	inbounds := []obj{mixed}

	dnsServers := []obj{{"type": "local", "tag": tagLocal}}
	rules := []obj{{"ip_is_private": true, "outbound": tagDirect}}
	dns := obj{"servers": dnsServers, "final": tagLocal}

	if tun != nil {
		t := obj{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      tunAddresses(),
			"auto_route":   true,
			"strict_route": true,
		}
		if len(tun.ExcludeAddrs) > 0 {
			t["route_exclude_address"] = tun.ExcludeAddrs
		}
		if s.TUNStack != "" {
			t["stack"] = s.TUNStack
		}
		if s.TUNMTU > 0 {
			t["mtu"] = s.TUNMTU
		}
		if runtime.GOOS == "windows" {
			t["interface_name"] = TUNName
		}
		if tun.Gateway {
			switch runtime.GOOS {
			case "linux":
				// nftables-based redirection also captures traffic forwarded from LAN devices.
				t["auto_redirect"] = true
			case "windows":
				// strict_route's firewall rules would block the ICS side (DHCP/DNS for clients).
				t["strict_route"] = false
			}
		}
		inbounds = append(inbounds, t)

		// Resolve through the tunnel over TCP (SSH and SOCKS upstreams can't carry UDP).
		dns["servers"] = append(dnsServers, obj{
			"type": "tcp", "tag": tagRemote, "server": s.RemoteDNS, "detour": tagProxy,
		})
		dns["final"] = tagRemote
		rules = append([]obj{
			{"action": "sniff"},
			{"protocol": "dns", "action": "hijack-dns"},
		}, rules...)
	}

	route := obj{
		"rules":                   rules,
		"final":                   tagProxy,
		"default_domain_resolver": tagLocal,
	}
	if tun != nil {
		// Keep the cores' own connections on the physical interface. Only needed
		// with TUN, and interface monitoring isn't permitted for Android apps.
		route["auto_detect_interface"] = true
	}
	return obj{
		"log":      obj{"level": logLevel(s), "timestamp": true},
		"dns":      dns,
		"inbounds": inbounds,
		"outbounds": []obj{
			proxyOut,
			{"type": "direct", "tag": tagDirect},
		},
		"route": route,
	}
}

func logLevel(s *profile.Settings) string {
	if s.LogLevel == "" {
		return "info"
	}
	return s.LogLevel
}

func singBoxOutbound(p *profile.Profile) (obj, error) {
	out := obj{"server": p.Server, "server_port": p.Port}
	switch p.Type {
	case profile.TypeSSH:
		out["type"], out["user"] = "ssh", p.User
		if p.Password != "" {
			out["password"] = p.Password
		}
		if p.PrivateKeyPath != "" {
			out["private_key_path"] = p.PrivateKeyPath
		}
		if p.HostKey != "" {
			out["host_key"] = []string{p.HostKey}
		}
		return out, nil
	case profile.TypeVMess:
		out["type"], out["uuid"], out["alter_id"] = "vmess", p.UUID, p.AlterID
		out["security"] = orDefault(p.Security, "auto")
		out["packet_encoding"] = "xudp"
	case profile.TypeVLESS:
		out["type"], out["uuid"] = "vless", p.UUID
		if p.Flow != "" {
			out["flow"] = p.Flow
		}
		out["packet_encoding"] = "xudp"
	case profile.TypeTrojan:
		out["type"], out["password"] = "trojan", p.Password
	case profile.TypeShadowsocks:
		out["type"], out["method"], out["password"] = "shadowsocks", p.Method, p.Password
		return out, nil
	case profile.TypeHysteria2:
		out["type"], out["password"] = "hysteria2", p.Password
		if p.ObfsPassword != "" {
			out["obfs"] = obj{"type": "salamander", "password": p.ObfsPassword}
		}
		if p.UpMbps > 0 {
			out["up_mbps"] = p.UpMbps
		}
		if p.DownMbps > 0 {
			out["down_mbps"] = p.DownMbps
		}
		out["tls"] = quicTLS(p, nil)
		return out, nil
	case profile.TypeTUIC:
		out["type"], out["uuid"], out["password"] = "tuic", p.UUID, p.Password
		out["congestion_control"] = orDefault(p.CongestionControl, "bbr")
		if p.UDPRelayMode != "" {
			out["udp_relay_mode"] = p.UDPRelayMode
		}
		out["tls"] = quicTLS(p, []string{"h3"})
		return out, nil
	default:
		return nil, fmt.Errorf("sing-box: unsupported profile type %q", p.Type)
	}

	transport, err := singBoxTransport(&p.Transport)
	if err != nil {
		return nil, err
	}
	if transport != nil {
		out["transport"] = transport
	}
	if tls := singBoxTLS(p); tls != nil {
		out["tls"] = tls
	}
	return out, nil
}

func singBoxTransport(t *profile.Transport) (obj, error) {
	switch t.Network {
	case "", "tcp":
		if t.HeaderType != "http" {
			return nil, nil
		}
		// sing-box's http transport is plain HTTP/1.1 without TLS, which is
		// what v2ray's tcp HTTP header obfuscation speaks.
		h := obj{"type": "http", "method": "GET", "path": orDefault(t.Path, "/")}
		if hosts := splitHosts(t.Host); len(hosts) > 0 {
			h["host"] = hosts
		}
		return h, nil
	case "ws":
		ws := obj{"type": "ws"}
		path, earlyData := splitEarlyData(t.Path)
		if path != "" {
			ws["path"] = path
		}
		if earlyData > 0 {
			ws["max_early_data"] = earlyData
			ws["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		if t.Host != "" {
			ws["headers"] = obj{"Host": t.Host}
		}
		return ws, nil
	case "grpc":
		return obj{"type": "grpc", "service_name": t.ServiceName}, nil
	case "httpupgrade":
		up := obj{"type": "httpupgrade", "path": t.Path}
		if t.Host != "" {
			up["host"] = t.Host
		}
		return up, nil
	case "xhttp":
		return nil, fmt.Errorf("sing-box does not support the xhttp transport, use the xray core")
	}
	return nil, fmt.Errorf("sing-box: unsupported transport %q", t.Network)
}

// splitHosts splits a comma-separated host list.
func splitHosts(s string) []string {
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// splitEarlyData turns the v2rayN "/path?ed=2048" convention into path + early data size.
func splitEarlyData(path string) (string, int) {
	base, query, ok := strings.Cut(path, "?")
	if !ok {
		return path, 0
	}
	for _, kv := range strings.Split(query, "&") {
		if v, ok := strings.CutPrefix(kv, "ed="); ok {
			if n, err := strconv.Atoi(v); err == nil {
				return base, n
			}
		}
	}
	return path, 0
}

func singBoxTLS(p *profile.Profile) obj {
	t := &p.TLS
	if t.Mode == "" {
		return nil
	}
	tls := obj{"enabled": true, "server_name": orDefault(t.SNI, p.Server)}
	if len(t.ALPN) > 0 {
		tls["alpn"] = t.ALPN
	}
	if t.Insecure {
		tls["insecure"] = true
	}
	fp := t.Fingerprint
	if t.Mode == "reality" {
		fp = orDefault(fp, "chrome") // REALITY requires uTLS
		tls["reality"] = obj{"enabled": true, "public_key": t.RealityPublicKey, "short_id": t.RealityShortID}
	}
	if fp != "" {
		tls["utls"] = obj{"enabled": true, "fingerprint": fp}
	}
	return tls
}

// quicTLS is the TLS block for QUIC-based protocols, which always use TLS.
func quicTLS(p *profile.Profile, defaultALPN []string) obj {
	tls := obj{"enabled": true, "server_name": orDefault(p.TLS.SNI, p.Server)}
	if alpn := p.TLS.ALPN; len(alpn) > 0 {
		tls["alpn"] = alpn
	} else if len(defaultALPN) > 0 {
		tls["alpn"] = defaultALPN
	}
	if p.TLS.Insecure {
		tls["insecure"] = true
	}
	return tls
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

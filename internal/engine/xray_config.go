package engine

import (
	"fmt"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// xrayConfig builds an Xray config exposing a local SOCKS5 proxy (with UDP) for the profile.
func xrayConfig(p *profile.Profile, s *profile.Settings) (obj, error) {
	out, err := xrayOutbound(p)
	if err != nil {
		return nil, err
	}
	out["tag"] = tagProxy

	socks := obj{"udp": true}
	if s.ProxyUser != "" {
		socks["auth"] = "password"
		socks["accounts"] = []obj{{"user": s.ProxyUser, "pass": s.ProxyPass}}
	} else {
		socks["auth"] = "noauth"
	}

	return obj{
		"log": obj{"loglevel": xrayLogLevel(s)},
		"inbounds": []obj{{
			"tag":      "socks-in",
			"listen":   s.ListenAddress(),
			"port":     s.ListenPort,
			"protocol": "socks",
			"settings": socks,
			"sniffing": obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": []obj{
			out,
			{"tag": tagDirect, "protocol": "freedom"},
		},
		"routing": obj{
			"rules": []obj{{"type": "field", "ip": privateCIDRs, "outboundTag": tagDirect}},
		},
	}, nil
}

func xrayLogLevel(s *profile.Settings) string {
	switch s.LogLevel {
	case "debug", "info", "warning", "error", "none":
		return s.LogLevel
	case "warn":
		return "warning"
	}
	return "warning"
}

func xrayOutbound(p *profile.Profile) (obj, error) {
	var out obj
	switch p.Type {
	case profile.TypeVMess:
		out = obj{"protocol": "vmess", "settings": obj{"vnext": []obj{{
			"address": p.Server, "port": p.Port,
			"users": []obj{{"id": p.UUID, "alterId": p.AlterID, "security": orDefault(p.Security, "auto")}},
		}}}}
	case profile.TypeVLESS:
		user := obj{"id": p.UUID, "encryption": "none"}
		if p.Flow != "" {
			user["flow"] = p.Flow
		}
		out = obj{"protocol": "vless", "settings": obj{"vnext": []obj{{
			"address": p.Server, "port": p.Port, "users": []obj{user},
		}}}}
	case profile.TypeTrojan:
		out = obj{"protocol": "trojan", "settings": obj{"servers": []obj{{
			"address": p.Server, "port": p.Port, "password": p.Password,
		}}}}
	case profile.TypeShadowsocks:
		out = obj{"protocol": "shadowsocks", "settings": obj{"servers": []obj{{
			"address": p.Server, "port": p.Port, "method": p.Method, "password": p.Password,
		}}}}
		return out, nil
	case profile.TypeSSH:
		return nil, fmt.Errorf("xray has no SSH outbound")
	default:
		return nil, fmt.Errorf("xray: unsupported profile type %q", p.Type)
	}

	stream, err := xrayStream(p)
	if err != nil {
		return nil, err
	}
	out["streamSettings"] = stream
	return out, nil
}

func xrayStream(p *profile.Profile) (obj, error) {
	t := &p.Transport
	network := orDefault(t.Network, "tcp")
	stream := obj{"network": network}
	switch network {
	case "tcp":
	case "ws":
		stream["wsSettings"] = obj{"path": t.Path, "host": t.Host}
	case "grpc":
		stream["grpcSettings"] = obj{"serviceName": t.ServiceName}
	case "httpupgrade":
		stream["httpupgradeSettings"] = obj{"path": t.Path, "host": t.Host}
	case "xhttp":
		stream["xhttpSettings"] = obj{"path": t.Path, "host": t.Host}
	default:
		return nil, fmt.Errorf("xray: unsupported transport %q", network)
	}

	tls := &p.TLS
	switch tls.Mode {
	case "":
		stream["security"] = "none"
	case "tls":
		if tls.Insecure {
			return nil, fmt.Errorf("xray no longer supports insecure TLS (allowInsecure was removed), use the sing-box core")
		}
		s := obj{"serverName": orDefault(tls.SNI, p.Server)}
		if len(tls.ALPN) > 0 {
			s["alpn"] = tls.ALPN
		}
		if tls.Fingerprint != "" {
			s["fingerprint"] = tls.Fingerprint
		}
		stream["security"], stream["tlsSettings"] = "tls", s
	case "reality":
		stream["security"] = "reality"
		stream["realitySettings"] = obj{
			"serverName":  tls.SNI,
			"fingerprint": orDefault(tls.Fingerprint, "chrome"),
			"publicKey":   tls.RealityPublicKey,
			"shortId":     tls.RealityShortID,
		}
	}
	return stream, nil
}

// Package profile defines connection profiles (SSH, VMess, VLESS, Trojan,
// Shadowsocks) and the app settings that decide how they are run.
package profile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
)

// Protocol types.
const (
	TypeSSH         = "ssh"
	TypeVMess       = "vmess"
	TypeVLESS       = "vless"
	TypeTrojan      = "trojan"
	TypeShadowsocks = "shadowsocks"
	TypeHysteria2   = "hysteria2"
	TypeTUIC        = "tuic"
)

// Types lists every supported protocol type.
var Types = []string{TypeSSH, TypeVMess, TypeVLESS, TypeTrojan, TypeShadowsocks, TypeHysteria2, TypeTUIC}

// Profile is one server account. Fields that don't apply to a protocol are left empty.
type Profile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Group  string `json:"group,omitempty"` // Group.ID, empty for ungrouped
	Type   string `json:"type"`
	Server string `json:"server"`
	Port   int    `json:"port"`

	// SSH
	User           string `json:"user,omitempty"`
	Password       string `json:"password,omitempty"` // also Trojan / Shadowsocks password
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	HostKey        string `json:"host_key,omitempty"` // authorized_keys format, pinned on first connect

	// VMess / VLESS
	UUID     string `json:"uuid,omitempty"`
	AlterID  int    `json:"alter_id,omitempty"`
	Security string `json:"security,omitempty"` // VMess cipher: auto, aes-128-gcm, chacha20-poly1305, none
	Flow     string `json:"flow,omitempty"`     // VLESS flow, e.g. xtls-rprx-vision

	// Shadowsocks
	Method string `json:"method,omitempty"`

	// Hysteria2 (Password is the auth string)
	ObfsPassword string `json:"obfs_password,omitempty"` // salamander obfuscation
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`

	// TUIC (UUID + Password)
	CongestionControl string `json:"congestion_control,omitempty"` // bbr, cubic, new_reno
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`     // native, quic

	Transport Transport `json:"transport,omitzero"`
	TLS       TLS       `json:"tls,omitzero"`

	// Test is the result of the last server test (nil = never tested).
	Test *TestResult `json:"test,omitempty"`
}

// Transport is the V2Ray transport layer.
type Transport struct {
	Network     string `json:"network,omitempty"` // tcp (default), ws, grpc, httpupgrade, xhttp
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"` // gRPC
	// HeaderType "http" disguises a plain tcp transport as HTTP/1.1
	// (v2ray's tcp header obfuscation); Path and Host then go in the request.
	HeaderType string `json:"header_type,omitempty"`
}

// TLS holds TLS / REALITY client settings.
type TLS struct {
	Mode             string   `json:"mode,omitempty"` // "", tls, reality
	SNI              string   `json:"sni,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	Fingerprint      string   `json:"fingerprint,omitempty"` // uTLS fingerprint, e.g. chrome
	Insecure         bool     `json:"insecure,omitempty"`
	RealityPublicKey string   `json:"reality_public_key,omitempty"`
	RealityShortID   string   `json:"reality_short_id,omitempty"`
}

// NewID returns a short random profile id.
func NewID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Address returns host:port of the server.
func (p *Profile) Address() string {
	return net.JoinHostPort(p.Server, strconv.Itoa(p.Port))
}

// Validate checks that the fields required by the profile type are set.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	if p.Server == "" {
		return fmt.Errorf("server is required")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("invalid port %d", p.Port)
	}
	switch p.Type {
	case TypeSSH:
		if p.User == "" {
			return fmt.Errorf("ssh: user is required")
		}
		if p.Password == "" && p.PrivateKeyPath == "" {
			return fmt.Errorf("ssh: password or private key is required")
		}
	case TypeVMess, TypeVLESS:
		if p.UUID == "" {
			return fmt.Errorf("%s: uuid is required", p.Type)
		}
	case TypeTrojan:
		if p.Password == "" {
			return fmt.Errorf("trojan: password is required")
		}
	case TypeShadowsocks:
		if p.Password == "" || p.Method == "" {
			return fmt.Errorf("shadowsocks: method and password are required")
		}
	case TypeHysteria2:
		if p.Password == "" {
			return fmt.Errorf("hysteria2: password is required")
		}
	case TypeTUIC:
		if p.UUID == "" || p.Password == "" {
			return fmt.Errorf("tuic: uuid and password are required")
		}
	default:
		return fmt.Errorf("unknown profile type %q", p.Type)
	}
	switch p.Transport.Network {
	case "", "tcp", "ws", "grpc", "httpupgrade", "xhttp":
	default:
		return fmt.Errorf("unsupported transport %q", p.Transport.Network)
	}
	switch p.Transport.HeaderType {
	case "":
	case "http":
		if p.Transport.Network != "" && p.Transport.Network != "tcp" {
			return fmt.Errorf("the HTTP header only applies to the tcp transport")
		}
	default:
		return fmt.Errorf("unsupported tcp header %q", p.Transport.HeaderType)
	}
	switch p.TLS.Mode {
	case "", "tls":
	case "reality":
		if p.TLS.RealityPublicKey == "" {
			return fmt.Errorf("reality: public key is required")
		}
	default:
		return fmt.Errorf("unsupported tls mode %q", p.TLS.Mode)
	}
	return nil
}

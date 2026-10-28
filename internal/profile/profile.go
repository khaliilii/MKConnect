// Package profile defines connection profiles (SSH, VMess, VLESS, Trojan,
// Shadowsocks) and the app settings that decide how they are run.
package profile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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
	// UDPGWPort is the port of badvpn-udpgw on the SSH server (0 = none):
	// carries UDP through the tunnel. UDPGWDNS makes udpgw answer DNS with
	// the server's own resolver (transparent DNS), overriding the DNS setting.
	UDPGWPort int  `json:"udpgw_port,omitempty"`
	UDPGWDNS  bool `json:"udpgw_dns,omitempty"`
	// Payload is an HTTP request sent on the raw socket before the SSH
	// handshake (the "SSH payload" of HTTP Injector and KPN Tunnel), so
	// filters that only pass HTTP(S) traffic see a request to an allowed
	// host. Placeholders: [host] [port] [host_port] [raw] [crlf] [cr] [lf]
	// [split] [delay_split]. PayloadProxy ("host:port") sends the payload to
	// a proxy instead of the SSH server; set on its own it is a plain HTTP
	// CONNECT proxy.
	Payload      string `json:"payload,omitempty"`
	PayloadProxy string `json:"payload_proxy,omitempty"`

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
	// PinnedCertSHA256 trusts a server certificate by the SHA-256 of a
	// certificate in its chain (hex, comma-separated; share links' "pcs"),
	// instead of by name: providers use it to front through a CDN whose
	// certificate doesn't carry the SNI they send. VerifyByName ("vcn")
	// checks the certificate against these names instead of the SNI.
	PinnedCertSHA256 string `json:"pinned_cert_sha256,omitempty"`
	VerifyByName     string `json:"verify_by_name,omitempty"`
}

// NewID returns a short random profile id.
func NewID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// IsInfo reports whether the "account" is a message a subscription sends in
// an account's place (data used, days left, "update the app", which accounts
// suit which network): its server is not a host name but text such as
// "Asgard By ODIN", or a bare number such as "1111". Such entries are kept,
// since their names carry the message, but can't be connected or tested.
func (p *Profile) IsInfo() bool {
	server := strings.TrimSpace(p.Server)
	if strings.ContainsAny(server, " \t") {
		return true
	}
	if server == "" {
		return false
	}
	for _, c := range server { // all digits: neither an address nor a name
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ErrInfoEntry is returned for connecting to or testing an IsInfo entry.
var ErrInfoEntry = errors.New("this entry is a message from the subscription, not a server")

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
		if p.UDPGWPort < 0 || p.UDPGWPort > 65535 {
			return fmt.Errorf("ssh: invalid udpgw port %d", p.UDPGWPort)
		}
		if p.User == "" {
			return fmt.Errorf("ssh: user is required")
		}
		if p.Password == "" && p.PrivateKeyPath == "" {
			return fmt.Errorf("ssh: password or private key is required")
		}
		if err := validateHostPort(p.PayloadProxy); err != nil {
			return fmt.Errorf("ssh: payload proxy: %w", err)
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
		if p.UDPGWPort != 0 {
			return fmt.Errorf("udpgw only applies to SSH")
		}
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
	if p.Type != TypeSSH && (p.Payload != "" || p.PayloadProxy != "") {
		return fmt.Errorf("the payload only applies to SSH")
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
	for _, pin := range strings.Split(p.TLS.PinnedCertSHA256, ",") {
		if pin = strings.ReplaceAll(strings.TrimSpace(pin), ":", ""); pin == "" {
			continue
		}
		if b, err := hex.DecodeString(pin); err != nil || len(b) != 32 {
			return fmt.Errorf("tls: pinned certificate %q is not a SHA-256 in hex", pin)
		}
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

// validateHostPort accepts an empty value or a "host:port" address.
func validateHostPort(addr string) error {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port", addr)
	}
	if host == "" {
		return fmt.Errorf("%q has no host", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q has an invalid port", addr)
	}
	return nil
}

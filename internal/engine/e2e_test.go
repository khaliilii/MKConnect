//go:build !no_singbox

package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	sbservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	sbjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/khaliilii/MKConnect/internal/profile"
)

const testUUID = "bf000d23-0752-40b4-affe-68f7707a9661"

// startProtocolServer runs a real VMess/VLESS/Trojan/Shadowsocks server
// (sing-box inbounds) so the clients can be tested end to end.
func startProtocolServer(t *testing.T, inbounds []obj) {
	t.Helper()
	ins := inbound.NewRegistry()
	vmess.RegisterInbound(ins)
	vless.RegisterInbound(ins)
	trojan.RegisterInbound(ins)
	shadowsocks.RegisterInbound(ins)
	outs := outbound.NewRegistry()
	direct.RegisterOutbound(outs)
	dnsReg := dns.NewTransportRegistry()
	local.RegisterTransport(dnsReg)
	ctx := box.Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())),
		ins, outs, endpoint.NewRegistry(), dnsReg, sbservice.NewRegistry(), certificate.NewRegistry())

	cfg, _ := json.Marshal(obj{
		"log":       obj{"level": "error"},
		"dns":       obj{"servers": []obj{{"type": "local", "tag": "local"}}},
		"inbounds":  inbounds,
		"outbounds": []obj{{"type": "direct", "tag": "direct"}},
		"route":     obj{"default_domain_resolver": "local"},
	})
	opts, err := sbjson.UnmarshalExtendedContext[option.Options](ctx, cfg)
	if err != nil {
		t.Fatalf("server config: %v\n%s", err, cfg)
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(ctx))
	server, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); cancel() })
}

// selfSignedTLS returns certificate and key PEM lines for 127.0.0.1 / localhost.
func selfSignedTLS(t *testing.T) (cert, key []string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	lines := func(b []byte) []string { return strings.Split(strings.TrimSpace(string(b)), "\n") }
	return lines(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		lines(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

type e2eCase struct {
	name    string
	inbound obj
	profile profile.Profile
	cores   []string
}

func TestEndToEndProtocols(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	cert, key := selfSignedTLS(t)
	both := []string{profile.CoreSingBox, profile.CoreXray}
	port := func() int { return freePort(t) }

	cases := []e2eCase{
		{
			name:    "vmess-tcp",
			inbound: obj{"type": "vmess", "users": []obj{{"uuid": testUUID, "alterId": 0}}},
			profile: profile.Profile{Type: profile.TypeVMess, UUID: testUUID, Security: "aes-128-gcm"},
			cores:   both,
		},
		{
			name: "vmess-ws",
			inbound: obj{"type": "vmess", "users": []obj{{"uuid": testUUID}},
				"transport": obj{"type": "ws", "path": "/ray"}},
			profile: profile.Profile{Type: profile.TypeVMess, UUID: testUUID,
				Transport: profile.Transport{Network: "ws", Path: "/ray"}},
			cores: both,
		},
		{
			name:    "vless-tcp",
			inbound: obj{"type": "vless", "users": []obj{{"uuid": testUUID}}},
			profile: profile.Profile{Type: profile.TypeVLESS, UUID: testUUID},
			cores:   both,
		},
		{
			name: "vless-grpc",
			inbound: obj{"type": "vless", "users": []obj{{"uuid": testUUID}},
				"transport": obj{"type": "grpc", "service_name": "gun"}},
			profile: profile.Profile{Type: profile.TypeVLESS, UUID: testUUID,
				Transport: profile.Transport{Network: "grpc", ServiceName: "gun"}},
			cores: []string{profile.CoreSingBox}, // sing-box's lite gRPC server isn't compatible with xray's client
		},
		{
			name: "vless-httpupgrade",
			inbound: obj{"type": "vless", "users": []obj{{"uuid": testUUID}},
				"transport": obj{"type": "httpupgrade", "path": "/up"}},
			profile: profile.Profile{Type: profile.TypeVLESS, UUID: testUUID,
				Transport: profile.Transport{Network: "httpupgrade", Path: "/up"}},
			// A sing-box client and a sing-box server disagree on VLESS over httpupgrade;
			// the sing-box client against an Xray server is covered in e2e_xray_test.go.
			cores: []string{profile.CoreXray},
		},
		{
			name: "vmess-httpupgrade",
			inbound: obj{"type": "vmess", "users": []obj{{"uuid": testUUID}},
				"transport": obj{"type": "httpupgrade", "path": "/up"}},
			profile: profile.Profile{Type: profile.TypeVMess, UUID: testUUID,
				Transport: profile.Transport{Network: "httpupgrade", Path: "/up"}},
			cores: both,
		},
		{
			name: "trojan-httpupgrade",
			inbound: obj{"type": "trojan", "users": []obj{{"password": "pw"}},
				"transport": obj{"type": "httpupgrade", "path": "/up"}},
			profile: profile.Profile{Type: profile.TypeTrojan, Password: "pw",
				Transport: profile.Transport{Network: "httpupgrade", Path: "/up"}},
			cores: both,
		},
		{
			name:    "trojan",
			inbound: obj{"type": "trojan", "users": []obj{{"password": "pw"}}},
			profile: profile.Profile{Type: profile.TypeTrojan, Password: "pw"},
			cores:   both,
		},
		{
			name: "trojan-tls",
			inbound: obj{"type": "trojan", "users": []obj{{"password": "pw"}},
				"tls": obj{"enabled": true, "certificate": cert, "key": key}},
			profile: profile.Profile{Type: profile.TypeTrojan, Password: "pw",
				TLS: profile.TLS{Mode: "tls", SNI: "localhost", Insecure: true}},
			cores: []string{profile.CoreSingBox}, // xray can't skip verification of a self-signed cert
		},
		{
			name:    "shadowsocks-aead",
			inbound: obj{"type": "shadowsocks", "method": "aes-256-gcm", "password": "pw"},
			profile: profile.Profile{Type: profile.TypeShadowsocks, Method: "aes-256-gcm", Password: "pw"},
			cores:   both,
		},
		{
			name:    "shadowsocks-2022",
			inbound: obj{"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": "8JCsPssfgS8tiRwiMlhARg=="},
			profile: profile.Profile{Type: profile.TypeShadowsocks, Method: "2022-blake3-aes-128-gcm", Password: "8JCsPssfgS8tiRwiMlhARg=="},
			cores:   both,
		},
	}

	target := newTarget(t)
	url := strings.Replace(target.URL, "127.0.0.1", "localhost", 1) // domains go through the proxy
	var inbounds []obj
	for i := range cases {
		c := &cases[i]
		p := port()
		c.inbound["tag"], c.inbound["listen"], c.inbound["listen_port"] = c.name, "127.0.0.1", p
		c.profile.Name, c.profile.Server, c.profile.Port = c.name, "127.0.0.1", p
		inbounds = append(inbounds, c.inbound)
	}
	startProtocolServer(t, inbounds)

	for _, c := range cases {
		for _, core := range c.cores {
			if core == profile.CoreXray && startXray == nil {
				continue
			}
			t.Run(c.name+"/"+core, func(t *testing.T) {
				s := testSettings(t)
				s.Core = core
				s.ProxyUser, s.ProxyPass = "u", "p"
				p := c.profile
				engines, err := start(t.Context(), &p, &s)
				for _, e := range engines {
					defer e.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				waitListening(t, s.ListenPort)

				for i := range 3 { // several requests over the same tunnel
					if body := getThroughSOCKS(t, s.ListenPort, "u", "p", url); body != "hello through tunnel" {
						t.Fatalf("request %d: unexpected body %q", i, body)
					}
				}
				_, down := engines[0].(trafficCounter).Traffic()
				if down < 3*int64(len("hello through tunnel")) {
					t.Fatalf("download not counted: %d", down)
				}
			})
		}
	}
}

// TestLANSharing checks the proxy is reachable on a LAN address and enforces its password.
func TestLANSharing(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	var lanIP string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			lanIP = n.IP.String()
			break
		}
	}
	if lanIP == "" {
		t.Skip("no LAN address")
	}

	ssPort := freePort(t)
	startProtocolServer(t, []obj{{"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ssPort,
		"method": "aes-256-gcm", "password": "pw"}})
	p := profile.Profile{Name: "ss", Type: profile.TypeShadowsocks, Server: "127.0.0.1", Port: ssPort, Method: "aes-256-gcm", Password: "pw"}

	s := testSettings(t)
	s.AllowLAN, s.ProxyUser, s.ProxyPass = true, "friend", "secret"
	engines, err := start(t.Context(), &p, &s)
	for _, e := range engines {
		defer e.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	waitListening(t, s.ListenPort)

	target := newTarget(t)
	url := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	if body := getThroughSOCKSAt(t, lanIP, s.ListenPort, "friend", "secret", url); body != "hello through tunnel" {
		t.Fatalf("via LAN address: %q", body)
	}
	if _, err := tryThroughSOCKSAt(lanIP, s.ListenPort, "friend", "wrong", url); err == nil {
		t.Fatal("wrong proxy password accepted")
	}
}

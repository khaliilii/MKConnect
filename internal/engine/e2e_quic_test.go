//go:build with_quic && !no_singbox

package engine

import (
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/tuic"

	"github.com/khaliilii/MKConnect/internal/profile"
)

func init() {
	registerQUICServerInbounds = func(r *inbound.Registry) {
		hysteria2.RegisterInbound(r)
		tuic.RegisterInbound(r)
	}
}

// TestEndToEndQUIC runs real Hysteria2 and TUIC servers and connects through
// them with links parsed the way they come from the clipboard.
func TestEndToEndQUIC(t *testing.T) {
	cert, key := selfSignedTLS(t)
	tls := obj{"enabled": true, "certificate": cert, "key": key, "alpn": []string{"h3"}}
	hyPort, tuicPort := freePort(t), freePort(t)
	startProtocolServer(t, []obj{
		{"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": hyPort,
			"users": []obj{{"password": "secret"}}, "obfs": obj{"type": "salamander", "password": "ob"}, "tls": tls},
		{"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": tuicPort,
			"users": []obj{{"uuid": testUUID, "password": "pw"}}, "congestion_control": "bbr", "tls": tls},
	})

	target := newTarget(t)
	url := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	links := map[string]string{
		"hysteria2": "hy2://secret@127.0.0.1:" + itoaPort(hyPort) + "?sni=localhost&insecure=1&obfs=salamander&obfs-password=ob#hy",
		"tuic":      "tuic://" + testUUID + ":pw@127.0.0.1:" + itoaPort(tuicPort) + "?congestion_control=bbr&alpn=h3&sni=localhost&allow_insecure=1#tu",
	}
	for name, link := range links {
		t.Run(name, func(t *testing.T) {
			p, err := profile.ParseLink(link)
			if err != nil {
				t.Fatal(err)
			}
			s := testSettings(t)
			engines, err := start(t.Context(), &p, &s)
			for _, e := range engines {
				defer e.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			waitListening(t, s.ListenPort)
			for i := range 3 {
				if body := getThroughSOCKS(t, s.ListenPort, "", "", url); body != "hello through tunnel" {
					t.Fatalf("request %d: %q", i, body)
				}
			}
			if _, down := engines[0].(trafficCounter).Traffic(); down == 0 {
				t.Fatal("download not counted")
			}
		})
	}

	// The xray core can't carry these; the error must say what to do.
	p, _ := profile.ParseLink(links["tuic"])
	s := testSettings(t)
	s.Core = profile.CoreXray
	if _, err := start(t.Context(), &p, &s); err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Fatalf("expected a 'use sing-box' error, got %v", err)
	}
}

func itoaPort(n int) string { return strconv.Itoa(n) }

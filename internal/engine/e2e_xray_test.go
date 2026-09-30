//go:build !no_singbox && !no_xray

package engine

import (
	"strings"
	"testing"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestSingBoxClientAgainstXrayServer covers the common real-world setup:
// servers run Xray (3x-ui, Marzban), clients use the sing-box core.
func TestSingBoxClientAgainstXrayServer(t *testing.T) {
	cases := []struct {
		name    string
		stream  obj
		profile profile.Profile
	}{
		{"vless-httpupgrade", obj{"network": "httpupgrade", "httpupgradeSettings": obj{"path": "/up"}},
			profile.Profile{Transport: profile.Transport{Network: "httpupgrade", Path: "/up"}}},
		{"vless-ws", obj{"network": "ws", "wsSettings": obj{"path": "/ws"}},
			profile.Profile{Transport: profile.Transport{Network: "ws", Path: "/ws"}}},
		{"vless-grpc", obj{"network": "grpc", "grpcSettings": obj{"serviceName": "gun"}},
			profile.Profile{Transport: profile.Transport{Network: "grpc", ServiceName: "gun"}}},
		{"vless-tcp", obj{"network": "tcp"}, profile.Profile{}},
	}
	target := newTarget(t)
	url := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			port := freePort(t)
			server, _ := marshal(obj{
				"log": obj{"loglevel": "error"},
				"inbounds": []obj{{
					"listen": "127.0.0.1", "port": port, "protocol": "vless",
					"settings":       obj{"clients": []obj{{"id": testUUID}}, "decryption": "none"},
					"streamSettings": c.stream,
				}},
				"outbounds": []obj{{"protocol": "freedom"}},
			})
			srv, err := startXray(server)
			if err != nil {
				t.Fatalf("xray server: %v", err)
			}
			defer srv.Close()

			p := c.profile
			p.Name, p.Type, p.Server, p.Port, p.UUID = c.name, profile.TypeVLESS, "127.0.0.1", port, testUUID
			s := testSettings(t)
			engines, err := start(t.Context(), &p, &s)
			for _, e := range engines {
				defer e.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			waitListening(t, s.ListenPort)
			if body := getThroughSOCKS(t, s.ListenPort, "", "", url); body != "hello through tunnel" {
				t.Fatalf("unexpected body %q", body)
			}
		})
	}
}

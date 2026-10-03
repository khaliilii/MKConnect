//go:build !no_singbox

package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/khaliilii/MKConnect/internal/profile"
)

func TestServerTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			io.WriteString(w, strings.Repeat("x", 4<<20))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) // names resolve through the proxy
	oldLatency, oldSpeed := LatencyURL, SpeedURL
	LatencyURL, SpeedURL = base+"/generate_204", base+"/down"
	defer func() { LatencyURL, SpeedURL = oldLatency, oldSpeed }()

	port := freePort(t)
	startProtocolServer(t, []obj{{
		"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": port,
		"method": "aes-256-gcm", "password": "pw",
	}})
	good := profile.Profile{Name: "good", Type: profile.TypeShadowsocks, Server: "127.0.0.1", Port: port, Method: "aes-256-gcm", Password: "pw"}
	dead := good
	dead.Name, dead.Port = "dead", freePort(t)
	wrong := good
	wrong.Name, wrong.Password = "wrong password", "nope"

	cores := []string{profile.CoreSingBox}
	if startXray != nil {
		cores = append(cores, profile.CoreXray)
	}
	for _, core := range cores {
		t.Run(core, func(t *testing.T) {
			s := testSettings(t)
			s.Core = core
			profiles := []profile.Profile{dead, good, wrong}
			calls := 0
			res := TestMany(t.Context(), profiles, []int{0, 1, 2}, s, TestOptions{Speed: true}, 3,
				func(int, *profile.TestResult) { calls++ })
			if r := res[1]; !r.OK() || r.Received != 3 || r.Speed <= 0 {
				t.Fatalf("good server: %+v", r)
			}
			for _, i := range []int{0, 2} {
				if r := res[i]; r.OK() || r.Error == "" {
					t.Fatalf("%s: %+v", profiles[i].Name, r)
				}
			}
			if calls != 4 { // 3 latency results + 1 speed result
				t.Fatalf("done called %d times", calls)
			}
		})
	}
}

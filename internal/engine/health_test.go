//go:build !no_singbox

package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestRunReportsHealth checks that a connection which carries traffic is
// reported healthy, and one whose server is gone is reported as such instead
// of just looking "connected".
func TestRunReportsHealth(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	old := LatencyURL
	LatencyURL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/generate_204"
	defer func() { LatencyURL = old }()

	serverPort := freePort(t)
	startProtocolServer(t, []obj{{
		"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": serverPort,
		"method": "aes-256-gcm", "password": "pw",
	}})

	run := func(p profile.Profile) error {
		s := testSettings(t)
		s.ListenPort = freePort(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		type result struct{ err error }
		got := make(chan result, 1)
		go Run(ctx, p, s, Hooks{
			OnHealth: func(_ time.Duration, err error) {
				select {
				case got <- result{err}:
				default:
				}
			},
		})
		select {
		case r := <-got:
			return r.err
		case <-time.After(45 * time.Second):
			t.Fatal("no health report")
			return nil
		}
	}

	good := profile.Profile{Name: "good", Type: profile.TypeShadowsocks, Server: "127.0.0.1",
		Port: serverPort, Method: "aes-256-gcm", Password: "pw"}
	if err := run(good); err != nil {
		t.Fatalf("a working connection was reported unhealthy: %v", err)
	}

	dead := good
	dead.Name, dead.Port = "dead", freePort(t) // nothing listens there
	if err := run(dead); err == nil {
		t.Fatal("a dead server was reported as working")
	}
}

// TestExplainFailure checks that the cores' many ways of saying the same few
// things reach the user as one plain sentence each, with the original kept.
func TestExplainFailure(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`Get "https://www.gstatic.com/generate_204": EOF`, "closes every connection"},
		{"socks connect tcp 127.0.0.1:1080->www.gstatic.com:443: unknown error general SOCKS server failure", "closes every connection"},
		{"read tcp 1.2.3.4:5->6.7.8.9:443: read: connection reset by peer", "closes every connection"},
		{"context deadline exceeded (Client.Timeout exceeded while awaiting headers)", "doesn't answer"},
		{"dial tcp 127.0.0.1:1: connect: connection refused", "nothing answers"},
		{"lookup nowhere.example: no such host", "can't be resolved"},
		{"tls: failed to verify certificate: x509: certificate signed by unknown authority", "TLS handshake failed"},
	}
	for _, c := range cases {
		err := explainFailure(errors.New(c.raw))
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q\n  explained as %q, want it to say %q", c.raw, err, c.want)
		}
		if d := failureDetail(err); d == "" && c.want != "doesn't answer" {
			t.Errorf("%q: the original error is lost for the log", c.raw)
		}
	}
}

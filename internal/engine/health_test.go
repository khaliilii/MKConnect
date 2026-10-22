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
	old, oldFallback, oldRetry := LatencyURL, FallbackURLs, healthRetry
	LatencyURL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/generate_204"
	FallbackURLs = nil // no real internet in tests
	healthRetry = 50 * time.Millisecond
	defer func() { LatencyURL, FallbackURLs, healthRetry = old, oldFallback, oldRetry }()

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

// TestProbeSurvivesOneBlockedTarget is the case a full test found: a server
// that refuses gstatic.com but carries everything else must not be reported
// as dead (and reconnected over and over).
func TestProbeSurvivesOneBlockedTarget(t *testing.T) {
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close() // what a server that refuses the destination looks like: EOF
	}))
	defer blocked.Close()
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hanging.Close()
	works := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer works.Close()

	old, oldFallback, oldHedge := LatencyURL, FallbackURLs, probeHedge
	defer func() { LatencyURL, FallbackURLs, probeHedge = old, oldFallback, oldHedge }()
	probeHedge = 200 * time.Millisecond
	c := &http.Client{Timeout: 5 * time.Second}

	// The main target closes the connection; a fallback answers.
	LatencyURL, FallbackURLs = blocked.URL, []string{blocked.URL + "/again", works.URL}
	if _, err := probeAny(t.Context(), c); err != nil {
		t.Fatalf("one blocked target made a working connection look dead: %v", err)
	}

	// The main target hangs; the fallbacks are tried before the time is up.
	LatencyURL, FallbackURLs = hanging.URL, []string{works.URL}
	start := time.Now()
	if _, err := probeAny(t.Context(), c); err != nil {
		t.Fatalf("a hanging target made a working connection look dead: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("the fallback waited for the hanging target: %v", time.Since(start))
	}

	// Everything fails: the main target's error is reported.
	LatencyURL, FallbackURLs = blocked.URL, []string{blocked.URL + "/x"}
	if _, err := probeAny(t.Context(), c); err == nil {
		t.Fatal("all targets failing was reported as working")
	}
}

// TestSlowStartIsNotReportedAsDead: a connection whose first checks fail
// while the path warms up (seen on the user's network: ~12 s of stalls, then
// fast traffic) is reported as working, not as "no internet".
func TestSlowStartIsNotReportedAsDead(t *testing.T) {
	oldCheck, oldRetry := healthCheck, healthRetry
	defer func() { healthCheck, healthRetry = oldCheck, oldRetry }()
	healthRetry = 10 * time.Millisecond

	calls := 0
	healthCheck = func(context.Context, profile.Settings) (time.Duration, error) {
		calls++
		if calls < healthFirstTries {
			return 0, explainFailure(errors.New("context deadline exceeded"))
		}
		return 300 * time.Millisecond, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reports := make(chan error, 4)
	go monitorHealth(ctx, profile.Settings{}, func(_ time.Duration, err error) { reports <- err })
	select {
	case err := <-reports:
		if err != nil {
			t.Fatalf("a connection that works after a slow start was reported dead: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report")
	}
	cancel() // the first monitor must stop before healthCheck changes
	time.Sleep(20 * time.Millisecond)
	if calls != healthFirstTries {
		t.Errorf("checked %d times, want %d", calls, healthFirstTries)
	}

	// A connection that never works is still reported, after the tries.
	calls = 0
	healthCheck = func(context.Context, profile.Settings) (time.Duration, error) {
		calls++
		return 0, explainFailure(errors.New("EOF"))
	}
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	reports2 := make(chan error, 4)
	go monitorHealth(ctx2, profile.Settings{}, func(_ time.Duration, err error) { reports2 <- err })
	select {
	case err := <-reports2:
		if err == nil {
			t.Fatal("a dead connection was reported working")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report for a dead connection")
	}
}

// TestHealthProbesTheUsersPath: proxy mode probes the local proxy, TUN mode
// on a desktop goes the system's way (into the TUN), like a browser.
func TestHealthProbesTheUsersPath(t *testing.T) {
	proxyMode := profile.Settings{Mode: profile.ModeProxy, ListenPort: 1080}
	if healthClient(&proxyMode).Transport.(*http.Transport).Proxy == nil {
		t.Error("proxy mode doesn't probe the local proxy")
	}
	tun := profile.Settings{Mode: profile.ModeTUN, ListenPort: 1080}
	old := probeThroughSystem
	defer func() { probeThroughSystem = old }()
	probeThroughSystem = true
	if healthClient(&tun).Transport.(*http.Transport).Proxy != nil {
		t.Error("TUN mode on a desktop probes the local proxy, not the TUN")
	}
	probeThroughSystem = false // the phone app, left out of its own VPN
	if healthClient(&tun).Transport.(*http.Transport).Proxy == nil {
		t.Error("the phone app's TUN mode must probe the proxy")
	}
}

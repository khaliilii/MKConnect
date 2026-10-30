package mkmobile

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// statusOf returns the state the app polls, failing if it takes long: the
// app reads it on its UI thread every second.
func statusOf(t *testing.T) map[string]any {
	t.Helper()
	done := make(chan string, 1)
	go func() { done <- Status() }()
	select {
	case data := <-done:
		var out map[string]any
		if err := json.Unmarshal([]byte(data), &out); err != nil {
			t.Fatal(err)
		}
		return out
	case <-time.After(time.Second):
		t.Fatal("Status blocked")
	}
	return nil
}

// connectableStore holds one Shadowsocks account (no server behind it: the
// core starts all the same) and a free local port, in proxy mode.
func connectableStore(t *testing.T) int {
	t.Helper()
	newTestStore(t)
	if _, err := Import("ss://YWVzLTI1Ni1nY206cHc@127.0.0.1:1#dead"); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	mu.Lock()
	store.Settings.ListenPort = port
	store.Settings.LogLevel = "error"
	mu.Unlock()
	t.Cleanup(func() { Stop() })
	return port
}

// TestStartStopLifecycle: the state can be read while a start or stop is
// under way (the app shows "Connecting…" instead of freezing), a second
// Start while connected changes nothing (a second tap must not tear the
// connection down), and Stop frees the proxy port.
func TestStartStopLifecycle(t *testing.T) {
	port := connectableStore(t)

	lifeMu.Lock() // as during a start that takes seconds
	setState("connecting", "", "dead")
	if s := statusOf(t); s["state"] != "connecting" {
		t.Errorf("state %v while starting", s["state"])
	}
	setState("idle", "", "")
	lifeMu.Unlock()

	if err := Start(nil); err != nil {
		t.Fatal(err)
	}
	if s := statusOf(t); s["state"] != "connected" || s["profile"] != "dead" {
		t.Fatalf("after Start: %v", s)
	}
	runMu.Lock()
	first := running
	runMu.Unlock()
	if err := Start(nil); err != nil {
		t.Errorf("a second Start: %v", err)
	}
	runMu.Lock()
	same := running == first
	runMu.Unlock()
	if !same {
		t.Error("a second Start replaced the connection")
	}

	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if s := statusOf(t); s["state"] != "idle" {
		t.Errorf("after Stop: %v", s)
	}
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		c.Close()
		t.Error("the proxy still listens after Stop")
	}
}

// TestReconnectRetriesAndStops: a reconnect that can't start the core leaves
// the connection "reconnecting" without one (to be tried again), the next try
// connects, and after Stop a reconnect gives up for good.
func TestReconnectRetriesAndStops(t *testing.T) {
	port := connectableStore(t)
	if err := Start(nil); err != nil {
		t.Fatal(err)
	}
	runMu.Lock()
	stop := monitorStop
	runMu.Unlock()

	// The core died and its port is taken: starting it again fails.
	runMu.Lock()
	dead := running
	running = nil
	runMu.Unlock()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}
	blocker, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	if err := reconnect(stop, false); err == nil || errors.Is(err, errGone) {
		t.Fatalf("reconnect with the port taken: %v", err)
	}
	if s := statusOf(t); s["state"] != "reconnecting" || s["error"] == "" {
		t.Errorf("after a failed reconnect: %v", s)
	}

	blocker.Close()
	if err := reconnect(stop, false); err != nil {
		t.Fatalf("second try: %v", err)
	}
	if s := statusOf(t); s["state"] != "connected" {
		t.Errorf("after the second try: %v", s)
	}

	Stop()
	if err := reconnect(stop, false); !errors.Is(err, errGone) {
		t.Errorf("reconnect after Stop: %v", err)
	}
	if s := statusOf(t); s["state"] != "idle" {
		t.Errorf("a reconnect after Stop changed the state: %v", s)
	}
}

// TestSessionShowsHowThePhoneRuns: the connection's description follows the
// phone's mode and the core that carries it, not the stored desktop settings.
func TestSessionShowsHowThePhoneRuns(t *testing.T) {
	p := profile.Profile{Name: "a", Type: profile.TypeVLESS, Server: "h", Port: 443}
	stored := profile.DefaultSettings() // proxy mode, sing-box
	stored.ShareInterfaces = []string{"en0"}
	vpn := newSession(p, stored, true, profile.CoreXray, nil)
	if vpn.Core != profile.CoreXray || len(vpn.Inbounds) != 2 || !strings.HasPrefix(vpn.Inbounds[1], "TUN ") {
		t.Errorf("VPN mode: %+v", vpn)
	}
	stored.Mode = profile.ModeTUN
	if proxy := newSession(p, stored, false, profile.CoreSingBox, nil); len(proxy.Inbounds) != 1 {
		t.Errorf("proxy mode: %+v", proxy)
	}
}

// TestLogsShowTheLastCrash: a crash report (the core's or the app's) comes
// first in the log screen, survives a new connection's log, and goes with
// Clear.
func TestLogsShowTheLastCrash(t *testing.T) {
	old := dataDir
	defer func() { dataDir = old }()
	dataDir = t.TempDir()
	os.WriteFile(filepath.Join(dataDir, "core.log"), []byte("connected\n"), 0o600)
	if got := Logs(100); got != "connected" {
		t.Fatalf("without a crash: %q", got)
	}
	os.WriteFile(filepath.Join(dataDir, crashLog), []byte("FATAL EXCEPTION: mkconnect-service\n"), 0o600)
	lines := strings.Split(Logs(100), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "💥") || lines[1] != "FATAL EXCEPTION: mkconnect-service" || lines[3] != "connected" {
		t.Fatalf("with a crash: %q", lines)
	}
	ClearLogs()
	if got := Logs(100); got != "" {
		t.Errorf("after Clear: %q", got)
	}
}

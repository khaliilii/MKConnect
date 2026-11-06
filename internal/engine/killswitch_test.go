package engine

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestKillSwitchFor: the kill switch guards TUN connections only, and on
// Windows refuses what its filters would block.
func TestKillSwitchFor(t *testing.T) {
	s := profile.DefaultSettings()
	s.KillSwitch = true
	if on, err := killSwitchFor(&s); on || err != nil {
		t.Errorf("proxy mode: %t, %v", on, err)
	}
	s.Mode = profile.ModeTUN
	if on, err := killSwitchFor(&s); !on || err != nil {
		t.Errorf("TUN mode: %t, %v", on, err)
	}
	s.ShareInterfaces = []string{"Ethernet"}
	on, err := killSwitchFor(&s)
	if windows := runtime.GOOS == "windows"; windows != (err != nil) || on == windows {
		t.Errorf("TUN mode with sharing: %t, %v", on, err)
	}
	s.KillSwitch = false
	if on, _ := killSwitchFor(&s); on {
		t.Error("guarded with the kill switch off")
	}
}

// TestLastKnownServerAddress: when DNS fails, a server looked up before is
// still reached; one never seen fails, and so does a cancelled connection.
func TestLastKnownServerAddress(t *testing.T) {
	old := lookupHost
	defer func() { lookupHost = old; knownServers.Clear() }()
	ip := []net.IPAddr{{IP: net.IPv4(203, 0, 113, 7)}}
	var fail error
	lookupHost = func(context.Context, string) ([]net.IPAddr, error) { return ip, fail }

	p := profile.Profile{Server: "srv.example", Port: 443}
	if _, err := pinServer(t.Context(), &p); err != nil || p.Server != "203.0.113.7" {
		t.Fatalf("%v, %s", err, p.Server)
	}
	fail = errors.New("no such host")
	p = profile.Profile{Server: "srv.example", Port: 443}
	if _, err := pinServer(t.Context(), &p); err != nil || p.Server != "203.0.113.7" {
		t.Fatalf("with DNS down: %v, %s", err, p.Server)
	}
	if _, err := resolveServer(t.Context(), "never.example"); err == nil {
		t.Error("an unknown server resolved with DNS down")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolveServer(ctx, "srv.example"); err == nil {
		t.Error("a cancelled connection went on")
	}
}

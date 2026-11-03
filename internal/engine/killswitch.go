package engine

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"time"

	"github.com/khaliilii/MKConnect/internal/killswitch"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// The kill switch (Settings.KillSwitch, TUN mode) is engaged by Run before
// the cores start and outlives it: a connection that drops leaves the block
// in place for the reconnect. Whoever runs the connections releases it when
// the user ends them (ReleaseKillSwitch). Replaced in tests.
var (
	engageKillSwitch  = killswitch.Engage
	releaseKillSwitch = killswitch.Release
)

// ReleaseKillSwitch lets traffic out without the tunnel again; for the end of
// a connection the user asked for, not for a drop.
func ReleaseKillSwitch() {
	if err := releaseKillSwitch(); err != nil {
		log.Printf("⚠️  %v", err)
	}
}

// KillSwitchEngaged reports whether this process blocks traffic without the tunnel.
func KillSwitchEngaged() bool { return killswitch.Engaged() }

// killSwitchFor reports whether the kill switch guards a connection with s,
// or why it can't.
func killSwitchFor(s *profile.Settings) (bool, error) {
	if !s.KillSwitch || s.Mode != profile.ModeTUN {
		return false, nil
	}
	if runtime.GOOS == "windows" {
		// Windows lets this process out by its program: another one's
		// connections, or the network sharing gives devices, would be blocked.
		if s.Core == profile.CoreExternal {
			return false, errors.New("the kill switch can't be used with an external core binary on Windows; choose sing-box or Xray, or turn the kill switch off")
		}
		if len(s.ShareInterfaces) > 0 {
			return false, errors.New("the kill switch can't be used together with sharing the tunnel on Windows; turn one of them off")
		}
	}
	return true, nil
}

// tunInterface finds the tunnel's network interface: the one with its
// address (sing-box names it itself on macOS and Linux).
func tunInterface(s *profile.Settings) (string, error) {
	if runtime.GOOS == "windows" {
		return TUNName, nil
	}
	want, _, err := net.ParseCIDR(tunAddresses(s.IPv6)[0])
	if err != nil {
		return "", err
	}
	for range 20 { // the address can come a moment after the interface
		ifs, _ := net.Interfaces()
		for _, ifc := range ifs {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.Equal(want) {
					return ifc.Name, nil
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("kill switch: the tunnel's interface (%s) wasn't found", want)
}

package engine

import (
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

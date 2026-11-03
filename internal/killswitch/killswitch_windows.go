package killswitch

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Windows: WireGuard's WFP filters, the ones of its "block untunneled
// traffic". They let this process out (its program and its rights: not the
// app's own, unelevated process), the tunnel's interface, loopback and DHCP,
// and block everything else, the local network included. They live in a WFP
// session of this process: Windows removes them when it ends, so nothing is
// left behind to clean up.

func defaultStateDir() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "MKConnect")
}

func engageRules(tun string) error {
	var luid uint64
	if tun != "" {
		ifc, err := net.InterfaceByName(tun)
		if err != nil {
			return fmt.Errorf("kill switch: %w", err)
		}
		l, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
		if err != nil {
			return fmt.Errorf("kill switch: %w", err)
		}
		luid = uint64(l)
	}
	// The filters name the tunnel's interface, so a new tunnel needs new ones.
	firewall.DisableFirewall()
	if err := firewall.EnableFirewall(luid, false, nil); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	return nil
}

func releaseRules() error {
	firewall.DisableFirewall()
	return nil
}

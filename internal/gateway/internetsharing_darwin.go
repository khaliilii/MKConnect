package gateway

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"
)

// FollowInternetSharing keeps Internet Sharing's devices in the tunnel until
// ctx ends: sharing can be turned on and off while a connection runs.
func FollowInternetSharing(ctx context.Context, tun, tunGateway string) {
	var loaded []SharedNet
	apply := func() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return
		}
		nets := sharedNets(ifaces)
		if sameNets(nets, loaded) {
			return
		}
		cmd := exec.Command("pfctl", "-a", sharingAnchor, "-f", "-")
		cmd.Stdin = strings.NewReader(sharingRules(nets, tun, tunGateway))
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("⚠️  Internet Sharing's devices won't go through the tunnel: pfctl: %v: %s", err, strings.TrimSpace(string(out)))
			return
		}
		loaded = nets
		if len(nets) > 0 {
			log.Printf("🔀 Internet Sharing's devices go through the tunnel (%v)", nets)
		}
	}
	apply()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			StopFollowingInternetSharing()
			return
		case <-t.C:
			apply()
		}
	}
}

// StopFollowingInternetSharing removes the rules, also those a crash left:
// they point into a tunnel that is gone.
func StopFollowingInternetSharing() {
	if out, err := exec.Command("pfctl", "-a", sharingAnchor, "-F", "rules").CombinedOutput(); err != nil {
		log.Printf("⚠️  %v", fmt.Errorf("pfctl -F: %w: %s", err, strings.TrimSpace(string(out))))
	}
}

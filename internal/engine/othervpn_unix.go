//go:build darwin || linux

package engine

import (
	"os/exec"
	"path/filepath"
	"strings"
)

// runningVPNApps names the known VPN apps that are running, to tell the user
// which one to disconnect.
func runningVPNApps() []string {
	out, err := exec.Command("ps", "-axo", "comm=").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var apps []string
	for _, line := range strings.Split(string(out), "\n") {
		name := filepath.Base(strings.TrimSpace(line))
		lower := strings.ToLower(name)
		for _, app := range knownVPNApps {
			if strings.Contains(lower, app) && !seen[app] {
				seen[app] = true
				apps = append(apps, strings.TrimSuffix(name, ".exe"))
			}
		}
	}
	return apps
}

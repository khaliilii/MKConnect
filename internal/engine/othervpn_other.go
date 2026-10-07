//go:build !darwin && !linux

package engine

func tunnelDefaultRoute() (string, error) { return "", nil }
func runningVPNApps() []string            { return nil }

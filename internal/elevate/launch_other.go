//go:build !darwin && !linux && !windows

package elevate

import "fmt"

func launchElevated(exe, dir string) (<-chan error, error) {
	return nil, fmt.Errorf("TUN mode needs root: start MKConnect as root")
}

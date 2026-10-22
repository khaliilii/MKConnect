//go:build !darwin

package elevate

import "errors"

// RunElevated is only needed on macOS (to restore a DNS setting a TUN
// connection made); elsewhere the system resolver needs no change.
func RunElevated(string, ...string) (string, error) {
	return "", errors.New("not needed on this system")
}

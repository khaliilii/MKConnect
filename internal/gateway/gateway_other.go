//go:build !linux && !darwin && !windows

package gateway

import "fmt"

func enable(*Session, []string, string) error {
	return fmt.Errorf("sharing the tunnel with other interfaces isn't supported on this system (Android needs root)")
}

func hint([]string) string { return "" }

//go:build !darwin

package engine

// Elsewhere the system resolver follows the TUN's routes (or the platform's
// VPN service sets DNS), so it needs no change.
func pointSystemDNSIntoTunnel() (restore func(), err error) { return func() {}, nil }

// LeftoverTunnelDNS and RepairTunnelDNS only have work to do on macOS.
func LeftoverTunnelDNS() []string { return nil }

func RepairTunnelDNS() ([]string, error) { return nil, nil }

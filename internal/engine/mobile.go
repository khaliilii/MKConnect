package engine

import "github.com/khaliilii/MKConnect/internal/profile"

// MobileConfig returns the sing-box config for the phone app: with tun the
// platform (Android's VpnService) creates the TUN from the inbound's addresses
// and routes; without it only the local proxy runs. Core logs go to logFile.
func MobileConfig(p profile.Profile, s profile.Settings, tun bool, logFile string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var opts *tunOptions
	if tun {
		opts = &tunOptions{}
	}
	cfg, err := singBoxConfig(&p, &s, opts)
	if err != nil {
		return nil, err
	}
	if logFile != "" {
		cfg["log"].(obj)["output"] = logFile
	}
	return marshal(cfg)
}

// NewSessionFor describes a running engine (used by the mobile bridge).
func NewSessionFor(p profile.Profile, s profile.Settings, e Engine) *Session {
	return newSession(&p, &s, e)
}

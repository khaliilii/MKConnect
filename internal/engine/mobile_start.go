//go:build !no_singbox

package engine

import (
	"errors"
	"fmt"

	"github.com/sagernet/sing-box/adapter"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// StartMobile starts a phone connection with the core PreferredCore picks for
// p: the one the desktop app and the phone's own server test use. That is
// sing-box, or Xray for the accounts sing-box fails with (an HTTP header over
// TCP, a CDN front, a pinned certificate, Mux). In VPN mode sing-box runs the
// platform's TUN, in front of Xray when Xray carries the traffic, as on the
// desktop. Core logs go to logFile. It returns the core carrying the traffic;
// closing the engine stops everything it started.
func StartMobile(p profile.Profile, s profile.Settings, vpn bool, logFile string, platform adapter.PlatformInterface) (Engine, string, error) {
	s.Core, s.Mode = profile.CoreSingBox, profile.ModeProxy
	if vpn {
		s.Mode = profile.ModeTUN
	}
	if PreferredCore(&p, &s) != profile.CoreXray {
		cfg, err := MobileConfig(p, s, vpn, logFile)
		if err != nil {
			return nil, "", err
		}
		e, err := StartSingBoxPlatform(cfg, platform)
		return e, profile.CoreSingBox, err
	}

	if err := p.Validate(); err != nil {
		return nil, "", err
	}
	cfg, err := xrayConfig(&p, &s)
	if err != nil {
		return nil, "", err
	}
	if logFile != "" {
		cfg["log"] = obj{"loglevel": xrayLogLevel(&s), "error": logFile, "access": "none"}
	}
	data, err := marshal(cfg)
	if err != nil {
		return nil, "", err
	}
	proxy, err := startXray(data)
	if err != nil {
		return nil, "", fmt.Errorf("xray: %w", err)
	}
	if !vpn {
		return proxy, profile.CoreXray, nil
	}
	front := singBoxTUNConfig(&s, s.ListenPort, &tunOptions{})
	if logFile != "" {
		front["log"].(obj)["output"] = logFile
	}
	if data, err = marshal(front); err == nil {
		var tun Engine
		if tun, err = StartSingBoxPlatform(data, platform); err == nil {
			return &engineStack{engines: []Engine{proxy, tun}}, profile.CoreXray, nil
		}
	}
	proxy.Close()
	return nil, "", err
}

// engineStack is engines started in order (the core, then the TUN in front
// of it), closed in reverse; the first one counts the traffic.
type engineStack struct{ engines []Engine }

func (s *engineStack) Close() error {
	var errs []error
	for i := len(s.engines) - 1; i >= 0; i-- {
		errs = append(errs, s.engines[i].Close())
	}
	return errors.Join(errs...)
}

func (s *engineStack) Traffic() (up, down int64) {
	if c, ok := s.engines[0].(trafficCounter); ok {
		return c.Traffic()
	}
	return 0, 0
}

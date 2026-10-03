package mkmobile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// Platform is implemented by the Android VpnService.
type Platform interface {
	// OpenTun builds the VPN interface (VpnService.Builder.establish) as
	// described by cfg and returns its file descriptor.
	OpenTun(cfg *TunConfig) (int32, error)
	// Protect keeps a socket of the core outside the VPN (VpnService.protect).
	Protect(fd int32) bool
	// Interfaces lists the network interfaces as JSON (Go's net.Interfaces
	// isn't allowed for apps on Android 11+):
	// [{"name","index","mtu","addresses":["192.168.1.5/24"],"flags","type","dns":[],"metered"}]
	Interfaces() string
}

// TunConfig describes the VPN interface sing-box wants.
type TunConfig struct {
	mtu                    int32
	inet4, inet6           []string
	routes4, routes6       []string
	dns                    string
	excludePackage         []string
	autoRoute, strictRoute bool
}

// MTU of the interface.
func (c *TunConfig) Mtu() int32 { return c.mtu }

// Addresses returns the interface addresses ("172.19.0.1/30,...").
func (c *TunConfig) Addresses() string { return strings.Join(append(c.inet4, c.inet6...), ",") }

// Routes returns the routes to add ("0.0.0.0/0,::/0" or split ranges).
func (c *TunConfig) Routes() string { return strings.Join(append(c.routes4, c.routes6...), ",") }

// DnsServer is the DNS address to give the VPN (answered by sing-box).
func (c *TunConfig) DnsServer() string { return c.dns }

var (
	runMu     sync.Mutex
	running   engine.Engine
	session   *engine.Session
	runState  = "idle"
	runErr    string
	runName   string
	dataDir   string
	activeApp Platform
)

// SetDataDir sets where logs are written (the app's files directory).
func SetDataDir(dir string) { dataDir = dir }

// Start connects the active account. With a platform it runs as the
// system VPN (unless the phone mode is "proxy"); without one only the local
// proxy runs.
func Start(app Platform) error {
	runMu.Lock()
	defer runMu.Unlock()
	if running != nil {
		return errors.New("already connected")
	}
	mu.Lock()
	s, err := loaded()
	if err != nil {
		mu.Unlock()
		return err
	}
	p, err := s.ActiveProfile()
	if err != nil {
		mu.Unlock()
		return err
	}
	prof, settings := *p, s.Settings
	mu.Unlock()

	settings.Core, settings.Mode = profile.CoreSingBox, profile.ModeProxy
	vpn := app != nil && settings.PhoneMode != "proxy"
	if vpn {
		settings.Mode = profile.ModeTUN
	}
	logFile := ""
	if dataDir != "" {
		logFile = filepath.Join(dataDir, "core.log")
		os.Remove(logFile)
	}
	cfg, err := engine.MobileConfig(prof, settings, vpn, logFile)
	if err != nil {
		return setError(err)
	}
	runState, runErr, runName = "connecting", "", prof.Name
	activeApp = app
	e, err := engine.StartSingBoxPlatform(cfg, newPlatform(app))
	if err != nil {
		return setError(err)
	}
	running = e
	session = engine.NewSessionFor(prof, settings, e)
	runState = "connected"
	return nil
}

func setError(err error) error {
	runState, runErr = "error", err.Error()
	return err
}

// Stop disconnects.
func Stop() error {
	runMu.Lock()
	defer runMu.Unlock()
	if running == nil {
		runState = "idle"
		return nil
	}
	err := running.Close()
	running, session, activeApp = nil, nil, nil
	runState = "idle"
	return err
}

// Status returns {"state","profile","error","core","inbounds","outbound","up","down"} as JSON.
func Status() string {
	runMu.Lock()
	defer runMu.Unlock()
	out := map[string]any{"state": runState, "profile": runName, "error": runErr}
	if session != nil {
		up, down, _ := session.Traffic()
		out["core"], out["inbounds"], out["outbound"], out["up"], out["down"] = session.Core, session.Inbounds, session.Outbound, up, down
		out["up_text"], out["down_text"] = profile.FormatBytes(up), profile.FormatBytes(down)
	}
	data, _ := json.Marshal(out)
	return string(data)
}

// Logs returns the last lines of the core log.
func Logs(maxLines int32) string {
	if dataDir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "core.log"))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if n := int(maxLines); n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

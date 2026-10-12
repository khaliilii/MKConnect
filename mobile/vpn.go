package mkmobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

// Addresses returns the interface addresses ("172.19.77.1/30,...").
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
	runProxy  string // socks5 URL of the running local proxy, "" in VPN mode or idle
	runErr    string
	runName   string
	dataDir   string
	activeApp Platform

	// What the running connection is made of, so a reconnect can repeat it.
	runConfig   []byte
	runProfile  profile.Profile
	runSettings profile.Settings
	// monitorStop ends the health monitor of the current connection; a
	// monitor whose channel is no longer the current one exits.
	monitorStop chan struct{}
	healthErr   string // "" while the connection carries traffic
	healthMS    int64
)

// Health checks: a sing-box that starts is not a working connection. The
// phone app probes through the local proxy (which runs in VPN mode too) and
// reports the result, reconnecting when nothing gets through.
const (
	healthFirstCheck   = 4 * time.Second
	healthEvery        = 45 * time.Second
	healthFailsToRetry = 2
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
	runConfig, runProfile, runSettings = cfg, prof, settings
	healthErr, healthMS = "", 0
	startHealthMonitor(settings)
	runProxy = ""
	if !vpn {
		runProxy = fmt.Sprintf("socks5://127.0.0.1:%d", settings.ListenPort)
		if settings.ProxyUser != "" {
			runProxy = fmt.Sprintf("socks5://%s:%s@127.0.0.1:%d", url.QueryEscape(settings.ProxyUser), url.QueryEscape(settings.ProxyPass), settings.ListenPort)
		}
	}
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
	running, session, activeApp, runProxy = nil, nil, nil, ""
	monitorStop, healthErr, healthMS = nil, "", 0
	runState = "idle"
	return err
}

// fetchProxy returns the running local proxy for downloads that fail directly.
func fetchProxy() string {
	runMu.Lock()
	defer runMu.Unlock()
	return runProxy
}

// Status returns {"state","profile","error","core","inbounds","outbound","up","down"} as JSON.
func Status() string {
	runMu.Lock()
	defer runMu.Unlock()
	out := map[string]any{"state": runState, "profile": runName, "error": runErr}
	if runState == "connected" || runState == "reconnecting" {
		out["health"] = healthErr // "" means traffic gets through
		out["health_ms"] = healthMS
	}
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

// startHealthMonitor probes the connection through its local proxy, keeps the
// result in the status and reconnects when two checks in a row fail.
// runMu must be held.
func startHealthMonitor(s profile.Settings) {
	stop := make(chan struct{})
	monitorStop = stop
	go func() {
		fails, wait := 0, healthFirstCheck
		for {
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
			wait = healthEvery
			latency, err := engine.CheckHealth(context.Background(), s)

			runMu.Lock()
			if monitorStop != stop {
				runMu.Unlock()
				return // this connection is gone
			}
			if err != nil {
				fails++
				healthErr, healthMS = err.Error(), 0
			} else {
				fails = 0
				healthErr, healthMS = "", latency.Milliseconds()
			}
			auto := s.AutoReconnect
			runMu.Unlock()

			if err == nil || fails < healthFailsToRetry || !auto {
				continue
			}
			fails = 0
			if rerr := reconnect(stop); rerr != nil {
				return // the connection ended for good
			}
		}
	}()
}

// reconnect starts the same connection again, in place, after it stopped
// carrying traffic.
func reconnect(stop chan struct{}) error {
	runMu.Lock()
	defer runMu.Unlock()
	if monitorStop != stop || running == nil {
		return errors.New("connection is gone")
	}
	runState = "reconnecting"
	running.Close()
	running, session = nil, nil
	e, err := engine.StartSingBoxPlatform(runConfig, newPlatform(activeApp))
	if err != nil {
		monitorStop = nil
		return setError(err)
	}
	running = e
	session = engine.NewSessionFor(runProfile, runSettings, e)
	runState, healthErr, healthMS = "connected", "", 0
	return nil
}

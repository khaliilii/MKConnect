package mkmobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// lifeMu serializes starting, stopping and reconnecting, which take seconds.
// runMu guards what the status shows and is only held briefly, so the app
// can always read the state ("connecting…") while one of those runs.
var (
	lifeMu sync.Mutex

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
	runProfile  profile.Profile
	runSettings profile.Settings
	runVPN      bool
	runLogFile  string
	// runBackups are the accounts failover may move to, best first.
	runBackups []profile.Profile
	// monitorStop ends the health monitor of the current connection; a
	// monitor whose channel is no longer the current one exits.
	monitorStop chan struct{}
	healthErr   string // "" while the connection carries traffic
	healthMS    int64
)

// Health checks: a core that starts is not a working connection. The phone
// app probes through the local proxy (which runs in VPN mode too) and reports
// the result, reconnecting when nothing gets through. A reconnect that fails
// (no network for a moment) is tried again every healthRetry.
const (
	healthFirstCheck   = 4 * time.Second
	healthEvery        = 45 * time.Second
	healthRetry        = 10 * time.Second
	healthFailsToRetry = 2
)

// errGone ends a health monitor: its connection was stopped.
var errGone = errors.New("connection is gone")

// SetDataDir sets where logs are written (the app's files directory) and
// sends this package's own log output to the same file, so the app's log
// screen shows the connection's messages (health checks, reconnects) and not
// only sing-box's.
func SetDataDir(dir string) {
	dataDir = dir
	path := filepath.Join(dir, "core.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(io.MultiWriter(f, os.Stderr)) // os.Stderr is Android's logcat
}

// ClearLogs empties the log file.
func ClearLogs() {
	if dataDir == "" {
		return
	}
	os.Truncate(filepath.Join(dataDir, "core.log"), 0)
}

// Start connects the active account. With a platform it runs as the
// system VPN (unless the phone mode is "proxy"); without one only the local
// proxy runs. Starting while connected (a second tap, the service restarted)
// does nothing.
func Start(app Platform) error {
	lifeMu.Lock()
	defer lifeMu.Unlock()
	runMu.Lock()
	connected := running != nil
	runMu.Unlock()
	if connected {
		return nil
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
	var backups []profile.Profile
	if settings.AutoReconnect && settings.Failover {
		backups = s.Backups(p)
	}
	mu.Unlock()
	if prof.IsInfo() {
		return setError(fmt.Errorf("%q: %w", prof.Name, profile.ErrInfoEntry))
	}

	vpn := app != nil && settings.PhoneMode != "proxy"
	logFile := ""
	if dataDir != "" {
		logFile = filepath.Join(dataDir, "core.log")
		// Truncate rather than remove: this package's own log output holds the
		// file open, and a removed file would take those messages with it.
		os.Truncate(logFile, 0)
	}
	setState("connecting", "", prof.Name)
	e, core, err := engine.StartMobile(prof, settings, vpn, logFile, newPlatform(app))
	if err != nil {
		return setError(err)
	}
	log.Printf("✅ %s connected through %s", prof.Name, core)

	runMu.Lock()
	defer runMu.Unlock()
	running, activeApp = e, app
	runProfile, runSettings, runVPN, runLogFile, runBackups = prof, settings, vpn, logFile, backups
	session = newSession(prof, settings, vpn, core, e)
	runState, healthErr, healthMS = "connected", "", 0
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

// newSession describes the connection as it runs: the core that carries it
// and, in VPN mode, the TUN among the inbounds (the stored mode is the
// desktop's).
func newSession(p profile.Profile, s profile.Settings, vpn bool, core string, e engine.Engine) *engine.Session {
	s.Core, s.Mode, s.ShareInterfaces = core, profile.ModeProxy, nil
	if vpn {
		s.Mode = profile.ModeTUN
	}
	return engine.NewSessionFor(p, s, e)
}

func setState(state, errText, name string) {
	runMu.Lock()
	defer runMu.Unlock()
	runState, runErr, runName = state, errText, name
}

func setError(err error) error {
	runMu.Lock()
	defer runMu.Unlock()
	runState, runErr = "error", err.Error()
	return err
}

// Stop disconnects.
func Stop() error {
	lifeMu.Lock()
	defer lifeMu.Unlock()
	runMu.Lock()
	e := running
	running, session, activeApp, runProxy = nil, nil, nil, ""
	monitorStop, healthErr, healthMS = nil, "", 0
	runState = "idle"
	runMu.Unlock()
	if e == nil {
		return nil
	}
	return e.Close()
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
// result in the status and reconnects when two checks in a row fail; the
// second reconnect moves to a backup account (failover). runMu must be held.
func startHealthMonitor(s profile.Settings) {
	stop := make(chan struct{})
	monitorStop = stop
	go func() {
		// retries counts reconnects since traffic last got through.
		fails, retries, wait, first := 0, 0, healthFirstCheck, true
		for {
			select {
			case <-stop:
				return
			case <-time.After(wait):
			}
			wait = healthEvery

			runMu.Lock()
			gone, down := monitorStop != stop, running == nil
			runMu.Unlock()
			if gone {
				return
			}
			if !down {
				// Confirmed: a fresh connection often stalls for a few seconds
				// before traffic flows, which must not read as "no internet".
				latency, err := engine.CheckHealthConfirmed(context.Background(), s, first)
				first = false
				runMu.Lock()
				if monitorStop != stop {
					runMu.Unlock()
					return
				}
				if err != nil {
					fails++
					healthErr, healthMS = err.Error(), 0
				} else {
					fails, retries = 0, 0
					healthErr, healthMS = "", latency.Milliseconds()
				}
				runMu.Unlock()
				if err == nil || fails < healthFailsToRetry || !s.AutoReconnect {
					continue
				}
			}
			// A core that failed to start again (a moment without network) is
			// retried as it was: only a connection that started and still
			// carried nothing counts toward failing over.
			if !down {
				fails, retries = 0, retries+1
			}
			switch err := reconnect(stop, !down && retries >= 2); {
			case errors.Is(err, errGone):
				return
			case err != nil:
				log.Printf("🔄 reconnecting failed (%v); trying again in %s", err, healthRetry)
				wait = healthRetry
			default:
				first = true
			}
		}
	}()
}

// reconnect starts the connection again, in place, after it stopped carrying
// traffic: the same account, or with failover the best backup account. When
// starting fails the connection stays "reconnecting" without a core, and the
// monitor tries again.
func reconnect(stop chan struct{}, failover bool) error {
	lifeMu.Lock()
	defer lifeMu.Unlock()
	runMu.Lock()
	if monitorStop != stop {
		runMu.Unlock()
		return errGone
	}
	runState = "reconnecting"
	if failover && len(runBackups) > 0 {
		next := runBackups[0]
		runBackups = runBackups[1:]
		log.Printf("🔀 %s keeps failing; switching to %s", runProfile.Name, next.Name)
		runProfile, runName = next, next.Name
		mu.Lock()
		if s, err := loaded(); err == nil {
			if _, err := s.Find(next.ID); err == nil {
				s.Active = next.ID
				s.Save()
			}
		}
		mu.Unlock()
	}
	old := running
	running, session = nil, nil
	prof, settings, vpn, logFile, app := runProfile, runSettings, runVPN, runLogFile, activeApp
	runMu.Unlock()

	if old != nil {
		old.Close()
	}
	// lifeMu is held throughout, so a Stop waits for this to finish (a
	// second or so) and then ends what it started.
	e, core, err := engine.StartMobile(prof, settings, vpn, logFile, newPlatform(app))
	runMu.Lock()
	defer runMu.Unlock()
	if err != nil {
		runErr = err.Error()
		return err
	}
	running, session = e, newSession(prof, settings, vpn, core, e)
	runState, runErr, healthErr, healthMS = "connected", "", "", 0
	return nil
}

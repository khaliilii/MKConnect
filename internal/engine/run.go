package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/khaliilii/MKConnect/internal/gateway"
	"github.com/khaliilii/MKConnect/internal/profile"
	"github.com/khaliilii/MKConnect/internal/recovery"
)

// Hooks lets the caller react to things discovered while connecting.
type Hooks struct {
	// OnHostKey is called with a newly pinned SSH host key so it can be saved.
	OnHostKey func(key string)
	// OnStarted is called once every core is up.
	OnStarted func(*Session)
}

// Run starts the profile with the given settings and blocks until ctx is
// cancelled or the core stops on its own.
func Run(ctx context.Context, p profile.Profile, s profile.Settings, hooks Hooks) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("profile %q: %w", p.Name, err)
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	if s.AllowLAN && s.ProxyUser == "" {
		log.Printf("⚠️  LAN sharing is on without a proxy password: anyone on the network can use this proxy")
	}

	if p.Type == profile.TypeSSH && p.HostKey == "" {
		key, err := FetchHostKey(ctx, p.Address())
		if err != nil {
			return fmt.Errorf("fetch ssh host key: %w", err)
		}
		log.Printf("🔑 Pinning SSH host key for %s: %s", p.Address(), Fingerprint(key))
		p.HostKey = key
		if hooks.OnHostKey != nil {
			hooks.OnHostKey(key)
		}
	}

	share := s.Mode == profile.ModeTUN && len(s.ShareInterfaces) > 0
	if len(s.ShareInterfaces) > 0 && !share {
		log.Printf("⚠️  sharing with %v needs TUN mode; ignored in proxy mode", s.ShareInterfaces)
	}

	if s.Mode == profile.ModeTUN {
		// Undo whatever a crashed earlier connection left, then journal this one
		// so a crash of this process can be undone too.
		if cleaned, err := recovery.Recover(); err != nil {
			log.Printf("⚠️  recovering from an earlier crash: %v", err)
		} else if len(cleaned) > 0 {
			log.Printf("🧹 cleaned up after an earlier crash: %s", strings.Join(cleaned, ", "))
		}
		if err := checkOtherVPN(); err != nil {
			return err
		}
		end, err := recovery.Begin()
		if err != nil {
			log.Printf("⚠️  crash recovery unavailable: %v", err)
		}
		defer end() // runs last: after the cores and the gateway have restored everything
	}

	shown := p // start may pin the server to an IP; show what the user configured
	engines, err := start(ctx, &p, &s)
	defer func() {
		for i := len(engines) - 1; i >= 0; i-- {
			if err := engines[i].Close(); err != nil {
				log.Printf("⚠️  close: %v", err)
			}
		}
	}()
	if err != nil {
		return err
	}

	if share {
		gw, err := gateway.Enable(s.ShareInterfaces, TUNName)
		if err != nil {
			return fmt.Errorf("share tunnel: %w", err)
		}
		defer func() {
			if err := gw.Stop(); err != nil {
				log.Printf("⚠️  %v", err)
			}
		}()
		log.Printf("🔀 sharing the tunnel with %v", s.ShareInterfaces)
		if h := gateway.Hint(s.ShareInterfaces); h != "" {
			log.Printf("   %s", h)
		}
	}

	session := newSession(&shown, &s, engines[0])
	log.Printf("🚀 %s running on %s", p.Name, session.Core)
	for _, in := range session.Inbounds {
		log.Printf("   ⬇ inbound:  %s", in)
	}
	log.Printf("   ⬆ outbound: %s", session.Outbound)
	if hooks.OnStarted != nil {
		hooks.OnStarted(session)
	}

	stopped := make(chan error, len(engines))
	for _, e := range engines {
		if w, ok := e.(waiter); ok {
			go func() { stopped <- <-w.Done() }()
		}
	}
	select {
	case <-ctx.Done():
		log.Println("🛑 Shutting down...")
		return nil
	case err := <-stopped:
		return fmt.Errorf("core stopped: %w", err)
	}
}

// start launches the engines for the profile, in start order.
func start(ctx context.Context, p *profile.Profile, s *profile.Settings) ([]Engine, error) {
	tun := s.Mode == profile.ModeTUN

	// sing-box handles TUN natively in the same instance.
	if s.Core == profile.CoreSingBox || (s.Core == profile.CoreExternal && s.ExternalKind == profile.CoreSingBox) {
		var tunOpts *tunOptions
		if tun {
			tunOpts = &tunOptions{Gateway: len(s.ShareInterfaces) > 0}
		}
		cfg, err := singBoxConfig(p, s, tunOpts)
		if err != nil {
			return nil, err
		}
		e, err := launchSingBox(s, cfg)
		if err != nil {
			return nil, withTUNHint(err, tun)
		}
		return []Engine{e}, nil
	}

	// Other cores only provide the proxy; TUN is layered on top with sing-box.
	var exclude []string
	if tun {
		if startSingBox == nil {
			return nil, fmt.Errorf("TUN mode needs the sing-box core, which is not compiled into this binary")
		}
		var err error
		if exclude, err = pinServer(ctx, p); err != nil {
			return nil, err
		}
	}

	var (
		core Engine
		err  error
	)
	switch {
	case p.Type == profile.TypeSSH:
		// Xray has no SSH outbound; use the built-in client.
		core, err = startSSH(p, s)
	case s.Core == profile.CoreXray:
		core, err = launchXray(p, s)
	case s.Core == profile.CoreExternal:
		cfg, cerr := xrayConfig(p, s)
		if cerr != nil {
			return nil, cerr
		}
		core, err = startExternal(s.ExternalPath, cfg)
	default:
		err = fmt.Errorf("unknown core %q", s.Core)
	}
	if err != nil {
		return nil, err
	}
	engines := []Engine{core}
	if !tun {
		return engines, nil
	}

	cfg := singBoxTUNConfig(s, s.ListenPort, &tunOptions{ExcludeAddrs: exclude, Gateway: len(s.ShareInterfaces) > 0})
	data, err := marshal(cfg)
	if err != nil {
		return engines, err
	}
	t, err := startSingBox(data)
	if err != nil {
		return engines, withTUNHint(err, true)
	}
	return append(engines, t), nil
}

func launchSingBox(s *profile.Settings, cfg obj) (Engine, error) {
	if s.Core == profile.CoreExternal {
		return startExternal(s.ExternalPath, cfg)
	}
	if startSingBox == nil {
		return nil, fmt.Errorf("the sing-box core is not compiled into this binary")
	}
	data, err := marshal(cfg)
	if err != nil {
		return nil, err
	}
	return startSingBox(data)
}

func launchXray(p *profile.Profile, s *profile.Settings) (Engine, error) {
	if startXray == nil {
		return nil, fmt.Errorf("the xray core is not compiled into this binary")
	}
	cfg, err := xrayConfig(p, s)
	if err != nil {
		return nil, err
	}
	data, err := marshal(cfg)
	if err != nil {
		return nil, err
	}
	return startXray(data)
}

// pinServer resolves the server hostname up front so the core connects to a
// fixed IP that can be routed around the TUN. The original hostname is kept for
// TLS SNI and HTTP Host so CDN-fronted servers keep working.
func pinServer(ctx context.Context, p *profile.Profile) ([]string, error) {
	if ip := net.ParseIP(p.Server); ip != nil {
		return []string{hostPrefix(ip)}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, p.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", p.Server, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", p.Server)
	}
	host := p.Server
	if p.TLS.Mode != "" && p.TLS.SNI == "" {
		p.TLS.SNI = host
	}
	switch p.Transport.Network {
	case "ws", "httpupgrade", "xhttp":
		if p.Transport.Host == "" {
			p.Transport.Host = host
		}
	}
	chosen := addrs[0].IP
	for _, a := range addrs {
		if a.IP.To4() != nil {
			chosen = a.IP
			break
		}
	}
	p.Server = chosen.String()
	exclude := make([]string, 0, len(addrs))
	for _, a := range addrs {
		exclude = append(exclude, hostPrefix(a.IP))
	}
	return exclude, nil
}

func hostPrefix(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

var errNeedsPrivileges = errors.New("TUN mode needs root (Linux/macOS: run with sudo) or Administrator (Windows)")

func withTUNHint(err error, tun bool) error {
	if !tun {
		return err
	}
	return fmt.Errorf("%w (%w)", err, errNeedsPrivileges)
}

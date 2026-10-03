package mkmobile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

var errUnsupported = errors.New("not supported by MKConnect on this platform")

// platform adapts the VpnService (Platform) to sing-box's platform interface.
// Without an app (proxy-only mode) sing-box uses its own defaults.
type platform struct {
	app            Platform
	networkManager adapter.NetworkManager
	tunAddrs       []netip.Addr
}

func newPlatform(app Platform) *platform { return &platform{app: app} }

func (p *platform) Initialize(nm adapter.NetworkManager) error {
	p.networkManager = nm
	return nil
}

func (p *platform) UsePlatformAutoDetectInterfaceControl() bool { return p.app != nil }

// AutoDetectInterfaceControl keeps the core's own sockets out of the VPN.
func (p *platform) AutoDetectInterfaceControl(fd int) error {
	if !p.app.Protect(int32(fd)) {
		return errors.New("VpnService.protect failed")
	}
	return nil
}

func (p *platform) UsePlatformInterface() bool { return p.app != nil }

func (p *platform) OpenInterface(options *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	routes, err := options.BuildAutoRouteRanges(true)
	if err != nil {
		return nil, err
	}
	cfg := &TunConfig{mtu: int32(options.MTU)}
	for _, a := range options.Inet4Address {
		cfg.inet4 = append(cfg.inet4, a.String())
	}
	for _, a := range options.Inet6Address {
		cfg.inet6 = append(cfg.inet6, a.String())
	}
	for _, r := range routes {
		if r.Addr().Is4() {
			cfg.routes4 = append(cfg.routes4, r.String())
		} else {
			cfg.routes6 = append(cfg.routes6, r.String())
		}
	}
	if dns, err := options.DNSServerAddress(); err == nil && len(dns) > 0 {
		cfg.dns = dns[0].String()
	}

	fd, err := p.app.OpenTun(cfg)
	if err != nil {
		return nil, err
	}
	if options.Name, err = tunnelName(fd); err != nil {
		return nil, err
	}
	if options.InterfaceMonitor != nil {
		options.InterfaceMonitor.RegisterMyInterface(options.Name)
	}
	// sing-tun closes the descriptor it is given; the VpnService keeps its own.
	if options.FileDescriptor, err = dupFD(int(fd)); err != nil {
		return nil, err
	}
	p.tunAddrs = p.tunAddrs[:0]
	for _, a := range options.Inet4Address {
		p.tunAddrs = append(p.tunAddrs, a.Addr())
	}
	for _, a := range options.Inet6Address {
		p.tunAddrs = append(p.tunAddrs, a.Addr())
	}
	return tun.New(*options)
}

func (p *platform) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }

func (p *platform) UsePlatformDefaultInterfaceMonitor() bool { return p.app != nil }

func (p *platform) CreateDefaultInterfaceMonitor(l logger.Logger) tun.DefaultInterfaceMonitor {
	m := &monitor{platform: p, logger: l}
	monitorMu.Lock()
	current = m
	monitorMu.Unlock()
	return m
}

func (p *platform) UsePlatformNetworkInterfaces() bool { return p.app != nil }

// interfaceJSON is one entry of Platform.Interfaces.
type interfaceJSON struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	Flags     int      `json:"flags"` // net.Flags bits: up=1 broadcast=2 loopback=4 p2p=8 multicast=16 running=32
	Type      int      `json:"type"`  // 0 wifi, 1 cellular, 2 ethernet, 3 other
	DNS       []string `json:"dns"`
	Metered   bool     `json:"metered"`
}

func (p *platform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	var in []interfaceJSON
	if err := json.Unmarshal([]byte(p.app.Interfaces()), &in); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []adapter.NetworkInterface
	for _, i := range in {
		if seen[i.Name] {
			continue
		}
		seen[i.Name] = true
		var addrs []netip.Prefix
		for _, a := range i.Addresses {
			if pfx, err := netip.ParsePrefix(a); err == nil {
				addrs = append(addrs, pfx)
			}
		}
		out = append(out, adapter.NetworkInterface{
			Interface:  control.Interface{Index: i.Index, MTU: i.MTU, Name: i.Name, Addresses: addrs, Flags: net.Flags(i.Flags)},
			Type:       C.InterfaceType(i.Type),
			DNSServers: i.DNS,
			Expensive:  i.Metered,
		})
	}
	return out, nil
}

func (p *platform) UnderNetworkExtension() bool                               { return false }
func (p *platform) NetworkExtensionIncludeAllNetworks() bool                  { return false }
func (p *platform) ClearDNSCache()                                            {}
func (p *platform) RequestPermissionForWIFIState() error                      { return nil }
func (p *platform) ReadWIFIState(context.Context) adapter.WIFIState           { return adapter.WIFIState{} }
func (p *platform) UsePlatformConnectionOwnerFinder() bool                    { return false }
func (p *platform) UsePlatformWIFIMonitor() bool                              { return false }
func (p *platform) UsePlatformNotification() bool                             { return false }
func (p *platform) SendNotification(*adapter.Notification) error              { return nil }
func (p *platform) CancelNotification(string, int32) error                    { return nil }
func (p *platform) MyInterfaceAddress() []netip.Addr                          { return p.tunAddrs }
func (p *platform) UsePlatformNeighborResolver() bool                         { return false }
func (p *platform) StartNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (p *platform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (p *platform) UsePlatformShell() bool                                    { return false }
func (p *platform) CheckPlatformShell() error                                 { return errUnsupported }
func (p *platform) LookupSFTPServer() (string, error)                         { return "", errUnsupported }
func (p *platform) ReadSystemSSHHostKey() ([]byte, error)                     { return nil, errUnsupported }
func (p *platform) TailscaleHostname() string                                 { return "" }
func (p *platform) UsePlatformBridge() bool                                   { return false }

func (p *platform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errUnsupported
}

func (p *platform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, errUnsupported
}

func (p *platform) LookupUser(string) (*adapter.PlatformUser, error) { return nil, errUnsupported }

func (p *platform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, errUnsupported
}

// monitor tracks Android's default network, reported by the app through
// UpdateDefaultInterface (ConnectivityManager callbacks).
type monitor struct {
	*platform
	logger    logger.Logger
	mu        sync.Mutex
	def       *control.Interface
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
	mine      []string
}

var (
	monitorMu sync.Mutex
	current   *monitor
	lastName  string
	lastIndex int32 = -1
)

func (m *monitor) Start() error {
	monitorMu.Lock()
	name, index := lastName, lastIndex
	monitorMu.Unlock()
	if index >= 0 {
		m.update(name, index)
	}
	return nil
}

func (m *monitor) Close() error {
	monitorMu.Lock()
	if current == m {
		current = nil
	}
	monitorMu.Unlock()
	return nil
}

func (m *monitor) DefaultInterface() *control.Interface {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.def
}

func (m *monitor) OverrideAndroidVPN() bool { return false }
func (m *monitor) AndroidVPNEnabled() bool  { return false }

func (m *monitor) RegisterCallback(cb tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(cb)
}

func (m *monitor) UnregisterCallback(e *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(e)
}

func (m *monitor) RegisterMyInterface(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mine = append(m.mine, name)
}

func (m *monitor) MyInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mine
}

func (m *monitor) update(name string, index int32) {
	if m.networkManager != nil {
		if err := m.networkManager.UpdateInterfaces(); err != nil && m.logger != nil {
			m.logger.Error("update interfaces: ", err)
		}
	}
	var iface *control.Interface
	if index >= 0 && m.networkManager != nil {
		found, err := m.networkManager.InterfaceFinder().ByIndex(int(index))
		if err != nil {
			if m.logger != nil {
				m.logger.Error("find default interface ", name, ": ", err)
			}
			return
		}
		iface = found
	}
	m.mu.Lock()
	m.def = iface
	callbacks := m.callbacks.Array()
	m.mu.Unlock()
	for _, cb := range callbacks {
		cb(iface, 0)
	}
}

// UpdateDefaultInterface is called by the app when Android's default network
// changes (index -1: no network).
func UpdateDefaultInterface(name string, index int32) {
	monitorMu.Lock()
	lastName, lastIndex = name, index
	m := current
	monitorMu.Unlock()
	if m != nil {
		go m.update(strings.TrimSpace(name), index)
	}
}

func dupFD(fd int) (int, error) {
	n, err := dup(fd)
	if err != nil {
		return 0, os.NewSyscallError("dup", err)
	}
	return n, nil
}

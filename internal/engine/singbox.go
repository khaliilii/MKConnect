//go:build !no_singbox

package engine

import (
	"context"
	"net"
	"sync/atomic"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	sbservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/trojan"
	sbtun "github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func init() {
	startSingBox = newSingBox
	parseSingBox = func(config []byte) error {
		_, err := json.UnmarshalExtendedContext[option.Options](newSingBoxContext(), config)
		return err
	}
}

func newSingBoxContext() context.Context {
	return singBoxContext(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
}

type singBoxEngine struct {
	box     *box.Box
	cancel  context.CancelFunc
	traffic *proxyTraffic
}

func newSingBox(config []byte) (Engine, error) {
	base := newSingBoxContext()
	options, err := json.UnmarshalExtendedContext[option.Options](base, config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(base))
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return nil, err
	}
	traffic := &proxyTraffic{}
	instance.Router().AppendTracker(traffic)
	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return nil, err
	}
	return &singBoxEngine{box: instance, cancel: cancel, traffic: traffic}, nil
}

func (e *singBoxEngine) Traffic() (up, down int64) {
	return e.traffic.up.Load(), e.traffic.down.Load()
}

// proxyTraffic counts bytes of connections routed to the proxy outbound.
type proxyTraffic struct {
	up, down atomic.Int64
}

func (t *proxyTraffic) RoutedConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ adapter.Rule, out adapter.Outbound) net.Conn {
	if out == nil || out.Tag() != tagProxy {
		return conn
	}
	// conn is the client side: reading from it is upload, writing to it is download.
	return bufio.NewInt64CounterConn(conn, []*atomic.Int64{&t.up}, []*atomic.Int64{&t.down})
}

func (t *proxyTraffic) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, out adapter.Outbound) N.PacketConn {
	if out == nil || out.Tag() != tagProxy {
		return conn
	}
	return bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&t.up}, nil, []*atomic.Int64{&t.down}, nil)
}

func (t *proxyTraffic) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

func (e *singBoxEngine) Close() error {
	defer e.cancel()
	return e.box.Close()
}

// singBoxContext registers only the protocols MKConnect generates configs for,
// instead of sing-box's include package, which drags in every protocol
// (naive/cronet, tailscale, openvpn, ...) and their native libraries.
func singBoxContext(ctx context.Context) context.Context {
	inbounds := inbound.NewRegistry()
	sbtun.RegisterInbound(inbounds)
	mixed.RegisterInbound(inbounds)

	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	block.RegisterOutbound(outbounds)
	socks.RegisterOutbound(outbounds)
	shadowsocks.RegisterOutbound(outbounds)
	vmess.RegisterOutbound(outbounds)
	vless.RegisterOutbound(outbounds)
	trojan.RegisterOutbound(outbounds)
	ssh.RegisterOutbound(outbounds)

	dnsTransports := dns.NewTransportRegistry()
	transport.RegisterTCP(dnsTransports)
	transport.RegisterUDP(dnsTransports)
	local.RegisterTransport(dnsTransports)

	return box.Context(ctx, inbounds, outbounds, endpoint.NewRegistry(), dnsTransports,
		sbservice.NewRegistry(), certificate.NewRegistry())
}

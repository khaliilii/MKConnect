//go:build !no_singbox

package engine

import (
	"context"

	box "github.com/sagernet/sing-box"
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
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common/json"
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
	box    *box.Box
	cancel context.CancelFunc
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
	if err := instance.Start(); err != nil {
		instance.Close()
		cancel()
		return nil, err
	}
	return &singBoxEngine{box: instance, cancel: cancel}, nil
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
	tun.RegisterInbound(inbounds)
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

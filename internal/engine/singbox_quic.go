//go:build with_quic && !no_singbox

package engine

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/tuic"
)

// QUIC-based protocols are only built with the with_quic tag, like in sing-box itself.
func init() {
	registerQUICOutbounds = func(r *outbound.Registry) {
		hysteria2.RegisterOutbound(r)
		tuic.RegisterOutbound(r)
	}
}

package engine

// UDP through an SSH tunnel with badvpn-udpgw: the SSH server runs
// `badvpn-udpgw --listen-addr 127.0.0.1:7300`; the client opens a TCP
// connection to that port through the tunnel and relays UDP datagrams over it,
// framed as the udpgw protocol describes (protocol/packetproto.h and
// udpgw/udpgw_proto.h of badvpn):
//
//	uint16 length (little-endian)                 packetproto header
//	uint8  flags, uint16 conid (little-endian)    udpgw header
//	ipv4 (4 bytes) or ipv6 (16 bytes) address, uint16 port (big-endian)
//	payload
//
// Each SOCKS UDP association gets its own udpgw connection; every destination
// inside it gets a conid. With the DNS flag the server sends the datagram to
// its own resolver instead of the given address ("transparent DNS").

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	udpgwFlagKeepAlive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3

	udpgwMaxFrame  = 65535 // PACKETPROTO_MAXPAYLOAD
	udpgwKeepAlive = 10 * time.Second
	udpgwMaxFlows  = 256 // destinations per association before the oldest conid is reused

	udpgwReplyHeadroom = 64 // the SOCKS UDP header is at most 3 + 1 + 255 + 2 bytes for a name, 22 for an address
)

// udpgwSession relays the datagrams of one SOCKS UDP association.
type udpgwSession struct {
	tunnel  net.Conn     // TCP to udpgw, through SSH
	packets N.PacketConn // the SOCKS side
	dns     bool         // transparent DNS: port 53 goes to the server's resolver

	writeMu sync.Mutex
	flowMu  sync.Mutex
	ids     map[string]uint16 // destination -> conid
	order   []string          // destinations, oldest first
	next    uint16
}

// relayUDPGW runs the association until either side ends.
func relayUDPGW(tunnel net.Conn, packets N.PacketConn, dns bool) error {
	s := &udpgwSession{tunnel: tunnel, packets: packets, dns: dns, ids: map[string]uint16{}}
	errc := make(chan error, 2)
	done := make(chan struct{})
	go func() { errc <- s.upstream() }()
	go func() { errc <- s.downstream() }()
	go func() {
		t := time.NewTicker(udpgwKeepAlive)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.write(udpgwFlagKeepAlive, 0, M.Socksaddr{}, nil)
			}
		}
	}()
	err := <-errc
	close(done)
	tunnel.Close()
	packets.Close()
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// upstream sends the SOCKS side's datagrams to udpgw.
func (s *udpgwSession) upstream() error {
	for {
		buffer := buf.NewPacket()
		dst, err := s.packets.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return err
		}
		if dst.IsFqdn() {
			// udpgw only takes addresses; resolve here (the SOCKS client normally already has).
			if addr, err := net.ResolveUDPAddr("udp", dst.String()); err == nil {
				dst = M.SocksaddrFromNet(addr)
			}
		}
		if dst.IsIP() {
			flags, conid := s.conidFor(dst)
			if s.dns && dst.Port == 53 {
				flags |= udpgwFlagDNS
			}
			if err := s.write(flags, conid, dst, buffer.Bytes()); err != nil {
				buffer.Release()
				return err
			}
		}
		buffer.Release()
	}
}

// conidFor returns the connection id for a destination, reusing the oldest
// one (with the rebind flag) when there are too many.
func (s *udpgwSession) conidFor(dst M.Socksaddr) (flags byte, conid uint16) {
	key := dst.String()
	s.flowMu.Lock()
	defer s.flowMu.Unlock()
	if id, ok := s.ids[key]; ok {
		return 0, id
	}
	if len(s.order) >= udpgwMaxFlows {
		oldest := s.order[0]
		s.order = s.order[1:]
		conid = s.ids[oldest]
		delete(s.ids, oldest)
		flags = udpgwFlagRebind
	} else {
		s.next++
		conid = s.next
	}
	s.ids[key] = conid
	s.order = append(s.order, key)
	return flags, conid
}

// write sends one udpgw frame.
func (s *udpgwSession) write(flags byte, conid uint16, dst M.Socksaddr, payload []byte) error {
	frame := encodeUDPGWFrame(flags, conid, dst, payload)
	if frame == nil {
		return nil // too large for the protocol: dropped, as a router would
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.tunnel.Write(frame)
	return err
}

// encodeUDPGWFrame builds a length-prefixed udpgw frame; nil when too large.
func encodeUDPGWFrame(flags byte, conid uint16, dst M.Socksaddr, payload []byte) []byte {
	var addr []byte
	if dst.IsIP() {
		addr = udpgwAddress(dst)
		if dst.Addr.Unmap().Is6() {
			flags |= udpgwFlagIPv6
		}
	}
	n := 3 + len(addr) + len(payload)
	if n > udpgwMaxFrame {
		return nil
	}
	frame := make([]byte, 2+n)
	binary.LittleEndian.PutUint16(frame, uint16(n))
	frame[2] = flags
	binary.LittleEndian.PutUint16(frame[3:], conid)
	copy(frame[5:], addr)
	copy(frame[5+len(addr):], payload)
	return frame
}

func udpgwAddress(a M.Socksaddr) []byte {
	ip := a.Addr.Unmap()
	var out []byte
	if ip.Is6() {
		b := ip.As16()
		out = append(out, b[:]...)
	} else {
		b := ip.As4()
		out = append(out, b[:]...)
	}
	return binary.BigEndian.AppendUint16(out, a.Port)
}

// downstream passes udpgw's replies to the SOCKS side, with the original
// destination as their source.
func (s *udpgwSession) downstream() error {
	r := bufio.NewReaderSize(s.tunnel, 2+udpgwMaxFrame)
	var head [2]byte
	for {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return err
		}
		n := int(binary.LittleEndian.Uint16(head[:]))
		frame := make([]byte, n)
		if _, err := io.ReadFull(r, frame); err != nil {
			return err
		}
		flags, src, payload, err := parseUDPGWFrame(frame)
		if err != nil {
			return err
		}
		if flags&udpgwFlagKeepAlive != 0 {
			continue
		}
		buffer := buf.NewPacket()
		buffer.Resize(udpgwReplyHeadroom, 0) // room for the SOCKS UDP header in front
		buffer.Write(payload)
		if err := s.packets.WritePacket(buffer, src); err != nil {
			return err
		}
	}
}

// parseUDPGWFrame splits a frame (without the length prefix) into its parts.
func parseUDPGWFrame(frame []byte) (flags byte, addr M.Socksaddr, payload []byte, err error) {
	if len(frame) < 3 {
		return 0, M.Socksaddr{}, nil, fmt.Errorf("udpgw: short frame (%d bytes)", len(frame))
	}
	flags = frame[0]
	rest := frame[3:]
	if flags&udpgwFlagKeepAlive != 0 {
		return flags, M.Socksaddr{}, nil, nil
	}
	addrLen := 4
	if flags&udpgwFlagIPv6 != 0 {
		addrLen = 16
	}
	if len(rest) < addrLen+2 {
		return 0, M.Socksaddr{}, nil, fmt.Errorf("udpgw: frame without address")
	}
	ip, _ := netip.AddrFromSlice(rest[:addrLen])
	port := binary.BigEndian.Uint16(rest[addrLen:])
	return flags, M.SocksaddrFrom(ip, port), rest[addrLen+2:], nil
}

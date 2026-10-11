package engine

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// startFakeUDPGW runs a udpgw server that behaves like badvpn-udpgw: every
// conid of a client becomes a UDP socket to the given address, or to the
// server's "resolver" dnsAddr when the DNS flag is set. Replies carry the
// address the client originally used.
func startFakeUDPGW(t *testing.T, dnsAddr string) (addr string, dnsFlagged *int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var flagged int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveFakeUDPGW(conn, dnsAddr, &flagged)
		}
	}()
	return l.Addr().String(), &flagged
}

func serveFakeUDPGW(conn net.Conn, dnsAddr string, flagged *int32) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	var writeMu sync.Mutex
	type flow struct {
		sock *net.UDPConn
		orig M.Socksaddr
	}
	flows := map[uint16]*flow{}
	defer func() {
		for _, f := range flows {
			f.sock.Close()
		}
	}()
	var head [2]byte
	for {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return
		}
		frame := make([]byte, binary.LittleEndian.Uint16(head[:]))
		if _, err := io.ReadFull(r, frame); err != nil {
			return
		}
		flags, dst, payload, err := parseUDPGWFrame(frame)
		if err != nil || flags&udpgwFlagKeepAlive != 0 {
			continue
		}
		conid := binary.LittleEndian.Uint16(frame[1:3])
		if f, ok := flows[conid]; ok && (flags&udpgwFlagRebind != 0 || f.orig != dst) {
			f.sock.Close()
			delete(flows, conid)
		}
		f, ok := flows[conid]
		if !ok {
			target := dst.UDPAddr()
			if flags&udpgwFlagDNS != 0 {
				*flagged++
				target, _ = net.ResolveUDPAddr("udp", dnsAddr)
			}
			sock, err := net.DialUDP("udp", nil, target)
			if err != nil {
				continue
			}
			f = &flow{sock: sock, orig: dst}
			flows[conid] = f
			go func(conid uint16, f *flow) {
				b := make([]byte, 65535)
				for {
					n, err := f.sock.Read(b)
					if err != nil {
						return
					}
					writeMu.Lock()
					conn.Write(encodeUDPGWFrame(0, conid, f.orig, b[:n]))
					writeMu.Unlock()
				}
			}(conid, f)
		}
		f.sock.Write(payload)
	}
}

// udpResponder answers every datagram with prefix + the datagram.
func udpResponder(t *testing.T, prefix string) *net.UDPAddr {
	return udpResponderAt(t, prefix, "127.0.0.1:0")
}

func udpResponderAt(t *testing.T, prefix, addr string) *net.UDPAddr {
	t.Helper()
	laddr, _ := net.ResolveUDPAddr("udp", addr)
	c, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			c.WriteToUDP(append([]byte(prefix), b[:n]...), from)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr)
}

func TestSSHUDPThroughUDPGW(t *testing.T) {
	sshAddr, hostKey := startTestSSHServer(t)
	echo := udpResponder(t, "echo:")
	// With MKCONNECT_UDPGW_ADDR a real badvpn-udpgw (reachable from the test
	// SSH server, i.e. on this host) is used instead of the fake one; its
	// transparent DNS then goes to the resolver of /etc/resolv.conf, which
	// scripts/test-udpgw-linux.sh points at 127.0.0.1:53.
	gwAddr, real := os.LookupEnv("MKCONNECT_UDPGW_ADDR")
	var dnsFlagged *int32
	var resolver *net.UDPAddr
	if real {
		resolver = udpResponderAt(t, "dns:", "127.0.0.1:53")
	} else {
		resolver = udpResponder(t, "dns:")
		gwAddr, dnsFlagged = startFakeUDPGW(t, resolver.String())
	}
	_, gwPort, _ := net.SplitHostPort(gwAddr)
	gw, _ := strconv.Atoi(gwPort)

	host, portStr, _ := net.SplitHostPort(sshAddr)
	port, _ := strconv.Atoi(portStr)
	p := profile.Profile{Name: "ssh", Type: profile.TypeSSH, Server: host, Port: port, User: "u", Password: "p",
		HostKey: hostKey, UDPGWPort: gw, UDPGWDNS: true}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s := testSettings(t)
	s.ProxyUser, s.ProxyPass = "u", "p"
	e, err := startSSH(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitListening(t, s.ListenPort)

	client := socks.NewClient(N.SystemDialer, M.ParseSocksaddr("127.0.0.1:"+strconv.Itoa(s.ListenPort)), socks.Version5, "u", "p")
	pc, err := client.ListenPacket(t.Context(), M.SocksaddrFromNet(echo))
	if err != nil {
		t.Fatalf("UDP associate: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(10 * time.Second))

	// A datagram to the echo server and back, several times over the same association.
	buf := make([]byte, 65535)
	for i := range 3 {
		if _, err := pc.WriteTo([]byte("ping"), echo); err != nil {
			t.Fatal(err)
		}
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("round %d: no reply through udpgw: %v", i, err)
		}
		if string(buf[:n]) != "echo:ping" || from.String() != echo.String() {
			t.Fatalf("round %d: got %q from %s", i, buf[:n], from)
		}
	}

	// Transparent DNS: port 53 anywhere is answered by the server's resolver,
	// and the reply comes back from the address that was asked.
	fakeDNS := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 53}
	if _, err := pc.WriteTo([]byte("query"), fakeDNS); err != nil {
		t.Fatal(err)
	}
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no DNS reply: %v", err)
	}
	if string(buf[:n]) != "dns:query" || from.String() != fakeDNS.String() || (dnsFlagged != nil && *dnsFlagged != 1) {
		t.Fatalf("DNS: got %q from %s", buf[:n], from)
	}
	t.Logf("transparent DNS answered by the resolver at %s", resolver)

	// TCP still works through the same SOCKS server.
	target := newTarget(t)
	if body := getThroughSOCKS(t, s.ListenPort, "u", "p", target.URL); body != "hello through tunnel" {
		t.Fatalf("tcp: %q", body)
	}
	up, down := e.(trafficCounter).Traffic()
	if up == 0 || down == 0 {
		t.Fatalf("traffic not counted: %d/%d", up, down)
	}
}

func TestSSHUDPWithoutUDPGW(t *testing.T) {
	sshAddr, hostKey := startTestSSHServer(t)
	host, portStr, _ := net.SplitHostPort(sshAddr)
	port, _ := strconv.Atoi(portStr)
	p := profile.Profile{Name: "ssh", Type: profile.TypeSSH, Server: host, Port: port, User: "u", Password: "p", HostKey: hostKey}
	s := testSettings(t)
	e, err := startSSH(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitListening(t, s.ListenPort)
	client := socks.NewClient(N.SystemDialer, M.ParseSocksaddr("127.0.0.1:"+strconv.Itoa(s.ListenPort)), socks.Version5, "", "")
	pc, err := client.ListenPacket(t.Context(), M.ParseSocksaddr("1.1.1.1:53"))
	if err == nil {
		// The association may open before the server rejects it; a datagram then gets no answer.
		pc.SetDeadline(time.Now().Add(2 * time.Second))
		pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
		if _, _, err := pc.ReadFrom(make([]byte, 16)); err == nil {
			t.Fatal("UDP answered without udpgw")
		}
		pc.Close()
	}
}

func TestSSHLinkUDPGW(t *testing.T) {
	p, err := profile.ParseLink("ssh://root:pw@h.com:22?udpgw=7300&udpgw_dns=1#srv")
	if err != nil || p.UDPGWPort != 7300 || !p.UDPGWDNS {
		t.Fatalf("parse: %+v %v", p, err)
	}
	// Exported links leave the password out; put it back to parse the rest.
	link := strings.Replace(p.Link(), "ssh://root@", "ssh://root:pw@", 1)
	q, err := profile.ParseLink(link)
	if err != nil || q.UDPGWPort != 7300 || !q.UDPGWDNS {
		t.Fatalf("round trip: %s -> %+v %v", p.Link(), q, err)
	}
}

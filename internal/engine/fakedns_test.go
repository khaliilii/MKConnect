//go:build !no_singbox

package engine

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/protocol/direct"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestFakeDNS runs the TUN configuration with FakeDNS, a UDP inbound standing
// in for the TUN: a lookup is answered at once with a placeholder address and
// a short TTL, HTTPS records come back empty, and a connection to the
// placeholder reaches the site by its name through the server.
func TestFakeDNS(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	registerTestInbounds = direct.RegisterInbound
	defer func() { registerTestInbounds = nil }()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello "+r.Host)
	}))
	defer site.Close()
	_, sitePort, _ := net.SplitHostPort(strings.TrimPrefix(site.URL, "http://"))

	ssPort := freePort(t)
	startProtocolServer(t, []obj{{
		"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ssPort,
		"method": "aes-256-gcm", "password": "pw",
	}})
	p := profile.Profile{Name: "ss", Type: profile.TypeShadowsocks, Server: "127.0.0.1", Port: ssPort, Method: "aes-256-gcm", Password: "pw"}
	s := testSettings(t)
	s.FakeDNS = true
	cfg, err := singBoxConfig(&p, &s, &tunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dnsPort := freePort(t)
	cfg["inbounds"].([]obj)[1] = obj{"type": "direct", "tag": "tun-in", "listen": "127.0.0.1", "listen_port": dnsPort, "network": "udp"}
	delete(cfg["route"].(obj), "auto_detect_interface")
	data, _ := marshal(cfg)
	e, err := startSingBox(data)
	if err != nil {
		t.Fatalf("sing-box refused the FakeDNS config: %v", err)
	}
	defer e.Close()
	if err := waitPort(t.Context(), s.ListenPort, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	c := &dns.Client{Net: "udp"}
	ask := func(qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("localhost.", qtype)
		r, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", dnsPort))
		if err != nil {
			t.Fatalf("lookup %s: %v", dns.TypeToString[qtype], err)
		}
		return r
	}
	r := ask(dns.TypeA)
	if len(r.Answer) != 1 {
		t.Fatalf("A answer: %v", r)
	}
	a := r.Answer[0].(*dns.A)
	fake, _ := netip.AddrFromSlice(a.A.To4())
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(fake) || a.Hdr.Ttl > 10 {
		t.Fatalf("want a placeholder with a short TTL, got %v", a)
	}
	if r := ask(dns.TypeAAAA); len(r.Answer) != 0 || r.Rcode != dns.RcodeSuccess {
		t.Errorf("AAAA without IPv6 should be empty: %v", r)
	}
	if r := ask(dns.TypeHTTPS); len(r.Answer) != 0 || r.Rcode != dns.RcodeSuccess {
		t.Errorf("HTTPS records should be empty: %v", r)
	}

	client := proxyClient(s.ListenPort, 0)
	defer client.CloseIdleConnections()
	resp, err := client.Get(fmt.Sprintf("http://%s:%s/", fake, sitePort))
	if err != nil {
		t.Fatalf("connection to the placeholder: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

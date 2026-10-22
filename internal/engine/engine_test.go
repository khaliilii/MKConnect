package engine

import (
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

var testProfiles = []profile.Profile{
	{Name: "vmess-ws", Type: profile.TypeVMess, Server: "127.0.0.1", Port: 10001, UUID: "bf000d23-0752-40b4-affe-68f7707a9661",
		Transport: profile.Transport{Network: "ws", Path: "/ray?ed=2048", Host: "a.com"}, TLS: profile.TLS{Mode: "tls", SNI: "a.com", Fingerprint: "chrome"}},
	{Name: "vless-reality", Type: profile.TypeVLESS, Server: "127.0.0.1", Port: 10002, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Flow: "xtls-rprx-vision",
		TLS: profile.TLS{Mode: "reality", SNI: "www.microsoft.com", RealityPublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", RealityShortID: "6ba85179"}},
	{Name: "vless-grpc", Type: profile.TypeVLESS, Server: "127.0.0.1", Port: 10003, UUID: "bf000d23-0752-40b4-affe-68f7707a9661",
		Transport: profile.Transport{Network: "grpc", ServiceName: "gun"}, TLS: profile.TLS{Mode: "tls"}},
	{Name: "trojan", Type: profile.TypeTrojan, Server: "127.0.0.1", Port: 10004, Password: "x", TLS: profile.TLS{Mode: "tls"}},
	{Name: "ss", Type: profile.TypeShadowsocks, Server: "127.0.0.1", Port: 10005, Method: "aes-256-gcm", Password: "x"},
}

var sshProfile = profile.Profile{Name: "ssh", Type: profile.TypeSSH, Server: "127.0.0.1", Port: 22, User: "u", Password: "p",
	HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}

func testSettings(t *testing.T) profile.Settings {
	s := profile.DefaultSettings()
	s.ListenPort = freePort(t)
	s.LogLevel = "error"
	return s
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %d", port)
}

// TestSingBoxStarts checks every generated sing-box config is accepted and
// serves the local proxy (proxy mode; TUN needs root so it is only parsed).
func TestSingBoxStarts(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	for _, p := range append(append([]profile.Profile{}, testProfiles...), sshProfile) {
		t.Run(p.Name, func(t *testing.T) {
			s := testSettings(t)
			s.ProxyUser, s.ProxyPass = "u", "p"
			cfg, err := singBoxConfig(&p, &s, nil)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := marshal(cfg)
			e, err := startSingBox(data)
			if err != nil {
				t.Fatalf("%v\n%s", err, data)
			}
			defer e.Close()
			waitListening(t, s.ListenPort)
		})
	}
}

func TestSingBoxTUNConfigParses(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	s := testSettings(t)
	cfgs := []obj{singBoxTUNConfig(&s, 1080, &tunOptions{ExcludeAddrs: []string{"1.2.3.4/32"}})}
	full, err := singBoxConfig(&testProfiles[0], &s, &tunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cfgs = append(cfgs, full)
	for _, cfg := range cfgs {
		data, _ := marshal(cfg)
		if err := parseSingBox(data); err != nil {
			t.Fatalf("%v\n%s", err, data)
		}
	}
}

func TestXrayStarts(t *testing.T) {
	if startXray == nil {
		t.Skip("xray not compiled in")
	}
	for _, p := range testProfiles {
		t.Run(p.Name, func(t *testing.T) {
			s := testSettings(t)
			cfg, err := xrayConfig(&p, &s)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := marshal(cfg)
			e, err := startXray(data)
			if err != nil {
				t.Fatalf("%v\n%s", err, data)
			}
			defer e.Close()
			waitListening(t, s.ListenPort)
		})
	}
}

func TestXrayRejectsSSHAndInsecure(t *testing.T) {
	s := profile.DefaultSettings()
	if _, err := xrayConfig(&sshProfile, &s); err == nil {
		t.Fatal("expected error for ssh on xray")
	}
	p := testProfiles[3]
	p.TLS.Insecure = true
	if _, err := xrayConfig(&p, &s); err == nil {
		t.Fatal("expected error for insecure tls on xray")
	}
}

func TestSplitEarlyData(t *testing.T) {
	for in, want := range map[string]struct {
		path string
		ed   int
	}{
		"/ray?ed=2048": {"/ray", 2048},
		"/ray":         {"/ray", 0},
		"/ray?x=1":     {"/ray?x=1", 0},
	} {
		path, ed := splitEarlyData(in)
		if path != want.path || ed != want.ed {
			t.Errorf("%s: got %s %d", in, path, ed)
		}
	}
}

func TestPinServerKeepsHostname(t *testing.T) {
	p := profile.Profile{Server: "localhost", Port: 443, TLS: profile.TLS{Mode: "tls"}, Transport: profile.Transport{Network: "ws"}}
	exclude, err := pinServer(t.Context(), &p)
	if err != nil {
		t.Fatal(err)
	}
	if net.ParseIP(p.Server) == nil || p.TLS.SNI != "localhost" || p.Transport.Host != "localhost" || len(exclude) == 0 {
		t.Fatalf("unexpected: %+v %v", p, exclude)
	}
}

func TestTUNGatewayConfig(t *testing.T) {
	s := testSettings(t)
	s.Mode, s.ShareInterfaces = profile.ModeTUN, []string{"eth1"}
	cfg, err := singBoxConfig(&testProfiles[0], &s, &tunOptions{Gateway: true})
	if err != nil {
		t.Fatal(err)
	}
	var tun obj
	for _, in := range cfg["inbounds"].([]obj) {
		if in["type"] == "tun" {
			tun = in
		}
	}
	switch runtime.GOOS {
	case "linux":
		if tun["auto_redirect"] != true {
			t.Fatal("gateway mode on Linux needs auto_redirect")
		}
	case "windows":
		if tun["interface_name"] != TUNName || tun["strict_route"] != false {
			t.Fatalf("windows gateway tun: %v", tun)
		}
	}
	if parseSingBox != nil {
		data, _ := marshal(cfg)
		if err := parseSingBox(data); err != nil {
			t.Fatal(err)
		}
	}
	session := newSession(&testProfiles[0], &s, nil)
	if !strings.Contains(strings.Join(session.Inbounds, "|"), "Gateway for devices on eth1") {
		t.Fatalf("session doesn't show the gateway: %v", session.Inbounds)
	}
}

func TestTUNIPv6Setting(t *testing.T) {
	s := testSettings(t)
	s.Mode = profile.ModeTUN
	p := profile.Profile{Type: profile.TypeTrojan, Server: "h.com", Port: 443, Password: "x"}
	cfg, err := singBoxConfig(&p, &s, &tunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tun := cfg["inbounds"].([]obj)[1]
	if addrs := tun["address"].([]string); len(addrs) != 1 || cfg["dns"].(obj)["strategy"] != "ipv4_only" {
		t.Fatalf("IPv6 off: addresses %v, dns strategy %v", addrs, cfg["dns"].(obj)["strategy"])
	}
	s.IPv6 = true
	cfg, _ = singBoxConfig(&p, &s, &tunOptions{})
	tun = cfg["inbounds"].([]obj)[1]
	if addrs := tun["address"].([]string); len(addrs) != 2 || cfg["dns"].(obj)["strategy"] != nil {
		t.Fatalf("IPv6 on: addresses %v, dns strategy %v", addrs, cfg["dns"].(obj)["strategy"])
	}
}

// TestPreferredCore pins which core runs which account when sing-box is the
// configured one (the default).
func TestPreferredCore(t *testing.T) {
	if startSingBox == nil || startXray == nil {
		t.Skip("needs both cores")
	}
	sb := profile.Settings{Core: profile.CoreSingBox}
	xr := profile.Settings{Core: profile.CoreXray}
	cases := []struct {
		name string
		p    profile.Profile
		s    profile.Settings
		want string
	}{
		{"vless reality stays on sing-box", profile.Profile{Type: profile.TypeVLESS, TLS: profile.TLS{Mode: "reality"}}, sb, profile.CoreSingBox},
		{"vmess ws stays on sing-box", profile.Profile{Type: profile.TypeVMess, Transport: profile.Transport{Network: "ws"}}, sb, profile.CoreSingBox},
		{"tcp + http header moves to Xray", profile.Profile{Type: profile.TypeVMess, Transport: profile.Transport{HeaderType: "http"}}, sb, profile.CoreXray},
		{"xhttp moves to Xray", profile.Profile{Type: profile.TypeVLESS, Transport: profile.Transport{Network: "xhttp"}}, sb, profile.CoreXray},
		{"hysteria2 moves to sing-box", profile.Profile{Type: profile.TypeHysteria2}, xr, profile.CoreSingBox},
		{"ssh keeps its core", profile.Profile{Type: profile.TypeSSH}, sb, profile.CoreSingBox},
		{"external is never changed", profile.Profile{Type: profile.TypeVMess, Transport: profile.Transport{HeaderType: "http"}},
			profile.Settings{Core: profile.CoreExternal}, profile.CoreExternal},
	}
	for _, c := range cases {
		if got := PreferredCore(&c.p, &c.s); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

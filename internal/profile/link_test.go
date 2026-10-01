package profile

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVMess(t *testing.T) {
	payload := `{"v":"2","ps":"my ws","add":"cdn.example.com","port":"443","id":"bf000d23-0752-40b4-affe-68f7707a9661","aid":0,"scy":"auto","net":"ws","host":"h.example.com","path":"/ray?ed=2048","tls":"tls","sni":"sni.example.com","fp":"chrome"}`
	p, err := ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
	want := Profile{
		Name: "my ws", Type: TypeVMess, Server: "cdn.example.com", Port: 443,
		UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Security: "auto",
		Transport: Transport{Network: "ws", Path: "/ray?ed=2048", Host: "h.example.com"},
		TLS:       TLS{Mode: "tls", SNI: "sni.example.com", Fingerprint: "chrome"},
	}
	assertProfile(t, p, want)
}

func TestParseVLESSReality(t *testing.T) {
	link := "vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6ba85179&type=tcp#DE%20reality"
	p, err := ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	want := Profile{
		Name: "DE reality", Type: TypeVLESS, Server: "1.2.3.4", Port: 443,
		UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Flow: "xtls-rprx-vision",
		TLS: TLS{Mode: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome",
			RealityPublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", RealityShortID: "6ba85179"},
	}
	assertProfile(t, p, want)
}

func TestParseTrojanDefaultsToTLS(t *testing.T) {
	p, err := ParseLink("trojan://secret@t.example.com:443?type=grpc&serviceName=gun#tr")
	if err != nil {
		t.Fatal(err)
	}
	if p.TLS.Mode != "tls" || p.Transport.Network != "grpc" || p.Transport.ServiceName != "gun" || p.Password != "secret" {
		t.Fatalf("unexpected profile: %+v", p)
	}
}

func TestParseShadowsocks(t *testing.T) {
	sip002 := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss")) + "@5.6.7.8:8388#ss%201"
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss@5.6.7.8:8388")) + "#ss%201"
	for _, link := range []string{sip002, legacy} {
		p, err := ParseLink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		want := Profile{Name: "ss 1", Type: TypeShadowsocks, Server: "5.6.7.8", Port: 8388, Method: "aes-256-gcm", Password: "pa:ss"}
		assertProfile(t, p, want)
	}
}

func TestParseSSH(t *testing.T) {
	p, err := ParseLink("ssh://root:p%40ss@10.0.0.1:2222#box")
	if err != nil {
		t.Fatal(err)
	}
	assertProfile(t, p, Profile{Name: "box", Type: TypeSSH, Server: "10.0.0.1", Port: 2222, User: "root", Password: "p@ss"})
}

func TestLinkRoundTrip(t *testing.T) {
	links := []string{
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:443?security=tls&sni=a.com&type=ws&path=%2Fws&host=a.com#rt",
		"trojan://secret@t.example.com:443?security=tls#tr",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@5.6.7.8:8388#s",
	}
	vm := `{"ps":"v","add":"x.com","port":443,"id":"bf000d23-0752-40b4-affe-68f7707a9661","net":"grpc","path":"svc","tls":"tls"}`
	links = append(links, "vmess://"+base64.StdEncoding.EncodeToString([]byte(vm)))
	for _, link := range links {
		p, err := ParseLink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		again, err := ParseLink(p.Link())
		if err != nil {
			t.Fatalf("re-parse %s: %v", p.Link(), err)
		}
		assertProfile(t, again, p)
	}
}

func TestParseLinksSubscription(t *testing.T) {
	sub := base64.StdEncoding.EncodeToString([]byte("trojan://a@h.com:443#one\n\nnot-a-link\nssh://u:p@h.com#two\n"))
	profiles, errs := ParseLinks(sub)
	// Text that isn't a link is ignored, as in v2rayN.
	if len(profiles) != 2 || len(errs) != 0 {
		t.Fatalf("got %d profiles, %d errors", len(profiles), len(errs))
	}
}

func assertProfile(t *testing.T, got, want Profile) {
	t.Helper()
	if got.Name != want.Name || got.Type != want.Type || got.Server != want.Server || got.Port != want.Port ||
		got.User != want.User || got.Password != want.Password || got.UUID != want.UUID ||
		got.Security != want.Security || got.Flow != want.Flow || got.Method != want.Method ||
		got.Transport != want.Transport || got.TLS.Mode != want.TLS.Mode || got.TLS.SNI != want.TLS.SNI ||
		got.TLS.Fingerprint != want.TLS.Fingerprint || got.TLS.RealityPublicKey != want.TLS.RealityPublicKey ||
		got.TLS.RealityShortID != want.TLS.RealityShortID {
		t.Fatalf("profile mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// TestParseLinksFromChatMessage covers what users actually copy: several links
// in one message, separated by spaces or text, with CRLF line endings, an
// unsupported protocol and a subscription URL mixed in.
func TestParseLinksFromChatMessage(t *testing.T) {
	vm := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"🇩🇪 Germany | VMess","add":"de.example.com","port":443,"id":"bf000d23-0752-40b4-affe-68f7707a9661","net":"ws","path":"/","tls":"tls"}`))
	msg := "🔥 New servers! Server 1: vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:443?security=reality&sni=a.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0#NL%201\r\n" +
		"Server 2: trojan://pw@t.example.com:443#TR trojan://pw2@t2.example.com:443#TR2, " +
		"vmess://" + vm + "\r\n" +
		"hy2://secret@hy.example.com:8443?sni=hy.example.com&obfs=salamander&obfs-password=ob#HY2\n" +
		"tuic://bf000d23-0752-40b4-affe-68f7707a9661:pw@tu.example.com:443?congestion_control=bbr&alpn=h3#TUIC\n" +
		"wireguard://unsupported@w.example.com:51820#WG\n" +
		"Subscription: https://panel.example.com/sub/abc (not an account)\n"
	profiles, errs := ParseLinks(msg)
	var names []string
	for _, p := range profiles {
		names = append(names, p.Type+":"+p.Name)
	}
	want := []string{"vless:NL 1", "trojan:TR", "trojan:TR2", "vmess:🇩🇪 Germany | VMess", "hysteria2:HY2", "tuic:TUIC"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("got  %v\nwant %v", names, want)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "wireguard") {
		t.Fatalf("expected one unsupported-scheme error, got %v", errs)
	}
}

func TestParseHysteria2AndTUIC(t *testing.T) {
	hy, err := ParseLink("hysteria2://user:pass@hy.example.com:443,20000-30000/?sni=s.com&insecure=1&obfs=salamander&obfs-password=ob&alpn=h3#hy")
	if err != nil {
		t.Fatal(err)
	}
	if hy.Password != "user:pass" || hy.Port != 443 || hy.ObfsPassword != "ob" || !hy.TLS.Insecure || hy.TLS.SNI != "s.com" {
		t.Fatalf("unexpected hysteria2 profile: %+v", hy)
	}
	tu, err := ParseLink("tuic://bf000d23-0752-40b4-affe-68f7707a9661:pw@tu.com:8443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&allow_insecure=1#tu")
	if err != nil {
		t.Fatal(err)
	}
	if tu.UUID != "bf000d23-0752-40b4-affe-68f7707a9661" || tu.Password != "pw" || tu.CongestionControl != "bbr" || tu.UDPRelayMode != "quic" || !tu.TLS.Insecure {
		t.Fatalf("unexpected tuic profile: %+v", tu)
	}
	for _, p := range []Profile{hy, tu} {
		again, err := ParseLink(p.Link())
		if err != nil {
			t.Fatalf("round trip %s: %v", p.Link(), err)
		}
		if again.Fingerprint() != p.Fingerprint() {
			t.Fatalf("round trip changed the profile:\n%s\n%s", p.Link(), again.Link())
		}
	}
}

func TestExtractLinksBase64Subscription(t *testing.T) {
	body := "trojan://a@h.com:443#one\r\nhy2://x@h.com:443#two\r\n"
	// Some panels wrap base64 at 76 columns.
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	wrapped := enc[:20] + "\n" + enc[20:]
	if got := ExtractLinks(wrapped); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

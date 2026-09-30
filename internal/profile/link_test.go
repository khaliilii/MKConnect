package profile

import (
	"encoding/base64"
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
	if len(profiles) != 2 || len(errs) != 1 {
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

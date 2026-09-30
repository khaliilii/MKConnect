package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// startTestSSHServer runs a minimal SSH server that accepts user/pass and
// forwards direct-tcpip channels, which is all a SOCKS-over-SSH client needs.
func startTestSSHServer(t *testing.T) (addr string, hostKey string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "u" && string(pass) == "p" {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(signer)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serveSSH(conn, cfg)
		}
	}()
	return l.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func serveSSH(conn net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		// payload: host string, port uint32, origin host string, origin port uint32
		data := nc.ExtraData()
		n := binary.BigEndian.Uint32(data)
		host := string(data[4 : 4+n])
		port := binary.BigEndian.Uint32(data[4+n:])
		target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			target.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() {
			defer ch.Close()
			defer target.Close()
			go io.Copy(target, ch)
			io.Copy(ch, target)
		}()
	}
}

func sshTestProfile(t *testing.T, addr string) profile.Profile {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return profile.Profile{Name: "ssh", Type: profile.TypeSSH, Server: host, Port: port, User: "u", Password: "p"}
}

// getThroughSOCKS fetches url via the local SOCKS5 proxy.
func getThroughSOCKS(t *testing.T, port int, user, pass, url string) string {
	t.Helper()
	return getThroughSOCKSAt(t, "127.0.0.1", port, user, pass, url)
}

func getThroughSOCKSAt(t *testing.T, host string, port int, user, pass, url string) string {
	t.Helper()
	body, err := tryThroughSOCKSAt(host, port, user, pass, url)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func tryThroughSOCKSAt(host string, port int, user, pass, url string) (string, error) {
	var auth *proxy.Auth
	if user != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(host, strconv.Itoa(port)), auth, proxy.Direct)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func newTarget(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello through tunnel")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchHostKey(t *testing.T) {
	addr, want := startTestSSHServer(t)
	got, err := FetchHostKey(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("host key mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestBuiltinSSHProxiesTraffic(t *testing.T) {
	addr, hostKey := startTestSSHServer(t)
	target := newTarget(t)

	p := sshTestProfile(t, addr)
	p.HostKey = hostKey
	s := testSettings(t)
	s.ProxyUser, s.ProxyPass = "lan", "secret"

	e, err := startSSH(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if body := getThroughSOCKS(t, s.ListenPort, "lan", "secret", target.URL); body != "hello through tunnel" {
		t.Fatalf("unexpected body %q", body)
	}

	if up, down := e.(*sshEngine).Traffic(); up == 0 || down < int64(len("hello through tunnel")) {
		t.Fatalf("traffic not counted: up=%d down=%d", up, down)
	}

	// Kill the SSH session; the next request must transparently reconnect.
	e.(*sshEngine).current().Close()
	if body := getThroughSOCKS(t, s.ListenPort, "lan", "secret", target.URL); body != "hello through tunnel" {
		t.Fatalf("after reconnect: unexpected body %q", body)
	}
}

func TestBuiltinSSHRejectsWrongHostKey(t *testing.T) {
	addr, _ := startTestSSHServer(t)
	_, otherKey := startTestSSHServer(t)
	p := sshTestProfile(t, addr)
	p.HostKey = otherKey
	s := testSettings(t)
	if e, err := startSSH(&p, &s); err == nil {
		e.Close()
		t.Fatal("connected despite host key mismatch")
	}
}

func TestSingBoxSSHProxiesTraffic(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	addr, hostKey := startTestSSHServer(t)
	target := newTarget(t)

	p := sshTestProfile(t, addr)
	p.HostKey = hostKey
	s := testSettings(t)
	cfg, err := singBoxConfig(&p, &s, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := marshal(cfg)
	e, err := startSingBox(data)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	waitListening(t, s.ListenPort)

	// Use a hostname: private IPs are routed direct, domains go through the SSH outbound.
	url := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	if body := getThroughSOCKS(t, s.ListenPort, "", "", url); body != "hello through tunnel" {
		t.Fatalf("unexpected body %q", body)
	}
	// Upload may be 0 here: sing-box can read the whole (tiny) request during the
	// SOCKS handshake, before the connection reaches the tracker.
	if _, down := e.(trafficCounter).Traffic(); down < int64(len("hello through tunnel")) {
		t.Fatalf("download not counted: %d", down)
	}
}

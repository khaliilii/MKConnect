package engine

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

func TestRenderPayloadPlaceholders(t *testing.T) {
	parts := renderPayload("GET / HTTP/1.1[crlf]Host: [host]:[port] [host_port][crlf][crlf]", "bug.example", 2222)
	if len(parts) != 1 {
		t.Fatalf("want one part, got %d: %+v", len(parts), parts)
	}
	want := "GET / HTTP/1.1\r\nHost: bug.example:2222 bug.example:2222\r\n\r\n"
	if parts[0].data != want {
		t.Fatalf("got %q, want %q", parts[0].data, want)
	}
}

func TestRenderPayloadRawAndSplits(t *testing.T) {
	parts := renderPayload("[raw][split]X[delay_split]Y", "h", 80)
	if len(parts) != 3 {
		t.Fatalf("want three parts, got %d: %+v", len(parts), parts)
	}
	if want := "CONNECT h:80 HTTP/1.1\r\nHost: h\r\n\r\n"; parts[0].data != want {
		t.Fatalf("[raw] = %q, want %q", parts[0].data, want)
	}
	if parts[1].data != "X" || parts[1].delay != 0 {
		t.Fatalf("second part = %+v, want X with no delay", parts[1])
	}
	if parts[2].data != "Y" || parts[2].delay != payloadSplitDelay {
		t.Fatalf("third part = %+v, want Y after %v", parts[2], payloadSplitDelay)
	}
}

func TestRenderPayloadKeepsUnknownTags(t *testing.T) {
	parts := renderPayload("GET /[net_data] HTTP/1.1[crlf]", "h", 1)
	if got := parts[0].data; got != "GET /[net_data] HTTP/1.1\r\n" {
		t.Fatalf("unknown tag was changed: %q", got)
	}
}

// payloadServer accepts connections, reports each injected request on the
// returned channel and relays the rest to target, so an SSH session can run
// on top of it.
func payloadServer(t *testing.T, target string, reply string) (addr string, requests <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	seen := make(chan string, 8) // buffered: the test reads it after connecting
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				select {
				case seen <- req.Method + " " + req.URL.String() + " host=" + req.Host:
				default:
				}
				if reply != "" {
					io.WriteString(conn, reply)
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				// Anything the client already pipelined goes upstream first.
				if n := br.Buffered(); n > 0 {
					b := make([]byte, n)
					io.ReadFull(br, b)
					up.Write(b)
				}
				go io.Copy(up, conn)
				io.Copy(conn, up)
			}()
		}
	}()
	return ln.Addr().String(), seen
}

func TestSSHThroughInjectedPayload(t *testing.T) {
	sshAddr, hostKey := startTestSSHServer(t)
	target := newTarget(t)

	proxy, requests := payloadServer(t, sshAddr, "")

	p := sshTestProfile(t, sshAddr)
	p.HostKey = hostKey
	p.PayloadProxy = proxy
	p.Payload = "GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]"

	s := profile.Settings{Core: profile.CoreSingBox, Mode: profile.ModeProxy, ListenPort: freePort(t)}
	e, err := startSSH(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if body := getThroughSOCKS(t, s.ListenPort, "", "", target.URL); !strings.Contains(body, "hello through tunnel") {
		t.Fatalf("unexpected body through the payload tunnel: %q", body)
	}
	if got := <-requests; !strings.Contains(got, "host=bug.example") {
		t.Fatalf("payload request was %q, want the bug host", got)
	}
}

func TestSSHThroughConnectProxy(t *testing.T) {
	sshAddr, hostKey := startTestSSHServer(t)
	target := newTarget(t)

	// A plain HTTP CONNECT proxy answers 200 before relaying.
	proxy, requests := payloadServer(t, sshAddr, "HTTP/1.1 200 Connection established\r\n\r\n")

	p := sshTestProfile(t, sshAddr)
	p.HostKey = hostKey
	p.PayloadProxy = proxy // no payload: a standard CONNECT

	s := profile.Settings{Core: profile.CoreSingBox, Mode: profile.ModeProxy, ListenPort: freePort(t)}
	e, err := startSSH(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if body := getThroughSOCKS(t, s.ListenPort, "", "", target.URL); !strings.Contains(body, "hello through tunnel") {
		t.Fatalf("unexpected body through the CONNECT proxy: %q", body)
	}
	if got := <-requests; !strings.HasPrefix(got, http.MethodConnect+" ") {
		t.Fatalf("proxy saw %q, want a CONNECT request", got)
	}
}

func TestPayloadProxyRejection(t *testing.T) {
	sshAddr, hostKey := startTestSSHServer(t)
	proxy, _ := payloadServer(t, sshAddr, "HTTP/1.1 403 Forbidden\r\n\r\n")

	p := sshTestProfile(t, sshAddr)
	p.HostKey, p.PayloadProxy = hostKey, proxy
	s := profile.Settings{Core: profile.CoreSingBox, Mode: profile.ModeProxy, ListenPort: freePort(t)}
	if _, err := startSSH(&p, &s); err == nil {
		t.Fatal("want an error when the proxy refuses the CONNECT")
	} else if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should mention the status: %v", err)
	}
}

func TestPayloadSplitDelayIsWaited(t *testing.T) {
	old := payloadSplitDelay
	payloadSplitDelay = 150 * time.Millisecond
	defer func() { payloadSplitDelay = old }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type part struct {
		at   time.Duration
		data string
	}
	done := make(chan []part, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		start := time.Now()
		var parts []part
		buf := make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for range 2 {
			n, err := conn.Read(buf)
			if n > 0 {
				parts = append(parts, part{time.Since(start), string(buf[:n])})
			}
			if err != nil {
				break
			}
		}
		done <- parts
	}()

	p := profile.Profile{Name: "x", Type: profile.TypeSSH, Server: "server.example", Port: 22, User: "u", Password: "p"}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p.PayloadProxy = net.JoinHostPort(host, portStr)
	p.Payload = "A[delay_split]B"
	conn, err := dialPayload(t.Context(), &p)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	parts := <-done
	if len(parts) != 2 || parts[0].data != "A" || parts[1].data != "B" {
		t.Fatalf("got %+v, want A then B in separate writes", parts)
	}
	if parts[1].at < payloadSplitDelay {
		t.Fatalf("second part arrived after %v, want at least %v", parts[1].at, payloadSplitDelay)
	}
}

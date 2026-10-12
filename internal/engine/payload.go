package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// An SSH payload is an HTTP request written on the raw socket before the SSH
// handshake, the way HTTP Injector and KPN Tunnel do it: filters that only let
// HTTP(S)-looking traffic through see a request to an allowed ("bug") host,
// while the bytes after it are the SSH session. The payload can be sent to the
// SSH server itself or to a separate proxy (profile.PayloadProxy).

// payloadSplitDelay is how long [delay_split] waits before sending the rest.
var payloadSplitDelay = time.Second

// errPayloadRejected means the proxy answered the payload with an error
// status; retrying the same payload won't help.
var errPayloadRejected = errors.New("payload rejected by the proxy")

// renderPayload turns a payload template into the parts to write, in order.
// A part boundary is a [split] (write separately) or [delay_split] (write
// after payloadSplitDelay); delay reports which boundary preceded each part.
type payloadPart struct {
	data  string
	delay time.Duration // wait this long before writing
}

// renderPayload expands the placeholders of a payload template for the given
// target. Supported, like the common Android tunnel apps:
//
//	[host] [port] [host_port]  the SSH server (or the CONNECT target)
//	[crlf] [cr] [lf]           line endings
//	[raw]                      CONNECT host:port HTTP/1.1 + Host header
//	[split] [delay_split]      send what came before separately
//
// Unknown [tags] are left as they are, so a payload that a server expects
// verbatim is not mangled.
func renderPayload(tmpl, host string, port int) []payloadPart {
	hostPort := net.JoinHostPort(host, strconv.Itoa(port))
	raw := "CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	// Longest tags first: [host_port] must not be eaten by [host].
	s := tmpl
	for _, r := range []struct{ from, to string }{
		{"[host_port]", hostPort},
		{"[raw]", raw},
		{"[host]", host},
		{"[port]", strconv.Itoa(port)},
		{"[crlf]", "\r\n"},
		{"[cr]", "\r"},
		{"[lf]", "\n"},
	} {
		s = replaceFold(s, r.from, r.to)
	}

	var parts []payloadPart
	next := time.Duration(0)
	for s != "" {
		cut, delay := len(s), time.Duration(0)
		if i := indexFold(s, "[split]"); i >= 0 {
			cut, delay = i, 0
		}
		if i := indexFold(s, "[delay_split]"); i >= 0 && i < cut {
			cut, delay = i, payloadSplitDelay
		}
		if cut == len(s) {
			parts = append(parts, payloadPart{data: s, delay: next})
			break
		}
		tag := "[split]"
		if delay > 0 {
			tag = "[delay_split]"
		}
		parts = append(parts, payloadPart{data: s[:cut], delay: next})
		s, next = s[cut+len(tag):], delay
	}
	// Drop empty parts, but keep their delay for the part that follows.
	var out []payloadPart
	carry := time.Duration(0)
	for _, p := range parts {
		if p.data == "" {
			carry += p.delay
			continue
		}
		out = append(out, payloadPart{data: p.data, delay: p.delay + carry})
		carry = 0
	}
	return out
}

func indexFold(s, substr string) int {
	return strings.Index(strings.ToLower(s), substr)
}

func replaceFold(s, from, to string) string {
	for {
		i := indexFold(s, from)
		if i < 0 {
			return s
		}
		s = s[:i] + to + s[i+len(from):]
	}
}

// dialPayload opens the TCP connection the SSH handshake runs on: straight to
// the server, or through the payload proxy, after sending the payload (or a
// plain CONNECT when only a proxy is set).
func dialPayload(ctx context.Context, p *profile.Profile) (net.Conn, error) {
	d := net.Dialer{Timeout: sshDialTimeout}
	target := p.Address()
	addr := target
	if p.PayloadProxy != "" {
		addr = p.PayloadProxy
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if p.Payload == "" && p.PayloadProxy == "" {
		return conn, nil
	}
	rest, err := sendPayload(ctx, conn, p, target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("payload to %s: %w", addr, err)
	}
	if len(rest) > 0 {
		return &prefixConn{Conn: conn, rest: rest}, nil
	}
	return conn, nil
}

// sendPayload writes the payload (or a plain CONNECT) and, when the request
// expects an HTTP answer, waits for a 2xx status.
// It returns any bytes read past the response (the SSH banner can arrive in
// the same packet), which the caller must put back in front of the stream.
func sendPayload(ctx context.Context, conn net.Conn, p *profile.Profile, target string) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(sshDialTimeout))
	}
	defer conn.SetDeadline(time.Time{})

	var parts []payloadPart
	switch {
	case p.Payload != "":
		parts = renderPayload(p.Payload, p.Server, p.Port)
	default: // only a proxy: a standard HTTP CONNECT
		parts = []payloadPart{{data: "CONNECT " + target + " HTTP/1.1\r\nHost: " + p.Server + "\r\n\r\n"}}
	}
	for _, part := range parts {
		if part.delay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(part.delay):
			}
		}
		if _, err := conn.Write([]byte(part.data)); err != nil {
			return nil, err
		}
	}
	if len(parts) == 0 || !expectsResponse(parts[0].data) {
		return nil, nil // an injected payload the server answers with the SSH banner
	}
	return readPayloadResponse(conn)
}

// expectsResponse reports whether a request's first line asks the other side
// for an HTTP response: a CONNECT (proxy) request does, an injected GET/POST
// aimed at a filter usually does not.
func expectsResponse(first string) bool {
	line, _, _ := strings.Cut(first, "\r\n")
	line, _, _ = strings.Cut(line, "\n")
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "CONNECT ")
}

// readPayloadResponse reads one HTTP response, accepts 2xx and returns
// whatever was buffered past it.
func readPayloadResponse(conn net.Conn) ([]byte, error) {
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: %s", errPayloadRejected, resp.Status)
	}
	log.Printf("🧩 payload accepted: %s", resp.Status)
	if n := br.Buffered(); n > 0 {
		rest := make([]byte, n)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, err
		}
		return rest, nil
	}
	return nil, nil
}

// prefixConn puts bytes already read back in front of a connection.
type prefixConn struct {
	net.Conn
	rest []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.rest) > 0 {
		n := copy(b, c.rest)
		c.rest = c.rest[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

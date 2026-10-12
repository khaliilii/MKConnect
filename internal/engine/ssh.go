package engine

import (
	stdbufio "bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"golang.org/x/crypto/ssh"

	"github.com/khaliilii/MKConnect/internal/profile"
)

const (
	sshDialTimeout = 10 * time.Second
	sshKeepAlive   = 15 * time.Second
)

var (
	errHostKeyCaptured = errors.New("host key captured")
	errHostKeyMismatch = errors.New("ssh host key does not match the pinned key (possible MITM; if the server was reinstalled, clear it with `profile edit --host-key \"\"`)")
)

// FetchHostKey connects to an SSH server just far enough to read its host key,
// returned in authorized_keys format. It goes through the profile's payload
// and proxy, if it has any.
func FetchHostKey(ctx context.Context, p profile.Profile) (string, error) {
	var key string
	cfg := &ssh.ClientConfig{
		User: "mkconnect-probe",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
			return errHostKeyCaptured
		},
		Timeout: sshDialTimeout,
	}
	conn, err := dialPayload(ctx, &p)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_, _, _, err = ssh.NewClientConn(conn, p.Address(), cfg)
	if key == "" {
		return "", err
	}
	return key, nil
}

// Fingerprint returns the OpenSSH-style SHA256 fingerprint of an authorized_keys line.
func Fingerprint(authorizedKey string) string {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "invalid key"
	}
	sum := sha256.Sum256(k.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// sshEngine is a SOCKS5 proxy that forwards connections through an SSH client
// and reconnects when the SSH session drops.
type sshEngine struct {
	addr    string
	config  *ssh.ClientConfig
	profile profile.Profile // for the payload / proxy of each new connection

	mu          sync.Mutex
	client      *ssh.Client
	reconnectMu sync.Mutex // serializes reconnects so a drop triggers only one

	listener net.Listener
	up, down atomic.Int64
	done     chan error
	closed   chan struct{}
	once     sync.Once
}

func startSSH(p *profile.Profile, s *profile.Settings) (Engine, error) {
	cfg, err := sshClientConfig(p)
	if err != nil {
		return nil, err
	}
	e := &sshEngine{
		addr:    p.Address(),
		config:  cfg,
		profile: *p,
		done:    make(chan error, 1),
		closed:  make(chan struct{}),
	}
	if _, err := e.connect(); err != nil {
		return nil, err
	}

	var authenticator *auth.Authenticator
	if s.ProxyUser != "" {
		authenticator = auth.NewAuthenticator([]auth.User{{Username: s.ProxyUser, Password: s.ProxyPass}})
	}
	handler := &sshSocksHandler{e: e, udpgwPort: p.UDPGWPort, dns: p.UDPGWDNS}
	e.listener, err = net.Listen("tcp", net.JoinHostPort(s.ListenAddress(), fmt.Sprint(s.ListenPort)))
	if err != nil {
		e.Close()
		return nil, err
	}
	go func() {
		for {
			conn, err := e.listener.Accept()
			if err != nil {
				select {
				case <-e.closed:
				default:
					e.done <- fmt.Errorf("socks5 server: %w", err)
				}
				return
			}
			go func() {
				defer conn.Close()
				err := socks.HandleConnectionEx(context.Background(), conn, stdbufio.NewReader(conn), authenticator,
					handler, udpListener{}, 5*time.Minute, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					log.Printf("socks5: %v", err)
				}
			}()
		}
	}()
	go e.keepAlive()
	if p.UDPGWPort > 0 {
		log.Printf("ℹ️  Built-in SSH core serves SOCKS5 (no HTTP proxy); UDP through udpgw on the server's port %d", p.UDPGWPort)
	} else {
		log.Printf("ℹ️  Built-in SSH core serves SOCKS5 only (no HTTP proxy, no UDP; set a udpgw port for UDP)")
	}
	return e, nil
}

// sshSocksHandler serves the SOCKS5 requests: TCP through the SSH tunnel,
// UDP through badvpn-udpgw on the server (when a port is set).
type sshSocksHandler struct {
	e         *sshEngine
	udpgwPort int
	dns       bool
}

func (h *sshSocksHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	// The destination is passed as given (name or IP): the SSH server resolves names.
	remote, err := h.e.dial("tcp", destination.String())
	if err != nil {
		log.Printf("socks5: %s: %v", destination, err)
		conn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	// The SOCKS reply is sent lazily, on the first read or write; sending it
	// now, as sing-box does, keeps the two copy directions from racing on it.
	if lazy, ok := conn.(N.ConnHandshakeSuccess); ok {
		if err := lazy.ConnHandshakeSuccess(remote); err != nil {
			remote.Close()
			N.CloseOnHandshakeFailure(conn, onClose, err)
			return
		}
	}
	err = bufio.CopyConn(ctx, conn, remote)
	remote.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (h *sshSocksHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.udpgwPort == 0 {
		err := errors.New("UDP needs a udpgw port on the SSH account")
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	tunnel, err := h.e.dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.udpgwPort))
	if err != nil {
		log.Printf("udpgw: %v", err)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	err = relayUDPGW(tunnel, conn, h.dns)
	if err != nil {
		log.Printf("udpgw: %v", err)
	}
	if onClose != nil {
		onClose(err)
	}
}

// udpListener opens the local socket of a SOCKS UDP association.
type udpListener struct{}

func (udpListener) ListenPacket(lc net.ListenConfig, ctx context.Context, network, address string) (net.PacketConn, error) {
	return lc.ListenPacket(ctx, network, address)
}

func sshClientConfig(p *profile.Profile) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if p.PrivateKeyPath != "" {
		pem, err := os.ReadFile(p.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if p.Password != "" {
		auth = append(auth, ssh.Password(p.Password))
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.HostKey))
	if err != nil {
		return nil, fmt.Errorf("invalid pinned host key: %w", err)
	}
	pinned := ssh.FixedHostKey(hostKey)
	return &ssh.ClientConfig{
		User: p.User,
		Auth: auth,
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			if pinned(host, remote, key) != nil {
				return errHostKeyMismatch
			}
			return nil
		},
		Timeout: sshDialTimeout,
	}, nil
}

// connect dials a new SSH client, retrying a few times, and makes it current.
func (e *sshEngine) connect() (*ssh.Client, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		c, err := e.dialClient()
		if err == nil {
			e.mu.Lock()
			old := e.client
			e.client = c
			e.mu.Unlock()
			if old != nil {
				old.Close()
			}
			log.Printf("✅ SSH connected to %s", e.addr)
			return c, nil
		}
		lastErr = err
		if isPermanentSSHError(err) || attempt == 3 {
			break
		}
		log.Printf("⚠️  SSH attempt %d to %s failed: %v", attempt, e.addr, err)
		select {
		case <-e.closed:
			return nil, net.ErrClosed
		case <-time.After(time.Duration(attempt) * 2 * time.Second):
		}
	}
	return nil, fmt.Errorf("ssh connect %s: %w", e.addr, lastErr)
}

// dialClient opens a TCP connection (through the payload, if the profile has
// one) and runs the SSH handshake on it.
func (e *sshEngine) dialClient() (*ssh.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshDialTimeout)
	defer cancel()
	conn, err := dialPayload(ctx, &e.profile)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, e.addr, e.config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// isPermanentSSHError reports errors that retrying won't fix.
func isPermanentSSHError(err error) bool {
	return errors.Is(err, errHostKeyMismatch) || errors.Is(err, errPayloadRejected) ||
		strings.Contains(err.Error(), "unable to authenticate")
}

func (e *sshEngine) current() *ssh.Client {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client
}

func (e *sshEngine) Traffic() (up, down int64) { return e.up.Load(), e.down.Load() }

func (e *sshEngine) dial(network, addr string) (net.Conn, error) {
	conn, err := e.dialSSH(network, addr)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, up: &e.up, down: &e.down}, nil
}

func (e *sshEngine) dialSSH(network, addr string) (net.Conn, error) {
	c := e.current()
	conn, err := c.Dial(network, addr)
	if err == nil {
		return conn, nil
	}
	// A rejected channel means the target is unreachable; anything else means the session is gone.
	var open *ssh.OpenChannelError
	if errors.As(err, &open) {
		return nil, err
	}
	if c, err = e.reconnect(c); err != nil {
		return nil, err
	}
	return c.Dial(network, addr)
}

// reconnect replaces broken unless another goroutine already did.
func (e *sshEngine) reconnect(broken *ssh.Client) (*ssh.Client, error) {
	e.reconnectMu.Lock()
	defer e.reconnectMu.Unlock()
	if c := e.current(); c != broken {
		return c, nil
	}
	log.Printf("🔄 SSH session lost, reconnecting...")
	return e.connect()
}

func (e *sshEngine) keepAlive() {
	t := time.NewTicker(sshKeepAlive)
	defer t.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-t.C:
		}
		c := e.current()
		if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			if _, err := e.reconnect(c); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("❌ %v", err)
			}
		}
	}
}

func (e *sshEngine) Done() <-chan error { return e.done }

func (e *sshEngine) Close() error {
	e.once.Do(func() {
		close(e.closed)
		if e.listener != nil {
			e.listener.Close()
		}
		if c := e.current(); c != nil {
			c.Close()
		}
	})
	return nil
}

// countingConn counts bytes written to (up) and read from (down) the tunnel.
type countingConn struct {
	net.Conn
	up, down *atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.down.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.up.Add(int64(n))
	return n, err
}

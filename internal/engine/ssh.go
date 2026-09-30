package engine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-socks5"
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
// returned in authorized_keys format.
func FetchHostKey(ctx context.Context, addr string) (string, error) {
	var key string
	cfg := &ssh.ClientConfig{
		User: "mkconnect-probe",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
			return errHostKeyCaptured
		},
		Timeout: sshDialTimeout,
	}
	d := net.Dialer{Timeout: sshDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
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
	addr   string
	config *ssh.ClientConfig

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
		addr:   p.Address(),
		config: cfg,
		done:   make(chan error, 1),
		closed: make(chan struct{}),
	}
	if _, err := e.connect(); err != nil {
		return nil, err
	}

	socksConf := &socks5.Config{
		Dial:     func(ctx context.Context, network, addr string) (net.Conn, error) { return e.dial(network, addr) },
		Resolver: remoteResolver{}, // let the SSH server resolve names
		Logger:   log.New(os.Stderr, "socks5: ", log.LstdFlags),
	}
	if s.ProxyUser != "" {
		socksConf.Credentials = socks5.StaticCredentials{s.ProxyUser: s.ProxyPass}
	}
	server, err := socks5.New(socksConf)
	if err != nil {
		e.Close()
		return nil, err
	}
	e.listener, err = net.Listen("tcp", net.JoinHostPort(s.ListenAddress(), fmt.Sprint(s.ListenPort)))
	if err != nil {
		e.Close()
		return nil, err
	}
	go func() {
		if err := server.Serve(e.listener); err != nil {
			select {
			case <-e.closed:
			default:
				e.done <- fmt.Errorf("socks5 server: %w", err)
			}
		}
	}()
	go e.keepAlive()
	log.Printf("ℹ️  Built-in SSH core serves SOCKS5 only (no HTTP proxy, no UDP)")
	return e, nil
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
		c, err := ssh.Dial("tcp", e.addr, e.config)
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

// isPermanentSSHError reports errors that retrying won't fix.
func isPermanentSSHError(err error) bool {
	return errors.Is(err, errHostKeyMismatch) || strings.Contains(err.Error(), "unable to authenticate")
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

// remoteResolver skips local DNS so hostnames are resolved by the SSH server.
type remoteResolver struct{}

func (remoteResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

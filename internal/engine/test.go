package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestOptions controls a server test.
type TestOptions struct {
	Probes    int           // latency probes (default 3)
	Timeout   time.Duration // per probe (default 6s)
	Speed     bool          // also measure download speed
	SpeedTime time.Duration // speed test duration cap (default 6s)
}

// Test endpoints, overridable in tests. The latency probe is HTTPS, so a
// server that only passes plain HTTP doesn't look usable.
//
// FallbackURLs are tried together with LatencyURL: some servers block single
// destinations (a provider refusing gstatic.com or speed tests to save
// bandwidth) while the rest of the internet works through them, and one
// blocked probe target must not make a working server look dead.
var (
	LatencyURL   = "https://www.gstatic.com/generate_204"
	FallbackURLs = []string{
		"https://cp.cloudflare.com/generate_204",
		"https://www.apple.com/library/test/success.html",
		"https://detectportal.firefox.com/success.txt", // HTTPS (Microsoft's check is HTTP only)
	}
	SpeedURL = "https://speed.cloudflare.com/__down?bytes=25000000"
	// SpeedFallbackURLs are downloaded when SpeedURL doesn't answer 200:
	// Cloudflare's speed test answers "429 Too Many Requests" to a server's
	// exit after a few tests, which made fast accounts measure 0 and sink to
	// the bottom of a speed-sorted list.
	SpeedFallbackURLs = []string{
		"https://cachefly.cachefly.net/10mb.test",
		"https://proof.ovh.net/files/10Mb.dat",
	}
)

// openSpeedStream starts a download for a speed measurement: SpeedURL, or
// the first fallback that answers 200.
func openSpeedStream(ctx context.Context, c *http.Client) (*http.Response, error) {
	var lastErr error
	for _, u := range append([]string{SpeedURL}, SpeedFallbackURLs...) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		resp.Body.Close()
		lastErr = fmt.Errorf("HTTP %s", resp.Status)
	}
	return nil, lastErr
}

// probeHedge is how long the main target gets before the fallbacks are
// tried too (a blocked target often hangs instead of failing).
var probeHedge = 3 * time.Second

// probeAny probes LatencyURL and, when that fails or is slow to answer, the
// fallbacks as well, returning the first answer. In the usual case it sends
// one request, so measured latencies stay comparable. It fails only when
// every target fails, with the main target's error.
func probeAny(ctx context.Context, c *http.Client) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		main bool
		d    time.Duration
		err  error
	}
	results := make(chan result, 1+len(FallbackURLs))
	go func() {
		d, err := probe(ctx, c, LatencyURL)
		results <- result{true, d, err}
	}()

	pending := 1
	var mainErr error
	select {
	case r := <-results:
		if r.err == nil {
			return r.d, nil
		}
		mainErr, pending = r.err, 0
	case <-time.After(probeHedge):
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	for _, u := range FallbackURLs {
		pending++
		go func() {
			d, err := probe(ctx, c, u)
			results <- result{false, d, err}
		}()
	}
	var firstErr error
	for ; pending > 0; pending-- {
		r := <-results
		switch {
		case r.err == nil:
			return r.d, nil
		case r.main:
			mainErr = r.err
		case firstErr == nil:
			firstErr = r.err
		}
	}
	if mainErr == nil {
		mainErr = firstErr
	}
	return 0, mainErr
}

// Test starts the profile on a private local port, measures it through the
// proxy and stops it again. It doesn't touch the system and can run while
// another connection (proxy mode) is active.
func Test(ctx context.Context, p profile.Profile, s profile.Settings, o TestOptions) *profile.TestResult {
	o.Probes = orDefaultInt(o.Probes, 3)
	o.Timeout = orDefaultDur(o.Timeout, 6*time.Second)
	o.SpeedTime = orDefaultDur(o.SpeedTime, 6*time.Second)
	r := &profile.TestResult{At: time.Now(), Sent: o.Probes}
	fail := func(err error) *profile.TestResult {
		r.Received, r.Error = 0, shortError(err)
		return r
	}

	if p.IsInfo() {
		r.Received, r.Error = 0, "not a server: a message from the subscription"
		return r
	}
	port, _, stop, err := startPrivate(ctx, &p, &s)
	if err != nil {
		return fail(err)
	}
	defer stop()

	client := proxyClient(port, o.Timeout)
	defer client.CloseIdleConnections()
	var samples []int
	var lastErr error
	for range o.Probes {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		d, err := probeAny(ctx, client)
		if err != nil {
			lastErr = err
			continue
		}
		samples = append(samples, int(d.Milliseconds()))
	}
	r.Received = len(samples)
	if r.Received == 0 {
		return fail(lastErr)
	}
	sum := 0
	for _, v := range samples {
		sum += v
	}
	r.Latency = sum / len(samples)
	r.Jitter = slices.Max(samples) - slices.Min(samples)

	if o.Speed {
		r.Speed, err = download(ctx, port, o.SpeedTime)
		if err != nil && r.Speed == 0 {
			r.Error = "speed: " + shortError(err)
		}
	}
	return r
}

// PreferredCore is the core that runs a profile best: the configured one,
// unless it can't run this profile or another core speaks its protocol
// natively.
//
//   - Hysteria2 and TUIC need sing-box; xhttp needs Xray.
//   - VMess/VLESS/Trojan/Shadowsocks over TCP with the HTTP header: sing-box
//     only emulates it with its HTTP transport, and some Xray servers answer
//     that with "400 Bad Request" (a full test found one refusing 7 of 8
//     requests that Xray carried), so Xray runs them when it is available.
//   - With Mux on, the accounts it applies to (MuxApplies): only Xray speaks
//     the Mux.Cool the servers understand.
//   - Accounts that trust their server's certificate by hash ("pcs") or by
//     other names ("vcn"): Xray checks those, sing-box can't, and without
//     them the CDN's own certificate fails the check.
//   - The same over WebSocket and HTTP upgrade, which reach the server
//     through an HTTP front end (often a CDN): when one of the front end's
//     backends fails, half the handshakes get "503". Xray dials each
//     connection up to 5 times; sing-box tries once, and with half of a
//     page's connections failing, no page loads although traffic flows
//     (measured from Iran: 3-5 of 10 requests on sing-box, 8-10 on Xray).
//
// Xray's proxy port serves HTTP as well as SOCKS5, so nothing changes for the
// apps that use it.
func PreferredCore(p *profile.Profile, s *profile.Settings) string {
	core := s.Core
	if core == profile.CoreExternal || p.Type == profile.TypeSSH {
		return core
	}
	quic := p.Type == profile.TypeHysteria2 || p.Type == profile.TypeTUIC
	if core == profile.CoreXray && (quic || startXray == nil) && startSingBox != nil {
		return profile.CoreSingBox
	}
	httpHeader := p.Transport.HeaderType == "http" && (p.Transport.Network == "" || p.Transport.Network == "tcp")
	// Not gRPC: Xray's gRPC client doesn't work with sing-box's own gRPC
	// servers, and gRPC showed no such failures.
	httpFront := slices.Contains([]string{"ws", "httpupgrade", "xhttp"}, p.Transport.Network)
	// sing-box can pin a public key but not a certificate hash.
	pinned := p.TLS.PinnedCertSHA256 != "" || p.TLS.VerifyByName != ""
	// sing-box's multiplexing doesn't speak Xray's Mux.Cool, which the
	// servers do.
	mux := s.Mux && MuxApplies(p)
	if core == profile.CoreSingBox && (httpFront || httpHeader || pinned || mux || startSingBox == nil) && startXray != nil {
		return profile.CoreXray
	}
	return core
}

// startForTest is start() for proxy mode with core logging turned down:
// a test of many servers would otherwise flood the log.
func startForTest(p *profile.Profile, s *profile.Settings) (Engine, error) {
	if p.Type == profile.TypeSSH {
		return startSSH(p, s)
	}
	if s.Core == profile.CoreSingBox || (s.Core == profile.CoreExternal && s.ExternalKind == profile.CoreSingBox) {
		cfg, err := singBoxConfig(p, s, nil)
		if err != nil {
			return nil, err
		}
		cfg["log"] = obj{"disabled": true}
		return launchSingBox(s, cfg)
	}
	cfg, err := xrayConfig(p, s)
	if err != nil {
		return nil, err
	}
	// Not "none": Xray's log level is process-wide and would also silence a
	// connection that is running at the same time.
	// No access log either: it goes to stdout, into the CLI's tables and JSON.
	cfg["log"] = obj{"loglevel": "error", "access": "none"}
	if s.Core == profile.CoreExternal {
		return startExternal(s.ExternalPath, cfg)
	}
	if startXray == nil {
		return nil, fmt.Errorf("the xray core is not compiled into this binary")
	}
	data, err := marshal(cfg)
	if err != nil {
		return nil, err
	}
	return startXray(data)
}

func proxyClient(port int, timeout time.Duration) *http.Client {
	proxy := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
			// Every probe opens a new connection through the server, so the
			// latency includes the handshake, as a real connection would.
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func probe(ctx context.Context, c *http.Client, target string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %s", resp.Status)
	}
	return time.Since(start), nil
}

// download measures throughput: bytes per second from the first byte of the
// body until the download ends or the time is up.
func download(ctx context.Context, port int, limit time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, limit+5*time.Second) // + time to the first byte
	defer cancel()
	c := proxyClient(port, 0)
	defer c.CloseIdleConnections()
	resp, err := openSpeedStream(ctx, c)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	start := time.Now()
	deadline := start.Add(limit)
	buf := make([]byte, 64<<10)
	var n int64
	for time.Now().Before(deadline) {
		m, err := resp.Body.Read(buf)
		n += int64(m)
		if err != nil {
			if !errors.Is(err, io.EOF) && n == 0 {
				return 0, err
			}
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 || n == 0 {
		return 0, errors.New("no data")
	}
	return int64(float64(n) / elapsed), nil
}

func freeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// waitPort waits for an external core to open its proxy port.
func waitPort(ctx context.Context, port int, limit time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(limit)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("core did not open its proxy port: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// shortError keeps the meaningful tail of long wrapped errors.
func shortError(err error) string {
	if err == nil {
		return "no response"
	}
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(msg, "Client.Timeout"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg) > 120 {
		msg = msg[i+2:]
	}
	return msg
}

func orDefaultInt(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func orDefaultDur(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

// TestMany tests profiles[i] for every i in idx, parallel at a time, and
// calls done (serialized) as each result arrives. Latency is measured for all
// accounts first; speed tests then run one by one for the ones that work, so
// they don't share the bandwidth, and done is called again with the speed.
func TestMany(ctx context.Context, profiles []profile.Profile, idx []int, s profile.Settings, o TestOptions,
	parallel int, done func(i int, r *profile.TestResult)) map[int]*profile.TestResult {
	parallel = orDefaultInt(parallel, 8)
	results := make(map[int]*profile.TestResult, len(idx))
	var mu sync.Mutex
	report := func(i int, r *profile.TestResult) {
		mu.Lock()
		defer mu.Unlock()
		results[i] = r
		if done != nil {
			done(i, r)
		}
	}

	speed := o.Speed
	o.Speed = false
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, i := range idx {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, p profile.Profile) {
			defer func() { <-sem; wg.Done() }()
			report(i, Test(ctx, p, s, o)) // with speed, reported again after the second pass
		}(i, profiles[i])
	}
	wg.Wait()

	if speed {
		o.Speed, o.Probes = true, 1
		for _, i := range idx {
			if !results[i].OK() || ctx.Err() != nil {
				continue
			}
			r := *results[i] // a copy: the first result may still be in use by the caller
			if sr := Test(ctx, profiles[i], s, o); sr.OK() && sr.Speed > 0 {
				r.Speed = sr.Speed
			} else if sr.Error != "" {
				r.Error = "speed: " + strings.TrimPrefix(sr.Error, "speed: ")
			}
			report(i, &r)
		}
	}
	return results
}

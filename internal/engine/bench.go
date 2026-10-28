package engine

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// A benchmark measures what using an account feels like, which a single
// latency probe doesn't: an account can answer a probe quickly and still
// leave pages hanging, because a page opens dozens of new connections at
// once and every one of them pays the setup through the tunnel (and, on some
// networks, stalls). So it measures new connections one by one, a page-like
// burst of them, and download speed with one and with several streams.

// BenchTargets are small resources on different CDNs, each fetched over a
// new connection; overridable in tests.
var BenchTargets = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
	"https://www.apple.com/library/test/success.html",
	"https://detectportal.firefox.com/success.txt",
	"https://www.google.com/favicon.ico",
	"https://github.com/favicon.ico",
	"https://en.wikipedia.org/static/favicon/wikipedia.ico",
	"https://www.youtube.com/favicon.ico",
	"https://www.cloudflare.com/favicon.ico",
	"https://www.bing.com/favicon.ico",
	"https://www.mozilla.org/favicon.ico",
	"https://www.amazon.com/favicon.ico",
}

// BenchOptions controls a benchmark; zero values pick the defaults.
type BenchOptions struct {
	Connections int           // new connections measured one by one (default 12)
	Timeout     time.Duration // per request (default 10 s)
	SpeedTime   time.Duration // each download measurement (default 5 s)
	Streams     int           // parallel download streams (default 4)
}

// BenchResult is one account's benchmark. Durations are zero when nothing
// succeeded; Error says why the account couldn't be measured at all.
type BenchResult struct {
	Name, Core string

	ConnectMedian, ConnectP90 time.Duration // time to the first answer of a new connection
	ConnectFailed, Connects   int

	Page                   time.Duration // a page-like burst of new connections, all done
	PageFailed, PageParts  int
	Download, DownloadMany int64 // bytes/s with one stream and with Streams streams

	Error string
}

// Score sums up a result for ranking (higher is better): a page that loads
// fast and completely, new connections that answer quickly, then speed.
// Failures weigh heavily, since a failed request is what a user notices.
func (r *BenchResult) Score() float64 {
	if r == nil || r.Error != "" || r.Connects == 0 {
		return 0
	}
	ok := float64(r.Connects-r.ConnectFailed) / float64(r.Connects)
	if r.PageParts > 0 {
		ok *= float64(r.PageParts-r.PageFailed) / float64(r.PageParts)
	}
	if ok == 0 {
		return 0
	}
	page := r.Page.Seconds()
	if page <= 0 {
		page = 20
	}
	connect := max(r.ConnectMedian.Seconds(), 0.05)
	speed := float64(max(r.Download, r.DownloadMany)) / (1 << 20) // MB/s
	return ok * ok * (100/(1+page) + 20/(1+connect) + 10*min(speed, 10))
}

// String is a one-line summary for logs and the CLI.
func (r *BenchResult) String() string {
	if r.Error != "" {
		return "failed: " + r.Error
	}
	return fmt.Sprintf("connect %s (p90 %s, %d/%d failed) · page %s (%d/%d failed) · %s/s, %s/s with streams · score %.0f",
		ms(r.ConnectMedian), ms(r.ConnectP90), r.ConnectFailed, r.Connects,
		ms(r.Page), r.PageFailed, r.PageParts,
		profile.FormatBytes(r.Download), profile.FormatBytes(r.DownloadMany), r.Score())
}

func ms(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return fmt.Sprintf("%d ms", d.Milliseconds())
}

// Benchmark starts the account on a private local port, measures it and
// stops it. Like Test, it doesn't touch the system or a running connection.
func Benchmark(ctx context.Context, p profile.Profile, s profile.Settings, o BenchOptions) *BenchResult {
	o.Connections = orDefaultInt(o.Connections, 12)
	o.Timeout = orDefaultDur(o.Timeout, 10*time.Second)
	o.SpeedTime = orDefaultDur(o.SpeedTime, 5*time.Second)
	o.Streams = orDefaultInt(o.Streams, 4)
	r := &BenchResult{Name: p.Name}

	port, core, stop, err := startPrivate(ctx, &p, &s)
	if err != nil {
		r.Error = shortError(err)
		return r
	}
	defer stop()
	r.Core = core

	client := proxyClient(port, o.Timeout)
	defer client.CloseIdleConnections()

	// New connections, one at a time.
	var times []time.Duration
	for i := range o.Connections {
		if ctx.Err() != nil {
			r.Error = "cancelled"
			return r
		}
		r.Connects++
		d, err := probe(ctx, client, BenchTargets[i%len(BenchTargets)])
		if err != nil {
			r.ConnectFailed++
			continue
		}
		times = append(times, d)
	}
	if len(times) > 0 {
		slices.Sort(times)
		r.ConnectMedian = times[len(times)/2]
		r.ConnectP90 = times[min(len(times)-1, len(times)*9/10)]
	}

	// A page: every target at once, each over a new connection.
	var (
		wg     sync.WaitGroup
		failed atomic.Int32
		start  = time.Now()
	)
	for _, u := range BenchTargets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := probe(ctx, client, u); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	r.PageParts, r.PageFailed = len(BenchTargets), int(failed.Load())
	if r.PageFailed < r.PageParts {
		r.Page = time.Since(start)
	}

	if r.ConnectFailed == r.Connects && r.PageFailed == r.PageParts {
		r.Error = "no request got through"
		return r
	}
	r.Download, _ = download(ctx, port, o.SpeedTime)
	r.DownloadMany = downloadStreams(ctx, port, o.SpeedTime, o.Streams)
	return r
}

// downloadStreams measures throughput with n downloads at once, in bytes/s,
// from the first byte any of them receives until limit later.
func downloadStreams(ctx context.Context, port int, limit time.Duration, n int) int64 {
	ctx, cancel := context.WithTimeout(ctx, limit+5*time.Second) // + time to the first byte
	defer cancel()
	var (
		wg        sync.WaitGroup
		total     atomic.Int64
		firstByte atomic.Int64 // unix nanoseconds
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := proxyClient(port, 0)
			defer c.CloseIdleConnections()
			resp, err := openSpeedStream(ctx, c)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			buf := make([]byte, 64<<10)
			for {
				m, err := resp.Body.Read(buf)
				if m > 0 {
					now := time.Now().UnixNano()
					firstByte.CompareAndSwap(0, now)
					if time.Duration(now-firstByte.Load()) > limit {
						return
					}
					total.Add(int64(m))
				}
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	fb := firstByte.Load()
	if fb == 0 {
		return 0
	}
	secs := min(time.Since(time.Unix(0, fb)), limit).Seconds()
	if secs <= 0 {
		return 0
	}
	return int64(float64(total.Load()) / secs)
}

// startPrivate starts an account on a free local port the way Test does:
// proxy mode only, no LAN, no proxy password, on the core that runs it best.
// It returns the port, the core and a function that stops it.
func startPrivate(ctx context.Context, p *profile.Profile, s *profile.Settings) (int, string, func(), error) {
	if p.IsInfo() {
		return 0, "", nil, profile.ErrInfoEntry
	}
	if err := p.Validate(); err != nil {
		return 0, "", nil, err
	}
	port, err := freeLocalPort()
	if err != nil {
		return 0, "", nil, err
	}
	s.Mode, s.ListenPort, s.AllowLAN, s.ShareInterfaces = profile.ModeProxy, port, false, nil
	s.ProxyUser, s.ProxyPass = "", ""
	s.Core = PreferredCore(p, s)
	if p.Type == profile.TypeSSH && p.HostKey == "" {
		key, err := FetchHostKey(ctx, *p)
		if err != nil {
			return 0, "", nil, err
		}
		p.HostKey = key
	}
	e, err := startForTest(p, s)
	if err != nil {
		return 0, "", nil, err
	}
	if err := waitPort(ctx, port, 5*time.Second); err != nil {
		e.Close()
		return 0, "", nil, err
	}
	return port, s.Core, func() { e.Close() }, nil
}

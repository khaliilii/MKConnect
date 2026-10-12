package engine

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// Health checks exist because a core can start, report a running connection
// and still carry no traffic: the server may be unreachable, blocked after the
// handshake, or out of quota. Reporting that is the difference between
// "Connected" and "Connected but nothing gets through".
var (
	// healthInterval is how often a running connection is re-checked.
	healthInterval = 45 * time.Second
	// healthTimeout is the time one check gets.
	healthTimeout = 12 * time.Second
)

// CheckHealth reports whether traffic reaches the internet through a running
// connection: through the local proxy, which both proxy and TUN mode serve.
func CheckHealth(ctx context.Context, s profile.Settings) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	c := healthClient(&s)
	defer c.CloseIdleConnections()
	return probe(ctx, c, LatencyURL)
}

// healthClient sends requests through the connection's own local proxy, with
// the proxy password when one is set.
func healthClient(s *profile.Settings) *http.Client {
	proxy := &url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", s.ListenPort)}
	if s.ProxyUser != "" {
		proxy.User = url.UserPassword(s.ProxyUser, s.ProxyPass)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxy),
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// monitorHealth checks the connection right after it starts and then every
// healthInterval, reporting every result to report (which may be nil) and
// logging the changes.
func monitorHealth(ctx context.Context, s profile.Settings, report func(time.Duration, error)) {
	var (
		last    error
		checked bool
	)
	for {
		d, err := CheckHealth(ctx, s)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil && (!checked || last == nil):
			log.Printf("⚠️  no internet through the tunnel: %v", shortError(err))
		case err == nil && (!checked || last != nil):
			log.Printf("✅ internet works through the tunnel (%d ms)", d.Milliseconds())
		}
		last, checked = err, true
		if report != nil {
			report(d, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(healthInterval):
		}
	}
}

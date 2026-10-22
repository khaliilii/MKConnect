package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
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
// A failure is reported as what it means for the user (a probeFailure),
// with the core's own error kept for the log.
func CheckHealth(ctx context.Context, s profile.Settings) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	c := healthClient(&s)
	defer c.CloseIdleConnections()
	d, err := probeAny(ctx, c)
	if err != nil && ctx.Err() != context.Canceled {
		return 0, explainFailure(err)
	}
	return d, err
}

// probeFailure is a failed check through the tunnel: Meaning is for the user,
// Detail is the core's error for the log.
type probeFailure struct {
	Meaning string
	Detail  string
}

func (f *probeFailure) Error() string { return f.Meaning }

// explainFailure says what a failed probe means. The cores report the same
// few situations in many words: "EOF" right after connecting (the server or a
// filter on the way closed the connection), "general SOCKS server failure"
// (the core couldn't open the connection at all), timeouts and refusals.
func explainFailure(err error) error {
	detail := shortError(err)
	msg := strings.ToLower(err.Error())
	var meaning string
	switch {
	case detail == "timeout":
		meaning = "the server doesn't answer: it is down or blocked on this network"
	case strings.Contains(msg, "eof"), strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "general socks server failure"), strings.Contains(msg, "broken pipe"):
		meaning = "the server closes every connection: it is blocked on this network, " +
			"or the account has expired or run out of data"
	case strings.Contains(msg, "connection refused"):
		meaning = "nothing answers on the server's port: the address or port is wrong, or the server is off"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "lookup "):
		meaning = "the server's name can't be resolved"
	case strings.Contains(msg, "certificate"), strings.Contains(msg, "x509"), strings.Contains(msg, "tls:"):
		meaning = "the TLS handshake failed: check the SNI / security settings of the account"
	default:
		meaning = detail
	}
	return &probeFailure{Meaning: meaning, Detail: detail}
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
			log.Printf("⚠️  no internet through the tunnel: %v%s", err, failureDetail(err))
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

// failureDetail is the core's own error, for the log, when it adds anything.
func failureDetail(err error) string {
	var f *probeFailure
	if errors.As(err, &f) && f.Detail != "" && f.Detail != f.Meaning {
		return " (" + f.Detail + ")"
	}
	return ""
}

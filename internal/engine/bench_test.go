//go:build !no_singbox

package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestBenchmark measures a working account and a dead one through a local
// Shadowsocks server, against local targets.
func TestBenchmark(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			io.WriteString(w, strings.Repeat("x", 2<<20))
			return
		case "/limited": // what Cloudflare's speed test answers after a few tests
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	oldTargets, oldSpeed, oldFallback := BenchTargets, SpeedURL, SpeedFallbackURLs
	BenchTargets = []string{base + "/a", base + "/b", base + "/c", base + "/d"}
	SpeedURL, SpeedFallbackURLs = base+"/limited", []string{base + "/down"} // the first answers 429
	defer func() { BenchTargets, SpeedURL, SpeedFallbackURLs = oldTargets, oldSpeed, oldFallback }()

	port := freePort(t)
	startProtocolServer(t, []obj{{
		"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": port,
		"method": "aes-256-gcm", "password": "pw",
	}})
	good := profile.Profile{Name: "good", Type: profile.TypeShadowsocks, Server: "127.0.0.1", Port: port, Method: "aes-256-gcm", Password: "pw"}
	o := BenchOptions{Connections: 6, SpeedTime: 300 * time.Millisecond, Streams: 3}

	r := Benchmark(t.Context(), good, testSettings(t), o)
	if r.Error != "" {
		t.Fatalf("benchmark failed: %s", r.Error)
	}
	if r.Connects != 6 || r.ConnectFailed != 0 || r.ConnectMedian <= 0 || r.ConnectP90 < r.ConnectMedian {
		t.Errorf("new connections: %+v", r)
	}
	if r.PageParts != 4 || r.PageFailed != 0 || r.Page <= 0 {
		t.Errorf("page burst: %+v", r)
	}
	if r.Download <= 0 || r.DownloadMany <= 0 {
		t.Errorf("speed: %+v", r)
	}
	if r.Score() <= 0 || !strings.Contains(r.String(), "score") {
		t.Errorf("score %v, summary %q", r.Score(), r.String())
	}

	dead := good
	dead.Port = freePort(t)
	d := Benchmark(t.Context(), dead, testSettings(t), o)
	if d.Error == "" || d.Score() != 0 {
		t.Errorf("a dead server was measured as working: %+v", d)
	}
	if d.Score() >= r.Score() {
		t.Error("a dead server scored as well as a working one")
	}
}

// TestLoadCheck: pages opened at once through a working account; the one
// that sends a little and then freezes counts as stuck, the rest don't.
func TestLoadCheck(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big": // more than the check reads
			io.WriteString(w, strings.Repeat("x", 200<<10))
		case "/stall": // what a frozen connection looks like
			io.WriteString(w, strings.Repeat("x", 8<<10))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case "/forbidden": // an answer is an answer: the server got through
			http.Error(w, "no", http.StatusForbidden)
		default:
			io.WriteString(w, "small page")
		}
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	oldURLs, oldStall := LoadURLs, loadStall
	LoadURLs = []string{base + "/a", base + "/big", base + "/stall", base + "/forbidden", base + "/b"}
	loadStall = 500 * time.Millisecond
	defer func() { LoadURLs, loadStall = oldURLs, oldStall }()

	port := freePort(t)
	startProtocolServer(t, []obj{{
		"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": port,
		"method": "aes-256-gcm", "password": "pw",
	}})
	p := profile.Profile{Name: "ss", Type: profile.TypeShadowsocks, Server: "127.0.0.1", Port: port, Method: "aes-256-gcm", Password: "pw"}
	lp, _, stop, err := startPrivate(t.Context(), &p, new(testSettings(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	start := time.Now()
	if got := loadCheck(t.Context(), lp); got != 1 {
		t.Errorf("stuck = %d, want 1 (only the frozen page)", got)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the check took %s: a frozen page should be given up after the stall limit", took)
	}
}

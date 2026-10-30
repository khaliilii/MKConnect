//go:build !no_singbox

package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// TestSiteCheck: sites opened through a working account, the way a browser
// does: the page (after a redirect), the hosts it loads from, and the scripts
// and styles it names. A site whose page or any part freezes doesn't open;
// any HTTP answer does.
func TestSiteCheck(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	var mu sync.Mutex
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.RequestURI()] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/old":
			http.Redirect(w, r, "/home/", http.StatusFound)
		case "/home/": // assets far in, as on YouTube, one of them twice
			io.WriteString(w, `<html><head><link rel="stylesheet" href="style.css"></head><body>`+strings.Repeat("x", 900<<10)+
				`<script src="/s/app.js?v=1&amp;lang=en"></script><script src="/s/app.js?v=1&amp;lang=en"></script>`+
				`<a href="/not-an-asset.js">a link</a><img src="/pic.png"></body></html>`)
		case "/frozen-page/":
			io.WriteString(w, `<script src="/stall.js"></script>`)
		case "/stall", "/stall.js": // what a frozen connection looks like
			io.WriteString(w, strings.Repeat("x", 8<<10))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case "/forbidden": // an answer is an answer: the server got through
			http.Error(w, "no", http.StatusForbidden)
		default:
			io.WriteString(w, strings.Repeat("y", 300<<10)) // more than the check reads
		}
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	oldSites, oldStall := Sites, siteStall
	Sites = []Site{
		{"Good", base + "/old", []string{base + "/cdn"}},
		{"Forbidden", base + "/forbidden", nil},
		{"FrozenAsset", base + "/frozen-page/", nil},
		{"FrozenHost", base + "/other", []string{base + "/stall"}},
	}
	siteStall = 500 * time.Millisecond
	defer func() { Sites, siteStall = oldSites, oldStall }()

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
	got := siteCheck(t.Context(), lp)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the check took %s: a frozen part should be given up after the stall limit", took)
	}
	want := []profile.SiteResult{
		{Name: "Good", OK: true, Parts: 4},
		{Name: "Forbidden", OK: true, Parts: 1},
		{Name: "FrozenAsset", Parts: 2, Stuck: 1},
		{Name: "FrozenHost", Parts: 2, Stuck: 1},
	}
	for i, w := range want {
		g := got[i]
		if g.OK && g.Ms <= 0 || !g.OK && g.Ms != 0 {
			t.Errorf("%s: %d ms", g.Name, g.Ms)
		}
		g.Ms = 0
		if g != w {
			t.Errorf("got %+v, want %+v", g, w)
		}
	}
	for _, u := range []string{"/home/style.css", "/s/app.js?v=1&lang=en"} {
		if !asked[u] {
			t.Errorf("the page's asset %s wasn't loaded (asked: %v)", u, asked)
		}
	}
	if asked["/not-an-asset.js"] || asked["/pic.png"] {
		t.Error("loaded something that isn't a script or style the page needs")
	}
}

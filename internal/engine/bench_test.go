//go:build !no_singbox

package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
// and styles it names (a script's src, a stylesheet's or preload's href,
// quoted or not). A site whose page or any part freezes in two tries doesn't
// open; one that freezes once and then loads does, and any HTTP answer does.
func TestSiteCheck(t *testing.T) {
	if startSingBox == nil {
		t.Skip("sing-box not compiled in")
	}
	var mu sync.Mutex
	var flaky atomic.Int32
	asked := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked[r.URL.RequestURI()] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/old":
			http.Redirect(w, r, "/home/", http.StatusFound)
		case "/home/": // assets far in, as on YouTube, one of them twice
			io.WriteString(w, `<html><head><link rel="stylesheet" href="style.css"><link rel=icon href=/favicon.ico>`+
				`<LINK REL=preload as=font href=/font></head><body>`+strings.Repeat("x", 900<<10)+
				`<script src="/s/app.js?v=1&amp;lang=en"></script><script src="/s/app.js?v=1&amp;lang=en"></script>`+
				`<script async src='/s/h/7f3a'></script><a href="/not-an-asset.js">a link</a><img src="/pic.png"></body></html>`)
		case "/frozen-page/":
			io.WriteString(w, `<script src="/stall.js"></script>`)
		case "/stall", "/stall.js": // what a frozen connection looks like
			io.WriteString(w, strings.Repeat("x", 8<<10))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case "/flaky": // freezes the first time only: a passing hiccup
			if flaky.Add(1) == 1 {
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				return
			}
			io.WriteString(w, "ok")
		case "/forbidden": // an answer is an answer: the server got through
			http.Error(w, "no", http.StatusForbidden)
		default:
			io.WriteString(w, strings.Repeat("y", 300<<10)) // more than the check reads
		}
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	oldStall := siteStall
	sites := []Site{
		{"Good", base + "/old", []string{base + "/cdn"}},
		{"Forbidden", base + "/forbidden", nil},
		{"FrozenAsset", base + "/frozen-page/", nil},
		{"FrozenHost", base + "/other", []string{base + "/stall"}},
		{"Hiccup", base + "/flaky", nil},
	}
	siteStall = 500 * time.Millisecond
	defer func() { siteStall = oldStall }()

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
	got := siteCheck(t.Context(), lp, sites)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the check took %s: a frozen part should be given up after the stall limit (twice)", took)
	}
	want := []profile.SiteResult{
		{Name: "Good", OK: true, Parts: 6},
		{Name: "Forbidden", OK: true, Parts: 1},
		{Name: "FrozenAsset", Parts: 2, Stuck: 2}, // stuck in both tries
		{Name: "FrozenHost", Parts: 2, Stuck: 2},
		{Name: "Hiccup", OK: true, Parts: 1, Stuck: 1}, // opened on the second try
	}
	for i, w := range want {
		g := got[i]
		if g.Name == "Good" && g.Ms <= 0 || !g.OK && g.Ms != 0 { // a local retry can take under 1 ms
			t.Errorf("%s: %d ms", g.Name, g.Ms)
		}
		g.Ms = 0
		if g != w {
			t.Errorf("got %+v, want %+v", g, w)
		}
	}
	for _, u := range []string{"/home/style.css", "/font", "/s/app.js?v=1&lang=en", "/s/h/7f3a"} {
		if !asked[u] {
			t.Errorf("the page's asset %s wasn't loaded (asked: %v)", u, asked)
		}
	}
	if asked["/not-an-asset.js"] || asked["/pic.png"] || asked["/favicon.ico"] {
		t.Error("loaded something that isn't a script or style the page needs")
	}
}

// TestSitesFromSettings: the settings' test sites become pages to open,
// named by host; well-known ones bring the hosts they load from, and entries
// that aren't websites are left out.
func TestSitesFromSettings(t *testing.T) {
	got := sitesFor([]string{"youtube.com", " https://www.linkedin.com/feed/ ", "not a site", "example.org"})
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Name != "youtube.com" || got[0].Page != "https://youtube.com/" || len(got[0].Also) == 0 {
		t.Errorf("youtube: %+v", got[0])
	}
	if got[1].Name != "linkedin.com" || got[1].Page != "https://www.linkedin.com/feed/" || len(got[1].Also) == 0 {
		t.Errorf("linkedin: %+v", got[1])
	}
	if got[2].Name != "example.org" || got[2].Also != nil {
		t.Errorf("example.org: %+v", got[2])
	}
	for _, site := range profile.DefaultTestSites {
		if s := sitesFor([]string{site}); len(s) != 1 || s[0].Also == nil {
			t.Errorf("default %s isn't a known site: %+v", site, s)
		}
	}
}

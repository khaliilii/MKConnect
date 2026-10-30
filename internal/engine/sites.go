package engine

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// Site is a website the account test opens the way a browser does: the page,
// the hosts it loads from at once, then the scripts and styles the page names.
type Site struct {
	Name string
	Page string
	Also []string
}

// Sites are the websites the site check opens (overridable in tests).
var Sites = []Site{
	{"YouTube", "https://www.youtube.com/", []string{"https://i.ytimg.com/generate_204", "https://yt3.ggpht.com/",
		"https://www.gstatic.com/generate_204", "https://fonts.gstatic.com/"}},
	{"Instagram", "https://www.instagram.com/", []string{"https://static.cdninstagram.com/"}},
	{"Telegram", "https://web.telegram.org/a/", []string{"https://telegram.org/", "https://vesta.web.telegram.org/"}},
	{"Facebook", "https://www.facebook.com/", []string{"https://static.xx.fbcdn.net/"}},
	{"X", "https://x.com/", []string{"https://abs.twimg.com/", "https://pbs.twimg.com/", "https://api.x.com/"}},
}

// Site check limits. A page is read up to sitePageBytes (YouTube names its
// scripts 0.8 MB in), each of the first siteAssets scripts and styles up to
// siteAssetBytes. A connection that receives nothing for siteStall counts as
// stuck, and the whole check gives up after siteTimeout (variables for tests).
const (
	sitePageBytes  = 2 << 20
	siteAssetBytes = 256 << 10
	siteAssets     = 6
)

var (
	siteStall   = 6 * time.Second
	siteTimeout = 25 * time.Second
)

// assetRef finds the scripts and styles a page names.
var assetRef = regexp.MustCompile(`<(?:script|link)\b[^>]*?\b(?:src|href)="([^"]+\.(?:js|css)(?:\?[^"]*)?)"`)

// siteCheck opens Sites all at once through the proxy on port. On some
// networks a server answers a probe quickly and downloads fast over one
// connection, yet a share of parallel connections freezes midway (filtering
// going after them): a page then hangs on one of its parts, which only
// loading whole pages like this shows.
func siteCheck(ctx context.Context, port int) []profile.SiteResult {
	ctx, cancel := context.WithTimeout(ctx, siteTimeout)
	defer cancel()
	out := make([]profile.SiteResult, len(Sites))
	var wg sync.WaitGroup
	for i, s := range Sites {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = openSite(ctx, port, s)
		}()
	}
	wg.Wait()
	return out
}

// openSite loads s and its parts, each on a new connection through the
// server; it opens when every part arrives.
func openSite(ctx context.Context, port int, s Site) profile.SiteResult {
	start := time.Now()
	r := profile.SiteResult{Name: s.Name, Parts: 1 + len(s.Also)}
	var stuck atomic.Int32
	var wg sync.WaitGroup
	load := func(u string) {
		defer wg.Done()
		if _, err := fetchPart(ctx, port, u, false, io.Discard); err != nil {
			stuck.Add(1)
		}
	}
	for _, u := range s.Also {
		wg.Add(1)
		go load(u)
	}
	var page bytes.Buffer
	if final, err := fetchPart(ctx, port, s.Page, true, &page); err != nil {
		stuck.Add(1)
	} else {
		assets := pageAssets(page.Bytes(), final)
		r.Parts += len(assets)
		for _, u := range assets {
			wg.Add(1)
			go load(u)
		}
	}
	wg.Wait()
	r.Stuck = int(stuck.Load())
	if r.OK = r.Stuck == 0; r.OK {
		r.Ms = int(time.Since(start).Milliseconds())
	}
	return r
}

// fetchPart copies the start of target (after redirects) to w and returns
// the address it came from; a page is asked for as a browser opening it
// (Facebook answers anything else with an error page). Any HTTP answer whose
// body keeps arriving is fine: the server got through; one that stalls for
// siteStall is not.
func fetchPart(ctx context.Context, port int, target string, page bool, w io.Writer) (*url.URL, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := proxyClient(port, 0)
	c.CheckRedirect = nil // follow them, as a browser does
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	limit := int64(siteAssetBytes)
	if page {
		limit = sitePageBytes
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
	}
	stall := time.AfterFunc(siteStall, cancel) // reset on every chunk that arrives
	defer stall.Stop()
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 32<<10)
	for n := int64(0); n < limit; {
		stall.Reset(siteStall)
		m, err := resp.Body.Read(buf[:min(int64(len(buf)), limit-n)])
		w.Write(buf[:m])
		n += int64(m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return resp.Request.URL, nil
}

// pageAssets returns the first siteAssets scripts and styles page names, as
// web addresses resolved against base.
func pageAssets(page []byte, base *url.URL) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range assetRef.FindAllSubmatch(page, -1) {
		u, err := base.Parse(html.UnescapeString(string(m[1])))
		if err != nil || u.Scheme != "https" && u.Scheme != "http" || seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		if out = append(out, u.String()); len(out) == siteAssets {
			break
		}
	}
	return out
}

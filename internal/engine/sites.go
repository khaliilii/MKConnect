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
	"strings"
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

// siteHosts are the other hosts well-known sites load from as soon as the
// page starts, by TestSiteName; the rest are found in the page.
var siteHosts = map[string][]string{
	"youtube.com": {"https://i.ytimg.com/generate_204", "https://yt3.ggpht.com/", "https://www.gstatic.com/generate_204",
		"https://fonts.gstatic.com/"},
	"instagram.com":    {"https://static.cdninstagram.com/"},
	"web.telegram.org": {"https://telegram.org/", "https://vesta.web.telegram.org/"},
	"facebook.com":     {"https://static.xx.fbcdn.net/"},
	"x.com":            {"https://abs.twimg.com/", "https://pbs.twimg.com/", "https://api.x.com/"},
	"twitter.com":      {"https://abs.twimg.com/", "https://pbs.twimg.com/", "https://api.x.com/"},
	"linkedin.com":     {"https://static.licdn.com/", "https://media.licdn.com/"},
	"clubhouse.com":    {"https://static-assets.clubhouseapi.com/"},
}

// sitesFor turns the test sites of the settings into what the site check
// opens, leaving out entries that aren't websites.
func sitesFor(list []string) []Site {
	var out []Site
	for _, entry := range list {
		page, err := profile.ParseTestSite(entry)
		if err != nil {
			continue
		}
		name := profile.TestSiteName(entry)
		out = append(out, Site{Name: name, Page: page, Also: siteHosts[name]})
	}
	return out
}

// Site check limits. A page is read up to sitePageBytes (YouTube names its
// scripts 0.8 MB in), each of the first siteAssets scripts and styles up to
// siteAssetBytes; siteParallel sites load at a time. A connection that
// receives nothing for siteStall counts as stuck, and the whole check gives
// up after siteTimeout (variables for tests).
const (
	sitePageBytes  = 2 << 20
	siteAssetBytes = 256 << 10
	siteAssets     = 6
	siteParallel   = 4
)

var (
	siteStall   = 6 * time.Second
	siteTimeout = 60 * time.Second
)

// assetTag finds the script and link tags of a page, attrValue their
// attributes (quoted or not).
var (
	assetTag  = regexp.MustCompile(`(?i)<(script|link)\b[^>]*>`)
	attrValue = regexp.MustCompile(`(?i)\s(src|href|rel)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// siteCheck opens sites all at once through the proxy on port. On some
// networks a server answers a probe quickly and downloads fast over one
// connection, yet a share of parallel connections freezes midway (filtering
// going after them): a page then hangs on one of its parts, which only
// loading whole pages like this shows.
//
// A site that doesn't open gets a second try, and fails only if that fails
// too: through a working account a burst of new connections now and then
// meets a passing hiccup (several sites at once, measured), while on the
// networks this check is for a large share of connections freezes every time.
func siteCheck(ctx context.Context, port int, sites []Site) []profile.SiteResult {
	ctx, cancel := context.WithTimeout(ctx, siteTimeout)
	defer cancel()
	out := make([]profile.SiteResult, len(sites))
	slots := make(chan struct{}, siteParallel)
	var wg sync.WaitGroup
	for i, s := range sites {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			r := openSite(ctx, port, s)
			if !r.OK && ctx.Err() == nil {
				again := openSite(ctx, port, s)
				again.Stuck += r.Stuck
				r = again
			}
			out[i] = r
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

// pageAssets returns the first siteAssets scripts and styles page names (a
// script's src, a stylesheet's or preload's href), as web addresses resolved
// against base.
func pageAssets(page []byte, base *url.URL) []string {
	var out []string
	seen := map[string]bool{}
	for _, tag := range assetTag.FindAllSubmatch(page, -1) {
		attrs := map[string]string{}
		for _, a := range attrValue.FindAllSubmatch(tag[0], -1) {
			attrs[strings.ToLower(string(a[1]))] = string(a[2]) + string(a[3]) + string(a[4])
		}
		ref := attrs["src"]
		if strings.EqualFold(string(tag[1]), "link") {
			rel := strings.ToLower(attrs["rel"])
			if !strings.Contains(rel, "stylesheet") && !strings.Contains(rel, "preload") {
				continue
			}
			ref = attrs["href"]
		}
		if ref == "" {
			continue
		}
		u, err := base.Parse(html.UnescapeString(ref))
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

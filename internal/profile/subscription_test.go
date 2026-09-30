package profile

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestParseUserInfo(t *testing.T) {
	u := ParseUserInfo("upload=1073741824; download=2147483648; total=10737418240; expire=1767225600")
	if u == nil || u.Used() != 3<<30 || u.Total != 10<<30 || u.Expire.Unix() != 1767225600 {
		t.Fatalf("unexpected usage %+v", u)
	}
	if ParseUserInfo("") != nil || ParseUserInfo("garbage") != nil {
		t.Fatal("expected nil for empty header")
	}
	if u := ParseUserInfo("upload=1.5e3;download=0;total=0;expire=0"); u == nil || u.Upload != 1500 || !u.Expire.IsZero() {
		t.Fatalf("float / zero expire not handled: %+v", u)
	}
}

func TestFetchSubscription(t *testing.T) {
	links := "trojan://a@h.com:443#one\nvless://bf000d23-0752-40b4-affe-68f7707a9661@h.com:443?security=tls#two\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != userAgent {
			t.Errorf("user agent %q", r.UserAgent())
		}
		w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=100; expire=0")
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("My VPN")))
		w.Header().Set("Profile-Update-Interval", "6")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer srv.Close()

	data, err := FetchSubscription(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if data.Title != "My VPN" || data.UpdateHours != 6 || data.Usage.Used() != 30 {
		t.Fatalf("unexpected metadata %+v", data)
	}

	s, _ := Load(filepath.Join(t.TempDir(), "p.json"))
	g := s.AddGroup("", srv.URL)
	n, errs := s.ApplySubscription(g, data, time.Now())
	if n != 2 || len(errs) != 0 || g.Name != "My VPN" {
		t.Fatalf("n=%d errs=%v name=%q", n, errs, g.Name)
	}
}

func TestApplySubscriptionKeepsIDs(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "p.json"))
	manual, _ := s.Add(Profile{Name: "manual", Type: TypeTrojan, Server: "m.com", Port: 443, Password: "x"})
	manualID := manual.ID
	g := s.AddGroup("sub", "https://example.com/sub")
	gid := g.ID

	first := &SubscriptionData{Body: "trojan://a@h.com:443#one\ntrojan://b@h.com:443#two\n"}
	s.ApplySubscription(g, first, time.Now())
	var keepID string
	for _, p := range s.Profiles {
		if p.Name == "one" {
			keepID = p.ID
		}
	}
	s.Active = keepID

	// "one" is renamed, "two" disappears, "three" is new.
	second := &SubscriptionData{Body: "trojan://a@h.com:443#one-renamed\ntrojan://c@h.com:443#three\n", Usage: &Usage{Total: 5}}
	g, _ = s.FindGroup(gid)
	n, _ := s.ApplySubscription(g, second, time.Now())
	if n != 2 {
		t.Fatalf("group has %d profiles, want 2", n)
	}
	p, err := s.Find(keepID)
	if err != nil || p.Name != "one-renamed" || s.Active != keepID {
		t.Fatalf("id not preserved: %v %+v active=%s", err, p, s.Active)
	}
	if _, err := s.Find(manualID); err != nil {
		t.Fatal("manual profile removed by subscription refresh")
	}
	if g.Usage == nil || g.Usage.Total != 5 {
		t.Fatal("usage not stored")
	}

	s.RemoveGroup(gid)
	if len(s.Profiles) != 1 || s.Active != "" || len(s.Groups) != 0 {
		t.Fatalf("remove group left %d profiles, active=%q", len(s.Profiles), s.Active)
	}
}

func TestAddUnique(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "p.json"))
	p, _ := ParseLink("trojan://a@h.com:443#one")
	if ok, _ := s.AddUnique(p); !ok {
		t.Fatal("first add rejected")
	}
	p.Name = "same server, other name"
	if ok, _ := s.AddUnique(p); ok {
		t.Fatal("duplicate added")
	}
}

func TestNeedsUpdate(t *testing.T) {
	now := time.Now()
	g := Group{URL: "https://x", UpdatedAt: now.Add(-13 * time.Hour)}
	if !g.NeedsUpdate(now) {
		t.Fatal("13h old subscription should update with the 12h default")
	}
	g.UpdateHours = 24
	if g.NeedsUpdate(now) {
		t.Fatal("provider interval ignored")
	}
	if (&Group{}).NeedsUpdate(now) {
		t.Fatal("local group can't update")
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KB", 5 << 30: "5.0 GB"} {
		if got := FormatBytes(n); got != want {
			t.Errorf("%d: got %s want %s", n, got, want)
		}
	}
}

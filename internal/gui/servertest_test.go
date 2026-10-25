package gui

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

func TestServerTestAndSort(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	// Fake results by account name: Germany fast, Netherlands slow, Home server down.
	fake := map[string]*profile.TestResult{
		"Germany":     {Sent: 3, Received: 3, Latency: 120},
		"Netherlands": {Sent: 3, Received: 3, Latency: 480},
		"Home server": {Sent: 3, Error: "timeout"},
	}
	speeds := map[string]int64{"Germany": 1 << 20, "Netherlands": 5 << 20}
	old := testEngine
	defer func() { testEngine = old }()
	testEngine = func(ctx context.Context, ps []profile.Profile, idx []int, s profile.Settings, o engine.TestOptions,
		parallel int, done func(int, *profile.TestResult)) map[int]*profile.TestResult {
		for _, i := range idx {
			r := *fake[ps[i].Name]
			done(i, &r)
		}
		if o.Speed {
			for _, i := range idx {
				if r := *fake[ps[i].Name]; r.OK() {
					r.Speed = speeds[ps[i].Name]
					done(i, &r)
				}
			}
		}
		return nil
	}

	u := newTestUI(t)
	names := func() []string {
		var out []string
		for _, i := range u.visible {
			out = append(out, u.store.Profiles[i].Name)
		}
		return out
	}
	u.testShown(false)
	waitFor(t, func() bool { return u.testCancel == nil })
	if got := names(); got[0] != "Germany" || got[1] != "Netherlands" || got[2] != "Home server" {
		t.Fatalf("latency order = %v", got)
	}
	if u.store.Settings.SortBy != profile.SortLatency {
		t.Fatalf("sort = %q", u.store.Settings.SortBy)
	}

	// The row shows the result, colored.
	main, extra, imp := testText(u.store.Profiles[u.visible[0]].Test)
	if main != "120 ms" || extra != "3/3 ok" || imp != widget.SuccessImportance {
		t.Fatalf("row text %q %q %v", main, extra, imp)
	}

	u.testShown(true)
	waitFor(t, func() bool { return u.testCancel == nil })
	u.setSort(profile.SortSpeed)
	if got := names(); got[0] != "Netherlands" || got[1] != "Germany" {
		t.Fatalf("speed order = %v", got)
	}
	screenshot(t, u.win, "tested")

	// Saved with the profiles.
	again, err := profile.Load(u.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range again.Profiles {
		if p.Test == nil {
			t.Fatalf("%s: result not saved", p.Name)
		}
	}
	u.setSort("")
	if got := names(); got[0] != "Home server" {
		t.Fatalf("added order = %v", got)
	}
}

func TestUpdateAllSubscriptionsButton(t *testing.T) {
	u := newTestUI(t)
	if u.groupUpdateBtn.Visible() {
		t.Fatal("update button shown without subscriptions")
	}
	u.store.AddGroup("sub", "https://example.com/sub")
	u.refreshProfiles()
	if !u.groupUpdateBtn.Visible() {
		t.Fatal("update button hidden on All accounts with a subscription")
	}
}

// TestUpdateAndRank is the one-click button: the shown subscription is
// downloaded again, every account in it (but not its message entries) is
// measured with speed, and the list ends up sorted by speed.
func TestUpdateAndRank(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	links := "trojan://a@slow.example:443#slow\ntrojan://b@fast.example:443#fast\n" +
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"ps":"Used: 1 GB","add":"Asgard By ODIN","port":1,"id":"bf000d23-0752-40b4-affe-68f7707a9661"}`)) + "\n"
	fetched := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched++
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer srv.Close()

	var tested []string
	var opts engine.TestOptions
	old := testEngine
	defer func() { testEngine = old }()
	testEngine = func(ctx context.Context, ps []profile.Profile, idx []int, s profile.Settings, o engine.TestOptions,
		parallel int, done func(int, *profile.TestResult)) map[int]*profile.TestResult {
		opts = o
		for _, i := range idx {
			tested = append(tested, ps[i].Name)
			r := &profile.TestResult{Sent: 3, Received: 3, Latency: 100, Speed: 1 << 20}
			if ps[i].Name == "fast" {
				r.Speed = 8 << 20
			}
			done(i, r)
		}
		return nil
	}

	u := newTestUI(t)
	g := u.store.AddGroup("", srv.URL)
	u.groupFilter = g.ID
	u.refreshProfiles()

	u.updateAndRank()
	waitFor(t, func() bool { return !u.ranking })

	if fetched != 1 {
		t.Fatalf("the subscription was fetched %d times, want 1", fetched)
	}
	if !opts.Speed || opts.SpeedTime != rankSpeedTime {
		t.Fatalf("test options %+v: want speed measured, capped at %v", opts, rankSpeedTime)
	}
	slices.Sort(tested)
	if strings.Join(tested, ",") != "fast,slow" {
		t.Fatalf("tested %v: want the two servers and not the message entry", tested)
	}
	if u.store.Settings.SortBy != profile.SortSpeed {
		t.Fatalf("sort = %q, want speed", u.store.Settings.SortBy)
	}
	if first := u.store.Profiles[u.visible[0]].Name; first != "fast" {
		t.Fatalf("first in the list is %q, want the fastest", first)
	}
	if u.rankBtn.Disabled() {
		t.Fatal("the button stayed disabled")
	}
}

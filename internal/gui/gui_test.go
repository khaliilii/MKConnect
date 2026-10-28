package gui

import (
	"context"
	"encoding/base64"
	"errors"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// The test driver can't serialize background refreshes with the tests, so
// the session box's ticker effectively never fires (set once: a running
// ticker goroutine of an earlier test still reads the variable).
func init() { sessionRefreshInterval, logRefreshInterval = time.Hour, time.Hour }

// newTestUI builds the main window on Fyne's headless test driver.
func newTestUI(t *testing.T) *ui {
	t.Helper()
	a := test.NewTempApp(t)
	a.SetIcon(theme.FyneLogo())
	store, err := profile.Load(filepath.Join(t.TempDir(), "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{
		"ssh://root:pw@1.2.3.4:22#Home%20server",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@de.example.com:443?security=reality&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6b&flow=xtls-rprx-vision#Germany",
		"trojan://pw@nl.example.com:443?type=ws&path=/tr#Netherlands",
	} {
		p, err := profile.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	store.Settings.ListenPort = freePort(t)
	store.Settings.LogLevel = "error"

	u := &ui{app: a, store: store, logs: &logBuffer{}}
	u.win = a.NewWindow("MKConnect")
	u.win.Resize(fyne.NewSize(1000, 680))
	u.build()
	return u
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// screenshot saves the window to $MKCONNECT_SCREENSHOTS/<name>.png when set.
func screenshot(t *testing.T, w fyne.Window, name string) {
	dir := os.Getenv("MKCONNECT_SCREENSHOTS")
	if dir == "" {
		return
	}
	f, err := os.Create(filepath.Join(dir, name+".png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, w.Canvas().Capture()); err != nil {
		t.Fatal(err)
	}
}

func TestMainWindow(t *testing.T) {
	u := newTestUI(t)
	if got := u.list.Length(); got != 3 {
		t.Fatalf("list shows %d profiles, want 3", got)
	}
	u.list.Select(1)
	if u.store.Active != u.store.Profiles[1].ID {
		t.Fatal("selecting a profile did not make it active")
	}
	screenshot(t, u.win, "main")

	u.importText("ss://"+"YWVzLTI1Ni1nY206cHc"+"@5.6.7.8:8388#Imported\nnot-a-link", "")
	if got := u.list.Length(); got != 4 {
		t.Fatalf("after import list shows %d profiles, want 4", got)
	}
	saved, err := profile.Load(u.store.Path())
	if err != nil || len(saved.Profiles) != 4 {
		t.Fatalf("import not saved: %v", err)
	}
}

func TestEditorsRender(t *testing.T) {
	u := newTestUI(t)
	for _, typ := range profile.Types {
		u.openEditor(profile.Profile{Type: typ, Port: 443}, true)
	}
	u.openEditor(u.store.Profiles[1], false)
	var editors []fyne.Window
	for _, w := range u.app.Driver().AllWindows() {
		if strings.HasPrefix(w.Title(), "New ") || strings.HasPrefix(w.Title(), "Edit ") {
			editors = append(editors, w)
		}
	}
	if len(editors) != len(profile.Types)+1 {
		t.Fatalf("got %d editor windows, want %d", len(editors), len(profile.Types)+1)
	}
	for _, w := range editors {
		screenshot(t, w, "editor-"+w.Title())
	}
}

func TestSaveProfileEditResetsHostKey(t *testing.T) {
	u := newTestUI(t)
	p := u.store.Profiles[0]
	u.store.Profiles[0].HostKey = "ssh-ed25519 AAAA"
	p.HostKey = "ssh-ed25519 AAAA"
	p.Server = "9.9.9.9"
	if err := u.saveProfile(p, false); err != nil {
		t.Fatal(err)
	}
	if u.store.Profiles[0].HostKey != "" {
		t.Fatal("host key kept after the server changed")
	}
	bad := p
	bad.User = ""
	if err := u.saveProfile(bad, false); err == nil {
		t.Fatal("invalid profile was saved")
	}
}

func TestConnectDisconnect(t *testing.T) {
	if raceEnabled {
		// Fyne's test driver runs fyne.Do callbacks on the calling goroutine instead
		// of a main thread, so the race detector flags accesses the real driver serializes.
		t.Skip("not meaningful under -race with the Fyne test driver")
	}
	u := newTestUI(t)
	u.list.Select(2) // trojan: sing-box starts without reaching the server
	u.connect()
	waitFor(t, func() bool { return u.state == stateConnected })
	screenshot(t, u.win, "connected")

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(u.store.Settings.ListenPort)))
	if err != nil {
		t.Fatalf("local proxy not listening: %v", err)
	}
	c.Close()

	if u.session == nil || !strings.Contains(u.session.Outbound, "nl.example.com:443") {
		t.Fatalf("session not published: %+v", u.session)
	}

	u.disconnect(nil)
	waitFor(t, func() bool { return u.state == stateIdle && u.session == nil })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var ok bool
		fyne.DoAndWait(func() { ok = cond() })
		if ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for state change")
}

func TestGroupsAndSubscription(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	links := "trojan://a@h.com:443#sub-one\ntrojan://b@h.com:443#sub-two\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1073741824; download=2147483648; total=10737418240; expire=4102444800")
		w.Header().Set("Profile-Title", "My Provider")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	}))
	defer srv.Close()

	u := newTestUI(t)
	// Bulk import into a new local group.
	u.importText("trojan://x@g.com:443#g1\ntrojan://y@g.com:443#g2", "Work")
	if u.groupFilter == filterAll || u.list.Length() != 2 {
		t.Fatalf("group view shows %d accounts, filter %q", u.list.Length(), u.groupFilter)
	}

	// Subscription: fetched in the background, then applied on the UI goroutine.
	g := u.store.AddGroup("", srv.URL)
	u.groupFilter = g.ID
	u.refreshProfiles()
	u.updateSubscription(g.ID, false)
	waitFor(t, func() bool { return u.list.Length() == 2 })
	g, _ = u.store.FindGroup(g.ID)
	if g.Name != "My Provider" || g.Usage == nil || g.Usage.Used() != 3<<30 {
		t.Fatalf("subscription metadata not applied: %+v", g)
	}
	if !u.usageCard.Visible() || !strings.Contains(u.usageText.Text, "3.0 GB of 10.0 GB used") {
		t.Fatalf("usage card: visible=%v text=%q", u.usageCard.Visible(), u.usageText.Text)
	}
	screenshot(t, u.win, "subscription")

	u.groupSelect.SetSelected(labelAllGroups)
	if u.list.Length() != 7 {
		t.Fatalf("all accounts shows %d, want 7", u.list.Length())
	}
}

func TestClipboardImport(t *testing.T) {
	u := newTestUI(t)
	link := "vless://bf000d23-0752-40b4-affe-68f7707a9661@clip.example.com:443?security=tls#From%20clipboard"
	u.app.Clipboard().SetContent(link)
	u.checkClipboard()
	if len(u.store.Profiles) != 4 {
		t.Fatalf("clipboard link not imported: %d profiles", len(u.store.Profiles))
	}
	u.lastClipboard = "" // same content again must not create a duplicate
	u.checkClipboard()
	if len(u.store.Profiles) != 4 {
		t.Fatal("duplicate imported from clipboard")
	}
	u.store.Settings.ClipboardImport = false
	u.app.Clipboard().SetContent("trojan://z@off.com:443#off")
	u.checkClipboard()
	if len(u.store.Profiles) != 4 {
		t.Fatal("imported although clipboard import is off")
	}
}

func TestAbout(t *testing.T) {
	u := newTestUI(t)
	u.showAbout()
	screenshot(t, u.win, "about")
}

// TestImportClipboardButton is the one-click import: a chat message with
// several links of different protocols, then the same message again.
func TestImportClipboardButton(t *testing.T) {
	u := newTestUI(t)
	msg := "Free servers 👇\n" +
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:443?security=tls&sni=a.com#VLESS-1 " +
		"trojan://pw@t.example.com:443#Trojan-1\r\n" +
		"hy2://secret@hy.example.com:443?sni=hy.example.com#HY2-1\n" +
		"tuic://bf000d23-0752-40b4-affe-68f7707a9661:pw@tu.example.com:443?congestion_control=bbr#TUIC-1\n" +
		"wireguard://x@w.example.com:51820#WG\n"
	u.app.Clipboard().SetContent(msg)
	u.importClipboard()
	if len(u.store.Profiles) != 3+4 {
		t.Fatalf("got %d profiles, want 7", len(u.store.Profiles))
	}
	got := map[string]bool{}
	for _, p := range u.store.Profiles {
		got[p.Type] = true
	}
	for _, typ := range []string{profile.TypeVLESS, profile.TypeTrojan, profile.TypeHysteria2, profile.TypeTUIC} {
		if !got[typ] {
			t.Errorf("no %s profile imported", typ)
		}
	}
	screenshot(t, u.win, "clipboard-import")

	u.importClipboard() // same content: nothing new
	if len(u.store.Profiles) != 7 {
		t.Fatalf("duplicates imported: %d profiles", len(u.store.Profiles))
	}
	saved, _ := profile.Load(u.store.Path())
	if len(saved.Profiles) != 7 {
		t.Fatal("import not saved")
	}

	u.app.Clipboard().SetContent("")
	u.importClipboard() // empty clipboard must not panic or add anything
	if len(u.store.Profiles) != 7 {
		t.Fatal("empty clipboard changed the list")
	}
}

func TestTUNShareInterfacesUI(t *testing.T) {
	u := newTestUI(t)
	u.store.Settings.Mode = profile.ModeTUN
	u.win.SetContent(nil)
	u.build() // rebuild with TUN selected so the share section is visible
	screenshot(t, u.win, "tun-share")
}

// TestMobileLayout renders the phone layout at a typical phone size.
func TestMobileLayout(t *testing.T) {
	isMobile = true
	defer func() { isMobile = runtime.GOOS == "android" || runtime.GOOS == "ios" }()
	u := newTestUI(t)
	u.win.Resize(fyne.NewSize(390, 800))
	if u.mobileTabs == nil || len(u.mobileTabs.Items) != 3 {
		t.Fatal("phone layout has no tabs")
	}
	for i, name := range []string{"accounts", "connection", "logs"} {
		u.mobileTabs.SelectIndex(i)
		screenshot(t, u.win, "mobile-"+name)
	}
	u.openEditor(u.store.Profiles[1], false)
	for _, w := range u.app.Driver().AllWindows() {
		if strings.HasPrefix(w.Title(), "Edit ") {
			w.Resize(fyne.NewSize(390, 800))
			screenshot(t, w, "mobile-editor")
		}
	}
	u.mobileTabs.SelectIndex(0)
	u.showImport()
	screenshot(t, u.win, "mobile-import")
}

func TestLogViewFilterLevelAndDetail(t *testing.T) {
	u := newTestUI(t)
	for _, line := range []string{"starting core", "❌ boom: connection refused", "🚀 running"} {
		u.logs.add(line)
	}
	u.refreshLogs()
	if got := u.logList.Length(); got != 3 {
		t.Fatalf("log list shows %d lines, want 3", got)
	}

	u.logSearch.SetText("boom")
	if got := u.logList.Length(); got != 1 {
		t.Fatalf("filtered list shows %d lines, want 1", got)
	}
	u.logSearch.SetText("")
	if got := u.logList.Length(); got != 3 {
		t.Fatalf("after clearing the filter: %d lines, want 3", got)
	}

	// A click opens the full line, which long lines need.
	u.logList.Select(1)
	if u.win.Canvas().Overlays().Top() == nil {
		t.Error("clicking a log line did not open it in full")
	}

	u.logLevel.SetSelected("debug")
	if u.store.Settings.LogLevel != "debug" {
		t.Fatalf("log level is %q, want debug", u.store.Settings.LogLevel)
	}
	saved, err := profile.Load(u.store.Path())
	if err != nil || saved.Settings.LogLevel != "debug" {
		t.Fatalf("log level not saved: %v", err)
	}

	u.logs.clear()
	u.refreshLogs()
	if got := u.logList.Length(); got != 0 {
		t.Fatalf("after clear: %d lines, want 0", got)
	}
}

// TestAutoReconnectAfterDrop drives the connection loop with a fake core: the
// first attempt drops, the second one stays up and healthy.
func TestAutoReconnectAfterDrop(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	u := newTestUI(t)
	u.store.Settings.AutoReconnect = true

	oldRun, oldDelay := runConnection, reconnectDelay
	defer func() { runConnection, reconnectDelay = oldRun, oldDelay }()
	reconnectDelay = func(int) time.Duration { return 10 * time.Millisecond }

	var attempts atomic.Int32
	runConnection = func(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
		if attempts.Add(1) == 1 {
			// Up, then dropped: not a user disconnect.
			hooks.OnStarted(engine.NewSession("singbox", []string{"SOCKS5 127.0.0.1:1080"}, p.Address(), nil))
			return errors.New("core stopped: boom")
		}
		hooks.OnStarted(engine.NewSession("singbox", []string{"SOCKS5 127.0.0.1:1080"}, p.Address(), nil))
		hooks.OnHealth(42*time.Millisecond, nil)
		<-ctx.Done()
		return nil
	}

	u.connect()
	// The first attempt is briefly connected too (it drops after starting):
	// wait for the second one to be up.
	waitFor(t, func() bool { return attempts.Load() == 2 && u.state == stateConnected && u.health.latency > 0 })
	if got := attempts.Load(); got != 2 {
		t.Fatalf("the connection was attempted %d times, want 2 (one drop, one success)", got)
	}
	if text := u.statusLabel.Text; !strings.Contains(text, "42 ms") {
		t.Errorf("status does not show the measured latency: %q", text)
	}

	u.disconnect(nil)
	waitFor(t, func() bool { return u.state == stateIdle })
	if got := attempts.Load(); got != 2 {
		t.Fatalf("a user disconnect was retried: %d attempts", got)
	}
}

// TestFailoverToBackup: an account that keeps failing is replaced by the
// fastest working account of its group, skipping one that bills extra.
func TestFailoverToBackup(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	u := newTestUI(t)
	u.store.Settings.AutoReconnect, u.store.Settings.Failover = true, true
	ps := u.store.Profiles
	ps[1].Name = "Germany x2" // the fastest, but at twice the usage
	ps[1].Test = &profile.TestResult{Sent: 3, Received: 3, Latency: 90, Speed: 5 << 20}
	ps[2].Test = &profile.TestResult{Sent: 3, Received: 3, Latency: 120, Speed: 1 << 20}
	u.store.Active = ps[0].ID
	failing, backup := ps[0].ID, ps[2].ID

	oldRun, oldDelay := runConnection, reconnectDelay
	defer func() { runConnection, reconnectDelay = oldRun, oldDelay }()
	reconnectDelay = func(int) time.Duration { return 10 * time.Millisecond }
	var mu sync.Mutex
	var tried []string
	runConnection = func(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
		mu.Lock()
		tried = append(tried, p.ID)
		mu.Unlock()
		hooks.OnStarted(engine.NewSession("singbox", []string{"SOCKS5 127.0.0.1:1080"}, p.Address(), nil))
		if p.ID == failing {
			return errors.New("core stopped: boom")
		}
		hooks.OnHealth(42*time.Millisecond, nil)
		<-ctx.Done()
		return nil
	}

	u.connect()
	waitFor(t, func() bool { return u.store.Active == backup && u.state == stateConnected && u.health.latency > 0 })
	mu.Lock()
	got := append([]string(nil), tried...)
	mu.Unlock()
	if want := []string{failing, failing, backup}; !slices.Equal(got, want) {
		t.Errorf("accounts tried %v, want %v (two tries, then the backup)", got, want)
	}
	if !strings.Contains(u.statusLabel.Text, ps[2].Name) {
		t.Errorf("status doesn't name the backup: %q", u.statusLabel.Text)
	}
	u.disconnect(nil)
	waitFor(t, func() bool { return u.state == stateIdle })
}

// TestNoInternetIsReported shows a core that runs but carries no traffic as
// such, instead of a green "Connected".
func TestNoInternetIsReported(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	u := newTestUI(t)
	u.store.Settings.AutoReconnect = false

	oldRun := runConnection
	defer func() { runConnection = oldRun }()
	runConnection = func(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
		hooks.OnStarted(engine.NewSession("singbox", []string{"SOCKS5 127.0.0.1:1080"}, p.Address(), nil))
		hooks.OnHealth(0, errors.New("timeout"))
		<-ctx.Done()
		return nil
	}

	u.connect()
	waitFor(t, func() bool { return strings.Contains(u.statusLabel.Text, "no internet") })
	if u.statusLabel.Importance != widget.WarningImportance {
		t.Errorf("a connection without internet is not marked as a warning: %v", u.statusLabel.Importance)
	}
	u.disconnect(nil)
	waitFor(t, func() bool { return u.state == stateIdle })
}

// TestFailedFirstConnectIsNotRetried: a connection that never came up shows
// its error at once instead of being retried ten times.
func TestFailedFirstConnectIsNotRetried(t *testing.T) {
	if raceEnabled {
		t.Skip("background fyne.Do callbacks aren't serialized by the Fyne test driver")
	}
	u := newTestUI(t)
	u.store.Settings.AutoReconnect = true
	oldRun, oldDelay := runConnection, reconnectDelay
	defer func() { runConnection, reconnectDelay = oldRun, oldDelay }()
	reconnectDelay = func(int) time.Duration { return time.Millisecond }

	var attempts atomic.Int32
	runConnection = func(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
		attempts.Add(1)
		return profile.ErrInfoEntry
	}
	u.connect()
	waitFor(t, func() bool { return u.state == stateIdle && u.cancel == nil })
	time.Sleep(50 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("a connection that never came up was tried %d times, want 1", got)
	}
}

// TestLogButtons: the log's buttons say what they do and do it — Copy copies
// what is shown and says so, Clear empties the log, Expand opens the log in a
// window of its own whose Close closes it. (Icon-only buttons were taken for
// window controls that didn't work.)
func TestLogButtons(t *testing.T) {
	u := newTestUI(t)
	parts := u.logParts
	for _, b := range []*widget.Button{parts.copyBtn, parts.clearBtn, parts.expandBtn} {
		if b.Text == "" {
			t.Errorf("a log button has no label (icon %v)", b.Icon.Name())
		}
	}
	for _, line := range []string{"one", "two", "three"} {
		u.logs.add(line)
	}
	u.refreshAllLogs()

	test.Tap(parts.copyBtn)
	if got := u.app.Clipboard().Content(); got != "one\ntwo\nthree" {
		t.Fatalf("copied %q", got)
	}
	if !strings.HasPrefix(parts.copyBtn.Text, "Copied 3") {
		t.Errorf("Copy gave no feedback: %q", parts.copyBtn.Text)
	}

	test.Tap(parts.expandBtn)
	if u.logWindow == nil || u.logWindow.Title() != "MKConnect logs" {
		t.Fatal("Expand did not open the log window")
	}
	screenshot(t, u.win, "log-panel")
	screenshot(t, u.logWindow, "log-window")
	if got := u.logWindowParts.list.Length(); got != 3 {
		t.Fatalf("the log window shows %d lines, want 3", got)
	}
	u.logs.add("four")
	u.refreshAllLogs()
	if got := u.logWindowParts.list.Length(); got != 4 {
		t.Fatalf("the log window did not follow new lines: %d", got)
	}
	test.Tap(parts.expandBtn) // again: the same window, not a second one
	if len(u.logRefreshers) != 2 {
		t.Fatalf("%d log views registered, want 2", len(u.logRefreshers))
	}
	test.Tap(u.logWindowParts.closeBtn)
	if u.logWindow != nil || len(u.logRefreshers) != 1 {
		t.Fatalf("Close left the window (%v) or its refresher (%d views)", u.logWindow, len(u.logRefreshers))
	}

	test.Tap(parts.clearBtn)
	if got := u.logList.Length(); got != 0 {
		t.Fatalf("Clear left %d lines", got)
	}
}

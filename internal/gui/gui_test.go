package gui

import (
	"encoding/base64"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"

	"github.com/khaliilii/MKConnect/internal/profile"
)

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
	time.Sleep(1500 * time.Millisecond) // let the session box tick once
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

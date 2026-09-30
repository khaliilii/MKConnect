package gui

import (
	"image/png"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// newTestUI builds the main window on Fyne's headless test driver.
func newTestUI(t *testing.T) *ui {
	t.Helper()
	a := test.NewTempApp(t)
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

	u.importText("ss://" + "YWVzLTI1Ni1nY206cHc" + "@5.6.7.8:8388#Imported\nnot-a-link")
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

	u.disconnect(nil)
	waitFor(t, func() bool { return u.state == stateIdle })
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

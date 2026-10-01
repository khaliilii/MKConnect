// Package gui is the Fyne desktop interface of MKConnect.
package gui

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

type connState int

const (
	stateIdle connState = iota
	stateConnecting
	stateConnected
)

// ui holds the application state. All fields are only touched on the Fyne
// main goroutine; background work reports back through fyne.Do.
type ui struct {
	app   fyne.App
	win   fyne.Window
	store *profile.Store
	logs  *logBuffer

	profilesPanel *fyne.Container
	list          *widget.List
	visible       []int // indices into store.Profiles shown in the list
	emptyHint     *widget.Label

	groupFilter    string            // filterAll, filterUngrouped or a group id
	groupLabels    map[string]string // group picker label -> filter value
	groupSelect    *widget.Select
	groupUpdateBtn *widget.Button
	groupDeleteBtn *widget.Button
	usageCard      *fyne.Container
	usageTitle     *widget.Label
	usageBar       *widget.ProgressBar
	usageText      *widget.Label

	lastClipboard string
	session       *engine.Session // nil while disconnected

	state  connState
	cancel context.CancelFunc
	done   chan struct{}

	connectBtn  *widget.Button
	statusLabel *widget.Label
	settingsBox *fyne.Container
	trayMenu    *fyne.Menu
	trayConnect *fyne.MenuItem
}

// Run starts the GUI and blocks until the app quits.
func Run(icon []byte) {
	logs := &logBuffer{}
	captureOutput(logs)

	a := app.NewWithID("com.khaliilii.mkconnect")
	res := fyne.NewStaticResource("icon.png", icon)
	a.SetIcon(res)

	u := &ui{app: a, logs: logs}
	u.win = a.NewWindow("MKConnect")
	u.win.Resize(fyne.NewSize(1000, 680))

	path, err := profilesPath(a)
	if err == nil {
		u.store, err = profile.Load(path)
	}
	if err == nil && isMobile {
		u.store.Settings.Mode = profile.ModeProxy // TUN needs the Android VPN service
	}
	if err != nil {
		// Don't start with an empty store: saving it would overwrite the user's profiles.
		u.win.SetContent(widget.NewLabel(""))
		d := dialog.NewError(fmt.Errorf("cannot load profiles: %w", err), u.win)
		d.SetOnClosed(a.Quit)
		d.Show()
		u.win.ShowAndRun()
		return
	}

	u.build()
	u.autoUpdateSubscriptions()
	// Like Hiddify: pick up share links copied while the app was in the background.
	a.Lifecycle().SetOnEnteredForeground(u.checkClipboard)
	if desk, ok := a.(desktop.App); ok {
		u.setupTray(desk, res)
		// With a tray icon, closing the window keeps the connection running in the background.
		u.win.SetCloseIntercept(u.win.Hide)
	} else {
		u.win.SetCloseIntercept(u.quit)
	}
	u.win.ShowAndRun()
}

// isMobile is true on Android/iOS, where there is no TUN (without a VPN service) and no tray.
const isMobile = runtime.GOOS == "android" || runtime.GOOS == "ios"

// profilesPath is $MKCONNECT_CONFIG, the user config dir on desktop, or the
// app's private storage on mobile (which has no home directory).
func profilesPath(a fyne.App) (string, error) {
	if p := os.Getenv("MKCONNECT_CONFIG"); p != "" || !isMobile {
		return profile.DefaultPath()
	}
	return filepath.Join(a.Storage().RootURI().Path(), "profiles.json"), nil
}

// build lays out the main window.
func (u *ui) build() {
	left := u.newProfilesPanel()
	var logPane *fyne.Container
	session := u.newSessionBox(func() { logPane.Refresh() })
	logPane = container.NewBorder(container.NewVBox(session, widget.NewSeparator()), nil, nil, nil, u.newLogView())
	right := container.NewVSplit(u.newConnectionPanel(), logPane)
	right.Offset = 0.62
	split := container.NewHSplit(left, right)
	split.Offset = 0.4
	u.win.SetContent(split)
	u.win.SetMainMenu(u.mainMenu())
}

func (u *ui) mainMenu() *fyne.MainMenu {
	return fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("Import from clipboard", u.importClipboard),
			fyne.NewMenuItem("Import links / subscription…", u.showImport),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit MKConnect", u.quit),
		),
		fyne.NewMenu("Help",
			fyne.NewMenuItem("About MKConnect", u.showAbout),
		),
	)
}

func (u *ui) setupTray(desk desktop.App, icon fyne.Resource) {
	u.trayConnect = fyne.NewMenuItem("Connect", u.toggleConnection)
	u.trayMenu = fyne.NewMenu("MKConnect",
		fyne.NewMenuItem("Show", func() { u.win.Show(); u.win.RequestFocus() }),
		u.trayConnect,
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", u.quit),
	)
	desk.SetSystemTrayMenu(u.trayMenu)
	desk.SetSystemTrayIcon(icon)
}

// quit disconnects (waiting briefly for the cores to close) and exits.
func (u *ui) quit() {
	if u.cancel == nil {
		u.app.Quit()
		return
	}
	done := u.done
	u.cancel()
	go func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		fyne.Do(u.app.Quit)
	}()
}

// logf writes to the log view (stdout/stderr are captured into it).
func (u *ui) logf(format string, args ...any) {
	log.Printf(format, args...)
}

// save writes the store and reports failures.
func (u *ui) save() {
	if err := u.store.Save(); err != nil {
		dialog.ShowError(fmt.Errorf("save profiles: %w", err), u.win)
	}
}

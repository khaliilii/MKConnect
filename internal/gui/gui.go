// Package gui is the Fyne desktop interface of MKConnect.
package gui

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

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

	list      *widget.List
	emptyHint *widget.Label

	state  connState
	cancel context.CancelFunc
	done   chan struct{}

	connectBtn   *widget.Button
	statusLabel  *widget.Label
	settingsBox  *fyne.Container
	trayMenu     *fyne.Menu
	trayConnect  *fyne.MenuItem
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

	path, err := profile.DefaultPath()
	if err == nil {
		u.store, err = profile.Load(path)
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
	if desk, ok := a.(desktop.App); ok {
		u.setupTray(desk, res)
		// With a tray icon, closing the window keeps the connection running in the background.
		u.win.SetCloseIntercept(u.win.Hide)
	} else {
		u.win.SetCloseIntercept(u.quit)
	}
	u.win.ShowAndRun()
}

// build lays out the main window.
func (u *ui) build() {
	left := u.newProfilesPanel()
	right := container.NewVSplit(u.newConnectionPanel(), u.newLogView())
	right.Offset = 0.62
	split := container.NewHSplit(left, right)
	split.Offset = 0.4
	u.win.SetContent(split)
	u.win.SetMainMenu(u.mainMenu())
}

func (u *ui) mainMenu() *fyne.MainMenu {
	return fyne.NewMainMenu(
		fyne.NewMenu("File",
			fyne.NewMenuItem("Import links / subscription…", u.showImport),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit MKConnect", u.quit),
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

// save writes the store and reports failures.
func (u *ui) save() {
	if err := u.store.Save(); err != nil {
		dialog.ShowError(fmt.Errorf("save profiles: %w", err), u.win)
	}
}

package gui

import (
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/applog"
)

const maxLogLines = 2000

// logLevels are the core log levels, least to most verbose.
var logLevels = []string{"error", "warn", "info", "debug", "trace"}

// logBuffer keeps the most recent log lines for the log view.
type logBuffer struct {
	mu    sync.Mutex
	lines []string
	dirty bool
}

func (b *logBuffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
	if len(b.lines) > maxLogLines {
		b.lines = append([]string(nil), b.lines[len(b.lines)-maxLogLines:]...)
	}
	b.dirty = true
}

// current returns the lines without touching the dirty flag, which the
// shared ticker has already taken.
func (b *logBuffer) current() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...)
}

func (b *logBuffer) takeDirty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dirty
}

func (b *logBuffer) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines, b.dirty = nil, true
}

// newLogView returns the log panel of the main window. Its header names what
// each button does: icon-only buttons read as window controls (a copy icon
// looks like "maximize", a clear icon like "close"), and users took them for
// broken ones.
func (u *ui) newLogView() fyne.CanvasObject {
	content, refresh, parts := u.logPanel(u.win, false)
	u.refreshLogs, u.logList, u.logSearch, u.logLevel = refresh, parts.list, parts.search, parts.level
	u.logParts = parts
	u.addLogRefresher(refresh)
	// One ticker for every log view: the buffer's dirty flag is taken once,
	// then each view (this panel, the expanded window) redraws.
	go func() {
		for range time.Tick(logRefreshInterval) {
			if u.logs.takeDirty() {
				fyne.Do(u.refreshAllLogs)
			}
		}
	}()
	return content
}

// logParts are the widgets of a log panel that tests and callers reach.
type logParts struct {
	list      *widget.List
	search    *widget.Entry
	level     *widget.Select
	copyBtn   *widget.Button
	clearBtn  *widget.Button
	expandBtn *widget.Button // main panel only
	closeBtn  *widget.Button // expanded window only
	followed  *widget.Check
}

// logPanel builds a log view for a window: wrapped lines, a filter, the log
// level, a follow switch, copy and clear, and, in the main window, Expand
// (the log in a window of its own) or, in that window, Close.
func (u *ui) logPanel(parent fyne.Window, expanded bool) (fyne.CanvasObject, func(), *logParts) {
	var (
		lines  []string // what the list shows (filtered)
		filter string
		list   *widget.List
	)
	heights := map[string]float32{} // text -> measured row height

	list = widget.NewList(
		func() int { return len(lines) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.SizeName = theme.SizeNameCaptionText
			l.Wrapping = fyne.TextWrapBreak // long lines wrap instead of being cut
			return l
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			if id >= len(lines) {
				return
			}
			text := lines[id]
			o.(*widget.Label).SetText(text)
			if h := u.logRowHeight(text, list, heights); h > 0 {
				list.SetItemHeight(id, h)
			}
		},
	)
	// Lines are often longer than the panel; a click shows one in full.
	list.OnSelected = func(id widget.ListItemID) {
		if id >= len(lines) {
			return
		}
		line := lines[id]
		list.Unselect(id)
		text := widget.NewMultiLineEntry() // an entry so the text can be selected and copied
		text.SetText(line)
		text.Wrapping = fyne.TextWrapBreak
		d := dialog.NewCustom("Log line", "Close", container.NewVScroll(text), parent)
		size := parent.Canvas().Size()
		d.Resize(fyne.NewSize(min(700, size.Width-16), min(300, size.Height-16)))
		d.Show()
	}

	follow := widget.NewCheck("Follow", nil)
	follow.SetChecked(true)
	search := widget.NewEntry()
	search.SetPlaceHolder("Filter…")

	refresh := func() {
		all := u.logs.current()
		if filter == "" {
			lines = all
		} else {
			lines = lines[:0:0]
			needle := strings.ToLower(filter)
			for _, l := range all {
				if strings.Contains(strings.ToLower(l), needle) {
					lines = append(lines, l)
				}
			}
		}
		list.Refresh()
		if follow.Checked {
			list.ScrollToBottom()
		}
	}
	search.OnChanged = func(s string) {
		filter = strings.TrimSpace(s)
		refresh()
	}
	follow.OnChanged = func(on bool) {
		if on {
			list.ScrollToBottom()
		}
	}

	level := widget.NewSelect(logLevels, nil)
	level.SetSelected(orDefault(u.store.Settings.LogLevel, "info"))
	level.OnChanged = func(v string) {
		if v == u.store.Settings.LogLevel {
			return
		}
		u.store.Settings.LogLevel = v
		u.save()
		if u.state != stateIdle {
			u.logf("ℹ️  log level %s applies to the next connection; reconnect to use it now", v)
		}
	}

	parts := &logParts{list: list, search: search, level: level, followed: follow}
	var toolsRow *fyne.Container // laid out again when a button's text changes
	parts.copyBtn = widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), nil)
	parts.copyBtn.OnTapped = func() {
		text := strings.Join(lines, "\n") // what is shown: the filter applies
		u.app.Clipboard().SetContent(text)
		btn := parts.copyBtn
		btn.SetText(fmt.Sprintf("Copied %d lines", len(lines)))
		btn.SetIcon(theme.ConfirmIcon())
		toolsRow.Refresh()
		go func() {
			time.Sleep(2 * time.Second)
			fyne.Do(func() {
				btn.SetText("Copy")
				btn.SetIcon(theme.ContentCopyIcon())
				toolsRow.Refresh()
			})
		}()
	}
	parts.clearBtn = widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), func() {
		u.logs.clear()
		u.refreshAllLogs()
	})

	title := widget.NewLabelWithStyle("Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	tools := []fyne.CanvasObject{widget.NewLabel("Level"), level, follow, layout.NewSpacer(), parts.copyBtn, parts.clearBtn}
	if expanded {
		parts.closeBtn = widget.NewButtonWithIcon("Close", theme.CancelIcon(), nil) // set by the window
		tools = append(tools, parts.closeBtn)
	} else {
		parts.expandBtn = widget.NewButtonWithIcon("Expand", theme.ViewFullScreenIcon(), u.showLogWindow)
		tools = append(tools, parts.expandBtn)
	}
	toolsRow = container.NewHBox(tools...)
	header := container.NewVBox(container.NewBorder(nil, nil, title, nil, search), toolsRow)

	// Every run is also kept in a file, to look at (or send) after the fact.
	var footer fyne.CanvasObject
	if path := applog.Path(); path != "" {
		where := widget.NewLabel("Saved to " + path)
		where.SizeName = theme.SizeNameCaptionText
		where.Truncation = fyne.TextTruncateEllipsis
		open := widget.NewButtonWithIcon("Open folder", theme.FolderOpenIcon(), func() {
			dir := filepath.ToSlash(filepath.Dir(path))
			if !strings.HasPrefix(dir, "/") {
				dir = "/" + dir // C:/Users/... -> file:///C:/Users/...
			}
			if err := u.app.OpenURL(&url.URL{Scheme: "file", Path: dir}); err != nil {
				u.logf("⚠️  could not open %s: %v", filepath.Dir(path), err)
			}
		})
		open.Importance = widget.LowImportance
		footer = container.NewBorder(nil, nil, nil, open, where)
	}
	refresh()
	return container.NewBorder(header, footer, nil, nil, list), refresh, parts
}

// showLogWindow opens the log in a large window of its own (or brings it to
// the front if it is open), with the same tools and a Close button.
func (u *ui) showLogWindow() {
	if u.logWindow != nil {
		u.logWindow.Show()
		u.logWindow.RequestFocus()
		return
	}
	w := u.app.NewWindow("MKConnect logs")
	content, refresh, parts := u.logPanel(w, true)
	id := u.addLogRefresher(refresh)
	closed := func() {
		u.removeLogRefresher(id)
		u.logWindow, u.logWindowParts = nil, nil
	}
	w.SetOnClosed(closed)
	parts.closeBtn.OnTapped = w.Close
	w.SetContent(content)
	w.Resize(fyne.NewSize(1000, 700))
	u.logWindow, u.logWindowParts = w, parts
	w.Show()
}

// addLogRefresher registers a log view to redraw when lines arrive; it
// returns an id for removeLogRefresher.
func (u *ui) addLogRefresher(f func()) int {
	if u.logRefreshers == nil {
		u.logRefreshers = map[int]func(){}
	}
	u.logRefresherID++
	u.logRefreshers[u.logRefresherID] = f
	return u.logRefresherID
}

func (u *ui) removeLogRefresher(id int) { delete(u.logRefreshers, id) }

// refreshAllLogs redraws every open log view.
func (u *ui) refreshAllLogs() {
	for _, f := range u.logRefreshers {
		f()
	}
}

// logRowHeight measures how tall a wrapped log line is at the list's current
// width, so rows that wrap over several lines are shown in full.
func (u *ui) logRowHeight(text string, list *widget.List, cache map[string]float32) float32 {
	width := list.Size().Width
	if width <= 0 {
		return 0 // not laid out yet; the default height is used
	}
	key := text
	if h, ok := cache[key]; ok {
		return h
	}
	size := theme.Size(theme.SizeNameCaptionText)
	inner := theme.Size(theme.SizeNameInnerPadding)
	avail := width - 4*inner
	one := fyne.MeasureText(text, size, fyne.TextStyle{})
	rows := float32(1)
	if avail > 0 && one.Width > avail {
		rows = float32(math.Ceil(float64(one.Width / avail)))
	}
	h := rows*one.Height + 2*inner
	if len(cache) > 4*maxLogLines {
		clear(cache) // the list scrolled far; start measuring again
	}
	cache[key] = h
	return h
}

// logRefreshInterval is how often the log view picks up new lines; tests make
// it long so the background refresh doesn't race the test driver.
var logRefreshInterval = 300 * time.Millisecond

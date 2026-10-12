package gui

import (
	"bufio"
	"log"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const maxLogLines = 2000

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

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

func (b *logBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dirty = false
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

// captureOutput redirects stdout, stderr and the standard logger into buf, so
// messages from the cores (which write to the process streams) show up in the
// window. Lines are still echoed to the original stderr.
func captureOutput(buf *logBuffer) {
	r, w, err := os.Pipe()
	if err != nil {
		log.Printf("log capture disabled: %v", err)
		return
	}
	orig := os.Stderr
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			orig.WriteString(line + "\n")
			buf.add(ansiEscape.ReplaceAllString(line, ""))
		}
	}()
}

// newLogView returns the log panel: wrapped lines, a search box, a log level
// picker and an auto-scroll toggle, refreshed a few times a second.
func (u *ui) newLogView() fyne.CanvasObject {
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
		d := dialog.NewCustom("Log line", "Close", container.NewVScroll(text), u.win)
		u.fitDialog(d, 700, 300)
		d.Show()
	}

	autoScroll := widget.NewCheck("", nil)
	autoScroll.SetChecked(true)
	search := widget.NewEntry()
	search.SetPlaceHolder("Filter…")

	refresh := func() {
		all := u.logs.snapshot()
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
		if autoScroll.Checked {
			list.ScrollToBottom()
		}
	}
	u.refreshLogs, u.logList, u.logSearch = refresh, list, search
	search.OnChanged = func(s string) {
		filter = strings.TrimSpace(s)
		refresh()
	}
	go func() {
		for range time.Tick(logRefreshInterval) {
			if u.logs.takeDirty() {
				fyne.Do(refresh)
			}
		}
	}()

	level := widget.NewSelect(logLevels, nil)
	u.logLevel = level
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

	clear := widget.NewButtonWithIcon("", theme.ContentClearIcon(), func() {
		u.logs.clear()
		refresh()
	})
	clear.Importance = widget.LowImportance
	copyAll := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		u.app.Clipboard().SetContent(strings.Join(u.logs.snapshot(), "\n"))
	})
	copyAll.Importance = widget.LowImportance

	title := widget.NewLabelWithStyle("Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	tools := container.NewHBox(widget.NewLabel("Level"), level, widget.NewLabel("Follow"), autoScroll, copyAll, clear)
	header := container.NewBorder(nil, nil, title, tools, search)
	return container.NewBorder(header, nil, nil, nil, list)
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

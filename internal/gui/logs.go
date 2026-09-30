package gui

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

const maxLogLines = 2000

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

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

// newLogView returns the log panel, refreshed a few times a second.
func (u *ui) newLogView() fyne.CanvasObject {
	var lines []string
	list := widget.NewList(
		func() int { return len(lines) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.SizeName = theme.SizeNameCaptionText
			l.Truncation = fyne.TextTruncateEllipsis
			return l
		},
		func(id widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(lines[id]) },
	)
	refresh := func() {
		lines = u.logs.snapshot()
		list.Refresh()
		list.ScrollToBottom()
	}
	go func() {
		for range time.Tick(300 * time.Millisecond) {
			if u.logs.takeDirty() {
				fyne.Do(refresh)
			}
		}
	}()

	clear := widget.NewButtonWithIcon("", theme.ContentClearIcon(), func() { u.logs.clear() })
	copyAll := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		u.app.Clipboard().SetContent(strings.Join(u.logs.snapshot(), "\n"))
	})
	header := container.NewBorder(nil, nil, widget.NewLabelWithStyle("Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), container.NewHBox(copyAll, clear))
	return container.NewBorder(header, nil, nil, nil, list)
}

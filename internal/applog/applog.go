// Package applog keeps the complete log of every run in a file, so a problem
// can be looked at after the fact: the app's own messages, everything the
// cores write to the process streams, and a crash report if the process dies.
//
// The files go next to the executable (a "logs" folder beside a portable
// MKConnect.exe), or, where that folder can't be written (Program Files,
// /usr/bin, inside a macOS app bundle), into the user's config folder:
//
//	Windows  %AppData%\mkconnect\logs
//	macOS    ~/Library/Application Support/mkconnect/logs
//	Linux    ~/.config/mkconnect/logs
//
// $MKCONNECT_LOG_DIR overrides both. The newest keepFiles files of each kind
// are kept.
package applog

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/khaliilii/MKConnect/internal/version"
)

const keepFiles = 20

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Dir returns the folder the log files are written to.
func Dir() string {
	if d := os.Getenv("MKCONNECT_LOG_DIR"); d != "" {
		return d
	}
	if d, ok := besideExecutable(); ok {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "mkconnect", "logs")
	}
	return filepath.Join(os.TempDir(), "mkconnect-logs")
}

// besideExecutable is the "logs" folder next to the program, when the program
// lives somewhere the user can write (a portable copy in Downloads, say).
func besideExecutable() (string, bool) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "android" || runtime.GOOS == "ios" {
		return "", false // inside a signed app bundle, or a phone's app storage
	}
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	dir := filepath.Join(filepath.Dir(exe), "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false
	}
	probe, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return "", false
	}
	probe.Close()
	os.Remove(probe.Name())
	return dir, true
}

var (
	mu      sync.Mutex
	current string
)

// Path returns the file this run logs to ("" before Start).
func Path() string {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// Start opens this run's log file (kind names it: "app", "cli", ...) and from
// then on copies into it everything the process logs: the standard logger and
// stdout/stderr, which the cores write to. Each line also goes to the original
// stderr and to every sink (the window's log view). A crash report goes to the
// file too. Returns the file's path; when the file can't be created, output
// still reaches stderr and the sinks.
func Start(kind string, sinks ...func(line string)) (string, error) {
	dir := Dir()
	var file *os.File
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		name := fmt.Sprintf("mkconnect-%s-%s.log", kind, time.Now().Format("20060102-150405"))
		file, err = os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	}
	if err == nil {
		prune(dir, kind)
		fmt.Fprintf(file, "MKConnect %s (%s) on %s/%s, %s, started %s\n",
			version.Version, kind, runtime.GOOS, runtime.GOARCH, runtime.Version(), time.Now().Format(time.RFC3339))
		// A panic or fatal error is written to the file as well: otherwise a
		// crash of a GUI app (no console on Windows) would leave no trace.
		debug.SetCrashOutput(file, debug.CrashOptions{})
		mu.Lock()
		current = file.Name()
		mu.Unlock()
	}

	r, w, perr := os.Pipe()
	if perr != nil {
		if file != nil {
			log.SetOutput(file)
		}
		return Path(), perr
	}
	orig := os.Stderr
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			raw := sc.Text()
			orig.WriteString(raw + "\n") // the terminal keeps its colours
			line := ansiEscape.ReplaceAllString(raw, "")
			if file != nil {
				file.WriteString(line + "\n")
			}
			for _, sink := range sinks {
				sink(line)
			}
		}
	}()
	if err != nil {
		return "", fmt.Errorf("log file: %w", err)
	}
	return Path(), nil
}

// prune deletes the oldest log files of a kind beyond keepFiles.
func prune(dir, kind string) {
	files, _ := filepath.Glob(filepath.Join(dir, "mkconnect-"+kind+"-*.log"))
	if len(files) <= keepFiles {
		return
	}
	slices.Sort(files) // the names carry the start time, so this is oldest first
	for _, f := range files[:len(files)-keepFiles] {
		if !strings.HasSuffix(f, ".log") {
			continue
		}
		os.Remove(f)
	}
}

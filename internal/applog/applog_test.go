package applog

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStartSavesEverything checks that the standard logger and the process
// streams (where the cores write) both reach the file, without colour codes,
// and that the sinks see the same lines.
func TestStartSavesEverything(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MKCONNECT_LOG_DIR", dir)
	oldOut, oldErr, oldLog := os.Stdout, os.Stderr, log.Writer()
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; log.SetOutput(oldLog) }()

	var seen []string
	done := make(chan struct{}, 8)
	path, err := Start("test", func(line string) {
		seen = append(seen, line)
		done <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("log file %s is not in %s", path, dir)
	}

	log.Print("from the app")
	fmt.Fprintln(os.Stderr, "\x1b[31mERROR\x1b[0m from a core")
	fmt.Fprintln(os.Stdout, "core stdout")
	for range 3 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("lines did not arrive; got %q", seen)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"MKConnect", "from the app", "ERROR from a core", "core stdout"} {
		if !strings.Contains(text, want) {
			t.Errorf("log file is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Error("colour codes were written to the file")
	}
	if Path() != path {
		t.Errorf("Path() = %q, want %q", Path(), path)
	}
}

func TestPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	for i := range keepFiles + 5 {
		name := fmt.Sprintf("mkconnect-app-20260101-%06d.log", i)
		os.WriteFile(filepath.Join(dir, name), nil, 0o600)
	}
	os.WriteFile(filepath.Join(dir, "mkconnect-cli-20250101-000000.log"), nil, 0o600)
	prune(dir, "app")

	left, _ := filepath.Glob(filepath.Join(dir, "mkconnect-app-*.log"))
	if len(left) != keepFiles {
		t.Fatalf("%d app logs left, want %d", len(left), keepFiles)
	}
	if _, err := os.Stat(filepath.Join(dir, "mkconnect-app-20260101-000000.log")); err == nil {
		t.Error("the oldest log was kept")
	}
	if _, err := os.Stat(filepath.Join(dir, "mkconnect-cli-20250101-000000.log")); err != nil {
		t.Error("a log of another kind was deleted")
	}
}

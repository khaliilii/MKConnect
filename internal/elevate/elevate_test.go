package elevate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// inProcess replaces the elevation prompt with running the helper in a goroutine.
func inProcess(t *testing.T) {
	t.Helper()
	orig := launch
	launch = func(exe, dir string) (<-chan error, error) {
		exited := make(chan error, 1)
		go func() { exited <- Serve(dir) }()
		return exited, nil
	}
	stdout, stderr := os.Stdout, os.Stderr
	t.Cleanup(func() { launch = orig; os.Stdout, os.Stderr = stdout, stderr })
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testRequest(t *testing.T) (profile.Profile, profile.Settings) {
	p := profile.Profile{Name: "nl", Type: profile.TypeTrojan, Server: "127.0.0.1", Port: 9, Password: "x", TLS: profile.TLS{Mode: "tls"}}
	s := profile.DefaultSettings()
	s.ListenPort = freePort(t)
	s.LogLevel = "error"
	return p, s
}

func TestRunThroughHelper(t *testing.T) {
	inProcess(t)
	p, s := testRequest(t)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan *engine.Session, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, p, s, engine.Hooks{OnStarted: func(sess *engine.Session) { started <- sess }})
	}()

	select {
	case sess := <-started:
		if !strings.Contains(sess.Outbound, "127.0.0.1:9") || sess.Core != "singbox" {
			t.Fatalf("session from helper: %+v", sess)
		}
		if _, _, ok := sess.Traffic(); !ok {
			time.Sleep(1500 * time.Millisecond) // first traffic update
			if _, _, ok := sess.Traffic(); !ok {
				t.Fatal("no traffic counters from the helper")
			}
		}
	case err := <-done:
		t.Fatalf("Run ended early: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("helper never reported running")
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ListenPort)))
	if err != nil {
		t.Fatalf("helper's proxy isn't listening: %v", err)
	}
	c.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("disconnect returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("helper didn't stop")
	}
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ListenPort))); err == nil {
		c.Close()
		t.Fatal("proxy still listening after disconnect")
	}
}

func TestHelperErrorIsReported(t *testing.T) {
	inProcess(t)
	p, s := testRequest(t)
	p.Transport.Network = "xhttp" // sing-box can't do xhttp
	err := Run(context.Background(), p, s, engine.Hooks{})
	if err == nil || !strings.Contains(err.Error(), "xhttp") {
		t.Fatalf("expected the helper's error, got %v", err)
	}
}

func TestDeniedPrompt(t *testing.T) {
	orig := launch
	defer func() { launch = orig }()
	launch = func(string, string) (<-chan error, error) { return nil, ErrDenied }
	p, s := testRequest(t)
	if err := Run(context.Background(), p, s, engine.Hooks{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("expected ErrDenied, got %v", err)
	}
}

func TestExternalCoreRefused(t *testing.T) {
	p, s := testRequest(t)
	s.Core, s.ExternalPath, s.ExternalKind = profile.CoreExternal, "/bin/sh", profile.CoreSingBox
	if err := Run(context.Background(), p, s, engine.Hooks{}); err == nil {
		t.Fatal("external core accepted for an elevated run")
	}
	// The helper refuses it too, even if a request is crafted by hand.
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	data, _ := json.Marshal(request{Profile: p, Settings: s})
	os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600)
	stdout, stderr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	if err := Serve(dir); err == nil {
		t.Fatal("helper ran an external core")
	}
}

func TestHelperStopsWhenAppExits(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skip("no `true` command")
	}
	deadPID := cmd.Process.Pid

	p, s := testRequest(t)
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	data, _ := json.Marshal(request{Profile: p, Settings: s, ParentPID: deadPID})
	os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600)
	stdout, stderr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()

	done := make(chan error, 1)
	go func() { done <- Serve(dir) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("helper kept running after the app exited")
	}
	if st, _ := readStatus(dir); st.State != stateStopped {
		t.Fatalf("final state %q", st.State)
	}
}

func TestPublicDirRejected(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o777)
	if err := checkDir(dir); err == nil && os.Getenv("GOOS") != "windows" {
		t.Fatal("world-writable helper directory accepted")
	}
}

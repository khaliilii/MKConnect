package elevate

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// helperDir is a private helper directory with a request from this process.
func helperDir(t *testing.T, seq int, s profile.Settings) string {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	p, _ := testRequest(t)
	data, _ := json.Marshal(request{Seq: seq, Profile: p, Settings: s, ParentPID: os.Getpid()})
	if err := os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	logOut := log.Writer()
	t.Cleanup(func() { log.SetOutput(logOut) })
	return dir
}

// fakeWorkers replaces the helper process: each call returns the next error
// and records whether it was asked to resume.
func fakeWorkers(t *testing.T, results ...error) *[]bool {
	t.Helper()
	orig := runWorker
	t.Cleanup(func() { runWorker = orig })
	var resumed []bool
	runWorker = func(dir string, resume bool, _ *os.File) error {
		resumed = append(resumed, resume)
		if len(resumed) > len(results) {
			t.Fatal("helper started again after it ended")
		}
		return results[len(resumed)-1]
	}
	return &resumed
}

// TestSupervisorRestartsACrashedHelper: a helper that crashes is started
// again, resuming its connection, without a new password prompt; the crash
// is in the log; a helper that ends normally ends the supervisor.
func TestSupervisorRestartsACrashedHelper(t *testing.T) {
	dir := helperDir(t, 4, profile.DefaultSettings())
	resumed := fakeWorkers(t, errors.New("exit status 2"), nil)
	if err := Supervise(dir); err != nil {
		t.Fatal(err)
	}
	if got := *resumed; len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("resume flags %v, want [false true]", got)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "helper.log"))
	if !strings.Contains(string(data), "crashed (exit status 2); starting it again") {
		t.Errorf("crash not logged: %q", data)
	}
}

// TestSupervisorGivesUp: a helper that keeps crashing is given up on, and
// the app is told through the status of its request.
func TestSupervisorGivesUp(t *testing.T) {
	dir := helperDir(t, 7, profile.DefaultSettings())
	crash := errors.New("exit status 2")
	resumed := fakeWorkers(t, crash, crash, crash)
	if err := Supervise(dir); err == nil {
		t.Fatal("no error after the helper kept crashing")
	}
	if len(*resumed) != maxCrashes {
		t.Errorf("started %d times, want %d", len(*resumed), maxCrashes)
	}
	st, err := readStatus(dir)
	if err != nil || st.State != stateError || st.Seq != 7 || !strings.Contains(st.Error, "crashed 3 times") {
		t.Fatalf("status %+v, %v", st, err)
	}
}

// TestSupervisorStopsWhenTheAppQuit: a helper that ends badly after the app
// asked it to quit is not started again.
func TestSupervisorStopsWhenTheAppQuit(t *testing.T) {
	dir := helperDir(t, 1, profile.DefaultSettings())
	os.WriteFile(filepath.Join(dir, "quit"), nil, 0o600)
	resumed := fakeWorkers(t, errors.New("signal: killed"))
	if err := Supervise(dir); err != nil {
		t.Fatal(err)
	}
	if len(*resumed) != 1 {
		t.Errorf("started %d times after quit", len(*resumed))
	}
}

// TestResumedHelperRunsTheRequest: a helper started again after a crash runs
// the request at once, without waiting for the app to say start; one the app
// asked to stop meanwhile is not run.
func TestResumedHelperRunsTheRequest(t *testing.T) {
	stdout, stderr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	refused := profile.DefaultSettings()
	refused.Core, refused.ExternalPath, refused.ExternalKind = profile.CoreExternal, "/bin/sh", profile.CoreSingBox

	dir := helperDir(t, 5, refused)
	os.WriteFile(filepath.Join(dir, "quit"), nil, 0o600) // ends the helper once the request is done
	serve(dir, true)
	if st, _ := readStatus(dir); st.Seq != 5 || !strings.Contains(st.Error, "external core") {
		t.Errorf("resumed request not run: %+v", st)
	}

	dir = helperDir(t, 5, refused)
	os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "quit"), nil, 0o600)
	serve(dir, true)
	if st, _ := readStatus(dir); st.Seq == 5 || st.State != stateExited {
		t.Errorf("a request stopped meanwhile was run: %+v", st)
	}
}

// TestHelperReleasesTheKillSwitch: the helper lifts the kill switch when the
// app says the user ended the connection, and when it exits; not before.
func TestHelperReleasesTheKillSwitch(t *testing.T) {
	stdout, stderr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	old := releaseKillSwitch
	defer func() { releaseKillSwitch = old }()
	var releases atomic.Int32
	releaseKillSwitch = func() { releases.Add(1) }

	dir := helperDir(t, 0, profile.DefaultSettings())
	done := make(chan error, 1)
	go func() { done <- serve(dir, false) }()
	waitUntil(t, func() bool { st, err := readStatus(dir); return err == nil && st.State == stateIdle })
	if n := releases.Load(); n != 0 {
		t.Fatalf("released %d times while idle", n)
	}
	os.WriteFile(filepath.Join(dir, "release"), nil, 0o600)
	waitUntil(t, func() bool { return releases.Load() == 1 })
	if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
		t.Error("the release request is still there")
	}
	os.WriteFile(filepath.Join(dir, "quit"), nil, 0o600)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := releases.Load(); n != 2 {
		t.Errorf("released %d times in all, want 2 (asked, exit)", n)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

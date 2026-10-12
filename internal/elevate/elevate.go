// Package elevate runs the tunnel in a privileged helper process, so the
// desktop app itself never needs root or Administrator rights.
//
// TUN mode (and gateway sharing) must create network interfaces and routes,
// which needs root on macOS/Linux and Administrator on Windows. When the app
// isn't elevated, Run asks the operating system for permission (password
// dialog, UAC or polkit) once and starts the same executable with HelperFlag.
// The helper then stays for the app's lifetime, idle between connections, so
// switching accounts or reconnecting doesn't prompt again. The two processes
// talk through files in a private directory:
//
//	request.json  app → helper  what to run (with a sequence number)
//	start         app → helper  run the request
//	status.json   helper → app  state, sequence, session info, traffic counters
//	helper.log    helper → app  core logs
//	stop          app → helper  disconnect
//	quit          app → helper  exit
//
// The helper also exits on its own when the app process goes away.
package elevate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// HelperFlag makes the executable run as the privileged helper:
//
//	MKConnect --tun-helper <dir>
const HelperFlag = "--tun-helper"

// Helper states.
const (
	stateIdle     = "idle" // waiting for a request
	stateStarting = "starting"
	stateRunning  = "running"
	stateStopped  = "stopped"
	stateError    = "error"
	stateExited   = "exited"
)

type request struct {
	Seq       int              `json:"seq"`
	Profile   profile.Profile  `json:"profile"`
	Settings  profile.Settings `json:"settings"`
	ParentPID int              `json:"parent_pid"`
}

type status struct {
	State     string    `json:"state"`
	Seq       int       `json:"seq"` // of the request the state is about
	PID       int       `json:"pid"`
	Error     string    `json:"error,omitempty"`
	HostKey   string    `json:"host_key,omitempty"`
	Core      string    `json:"core,omitempty"`
	Inbounds  []string  `json:"inbounds,omitempty"`
	Outbound  string    `json:"outbound,omitempty"`
	Up        int64     `json:"up"`
	Down      int64     `json:"down"`
	TrafficOK bool      `json:"traffic_ok"`
	Updated   time.Time `json:"updated"`
	// Health is the result of the helper's last internet check; HealthSeq
	// counts the checks, so the app notices a new one.
	HealthSeq int    `json:"health_seq,omitempty"`
	HealthMS  int64  `json:"health_ms,omitempty"`
	HealthErr string `json:"health_err,omitempty"`
}

// ErrDenied means the user declined the permission prompt.
var ErrDenied = errors.New("administrator permission was not granted; TUN mode needs it to create the virtual network interface")

const (
	promptTimeout = 3 * time.Minute // time to type the password
	startTimeout  = 30 * time.Second
	pollInterval  = 300 * time.Millisecond
)

// launch starts the helper with elevated rights; replaced in tests.
var launch = launchElevated

// helper is the running privileged process, shared by all connections of the app.
type helper struct {
	dir    string
	exited <-chan error // from the launcher, when it reports the helper's end
	seq    int
	dead   bool
}

var (
	mu      sync.Mutex
	current *helper
)

// Run behaves like engine.Run, but the core runs in the elevated helper.
func Run(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
	if s.Core == profile.CoreExternal {
		return fmt.Errorf("TUN mode without administrator rights can't use an external core binary (it would run as root); choose sing-box or Xray")
	}
	h, err := acquire()
	if err != nil {
		return err
	}
	mu.Lock()
	h.seq++
	seq := h.seq
	mu.Unlock()
	dir := h.dir

	data, err := json.Marshal(request{Seq: seq, Profile: p, Settings: s, ParentPID: os.Getpid()})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600); err != nil {
		return err
	}
	os.Remove(filepath.Join(dir, "stop"))
	stopLogs := tailLog(filepath.Join(dir, "helper.log"))
	defer stopLogs()
	if err := os.WriteFile(filepath.Join(dir, "start"), nil, 0o600); err != nil {
		return err
	}

	var (
		st         status
		started    bool
		lastHealth int
		begin      = time.Now()
		stopAt     time.Time
	)
	stop := func() {
		if stopAt.IsZero() {
			os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
			stopAt = time.Now()
		}
	}
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stop()
		case err := <-h.exited:
			markDead(h)
			if errors.Is(err, ErrDenied) {
				return err
			}
			if cur, rerr := readStatus(dir); rerr != nil || cur.Seq != seq || cur.State == stateRunning || cur.State == stateStarting {
				return fmt.Errorf("the TUN helper exited unexpectedly")
			}
		case <-tick.C:
		}

		if cur, err := readStatus(dir); err == nil && cur.Seq == seq {
			st = cur
		}
		if st.HealthSeq > lastHealth && hooks.OnHealth != nil {
			lastHealth = st.HealthSeq
			var herr error
			if st.HealthErr != "" {
				herr = errors.New(st.HealthErr)
			}
			hooks.OnHealth(time.Duration(st.HealthMS)*time.Millisecond, herr)
		}
		switch st.State {
		case stateRunning:
			if !started {
				started = true
				if st.HostKey != "" && hooks.OnHostKey != nil {
					hooks.OnHostKey(st.HostKey)
				}
				if hooks.OnStarted != nil {
					hooks.OnStarted(engine.NewSession(st.Core, st.Inbounds, st.Outbound, func() (int64, int64, bool) {
						cur, err := readStatus(dir)
						return cur.Up, cur.Down, err == nil && cur.Seq == seq && cur.TrafficOK
					}))
				}
			}
		case stateStopped:
			return nil
		case stateError:
			return errors.New(st.Error)
		}

		switch {
		case !stopAt.IsZero() && time.Since(stopAt) > 10*time.Second:
			markDead(h)
			return fmt.Errorf("the TUN helper didn't stop in time")
		case st.State == "" && time.Now().After(begin.Add(startTimeout)):
			markDead(h)
			return fmt.Errorf("the TUN helper didn't respond")
		case started && time.Since(st.Updated) > 10*time.Second:
			markDead(h)
			return fmt.Errorf("the TUN helper stopped responding")
		}
	}
}

// acquire returns the running helper, or starts one (permission prompt).
func acquire() (*helper, error) {
	mu.Lock()
	defer mu.Unlock()
	if current != nil && !current.dead {
		if st, err := readStatus(current.dir); err == nil && st.PID > 0 && processAlive(st.PID) && st.State != stateExited {
			return current, nil
		}
		os.RemoveAll(current.dir)
		current = nil
	}
	dir, err := os.MkdirTemp("", "mkconnect-helper-")
	if err != nil {
		return nil, err
	}
	// The helper starts idle; the first request only tells it which app to watch.
	data, _ := json.Marshal(request{ParentPID: os.Getpid()})
	if err := os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	log.Printf("🔐 TUN mode needs administrator rights; asking the system for permission (once per app run)...")
	exited, err := launch(exe, dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	h := &helper{dir: dir, exited: exited}
	deadline := time.Now().Add(promptTimeout)
	for {
		if st, err := readStatus(dir); err == nil && st.PID > 0 {
			current = h
			return h, nil
		}
		select {
		case err := <-h.exited:
			os.RemoveAll(dir)
			if errors.Is(err, ErrDenied) || err == nil {
				return nil, ErrDenied
			}
			return nil, err
		case <-time.After(pollInterval):
		}
		if time.Now().After(deadline) {
			os.RemoveAll(dir)
			return nil, ErrDenied
		}
	}
}

func markDead(h *helper) {
	mu.Lock()
	defer mu.Unlock()
	h.dead = true
	if current == h {
		current = nil
	}
}

// Shutdown ends the helper, if one is running. Called when the app quits.
func Shutdown() {
	mu.Lock()
	h := current
	current = nil
	mu.Unlock()
	if h == nil {
		return
	}
	os.WriteFile(filepath.Join(h.dir, "quit"), nil, 0o600)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := readStatus(h.dir); err != nil || st.State == stateExited || !processAlive(st.PID) {
			break
		}
		time.Sleep(pollInterval)
	}
	os.RemoveAll(h.dir)
}

func readStatus(dir string) (status, error) {
	var st status
	data, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(data, &st)
	return st, err
}

// tailLog copies what the helper appends to its log from now on into this
// process's log output (which the GUI shows) until the returned function is
// called.
func tailLog(path string) func() {
	done := make(chan struct{})
	var offset int64
	if fi, err := os.Stat(path); err == nil {
		offset = fi.Size() // earlier connections' output was shown already
	}
	go func() {
		var f *os.File
		buf := make([]byte, 32<<10)
		for {
			select {
			case <-done:
				if f != nil {
					f.Close()
				}
				return
			case <-time.After(pollInterval):
			}
			if f == nil {
				var err error
				if f, err = os.Open(path); err != nil {
					f = nil
					continue
				}
				f.Seek(offset, 0)
			}
			for {
				n, err := f.Read(buf)
				if n > 0 {
					log.Writer().Write(buf[:n])
				}
				if err != nil || n == 0 {
					break
				}
			}
		}
	}()
	return func() { close(done) }
}

// Serve is the privileged helper: it runs requests until told to quit or
// until the app that started it exits. A request without an app to watch
// (parent pid 0) is run once.
func Serve(dir string) error {
	if err := checkDir(dir); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "helper.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	redirectOutput(logFile)
	log.SetOutput(logFile)

	st := &statusWriter{dir: dir, pid: os.Getpid()}
	req, err := readRequest(dir)
	if err != nil {
		return st.fail(0, err)
	}
	parent := req.ParentPID
	once := parent == 0 // no app to watch: a single request
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil }
	gone := func() bool { return exists("quit") || (parent > 0 && !processAlive(parent)) }

	st.set(func(s *status) { s.State = stateIdle })
	lastSeq := 0
	for {
		// Wait for a request to run.
		if !once {
			for !exists("start") {
				if gone() {
					log.Printf("MKConnect exited; helper done")
					st.set(func(s *status) { s.State = stateExited })
					return nil
				}
				time.Sleep(pollInterval)
			}
			os.Remove(filepath.Join(dir, "start"))
			if req, err = readRequest(dir); err != nil {
				st.fail(lastSeq+1, err)
				continue
			}
			if req.Seq <= lastSeq {
				continue // already handled
			}
		}
		lastSeq = req.Seq
		err := serveOne(dir, st, req, gone)
		if once {
			return err
		}
	}
}

// serveOne runs one request until it is stopped.
func serveOne(dir string, st *statusWriter, req request, gone func() bool) error {
	seq := req.Seq
	if req.Settings.Core == profile.CoreExternal {
		return st.fail(seq, errors.New("refusing to run an external core binary as root"))
	}
	os.Remove(filepath.Join(dir, "stop"))
	st.set(func(s *status) { *s = status{State: stateStarting, Seq: seq, PID: s.PID} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		t := time.NewTicker(pollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				log.Printf("disconnect requested")
				cancel()
				return
			}
			if gone() {
				log.Printf("MKConnect exited; stopping the tunnel")
				cancel()
				return
			}
		}
	}()

	var session *engine.Session
	stopTraffic := make(chan struct{})
	defer close(stopTraffic)
	err := engine.Run(ctx, req.Profile, req.Settings, engine.Hooks{
		OnHostKey: func(key string) { st.set(func(s *status) { s.HostKey = key }) },
		OnHealth: func(latency time.Duration, herr error) {
			st.set(func(s *status) {
				s.HealthSeq, s.HealthMS, s.HealthErr = s.HealthSeq+1, latency.Milliseconds(), ""
				if herr != nil {
					s.HealthErr = herr.Error()
				}
			})
		},
		OnStarted: func(s *engine.Session) {
			session = s
			st.set(func(x *status) {
				x.State, x.Core, x.Inbounds, x.Outbound = stateRunning, s.Core, s.Inbounds, s.Outbound
			})
			go func() {
				t := time.NewTicker(time.Second)
				defer t.Stop()
				for {
					select {
					case <-stopTraffic:
						return
					case <-t.C:
					}
					up, down, ok := session.Traffic()
					st.set(func(x *status) { x.Up, x.Down, x.TrafficOK = up, down, ok })
				}
			}()
		},
	})
	os.Remove(filepath.Join(dir, "stop"))
	if err != nil {
		return st.fail(seq, err)
	}
	st.set(func(s *status) { s.State = stateStopped })
	return nil
}

func readRequest(dir string) (request, error) {
	var req request
	data, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		return req, err
	}
	err = json.Unmarshal(data, &req)
	return req, err
}

// statusWriter publishes the helper status atomically.
type statusWriter struct {
	dir string
	pid int
	mu  sync.Mutex
	cur status
}

func (w *statusWriter) set(f func(*status)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f(&w.cur)
	w.cur.PID = w.pid
	w.cur.Updated = time.Now()
	data, _ := json.Marshal(w.cur)
	tmp := filepath.Join(w.dir, "status.json.tmp")
	if os.WriteFile(tmp, data, 0o644) == nil {
		os.Rename(tmp, filepath.Join(w.dir, "status.json"))
	}
}

func (w *statusWriter) fail(seq int, err error) error {
	log.Printf("❌ %v", err)
	w.set(func(s *status) { *s = status{State: stateError, Seq: seq, Error: err.Error()} })
	return err
}

// redirectOutput sends the cores' stdout/stderr output into the helper log.
func redirectOutput(f *os.File) {
	os.Stdout, os.Stderr = f, f
}

// Package elevate runs the tunnel in a privileged helper process, so the
// desktop app itself never needs root or Administrator rights.
//
// TUN mode (and gateway sharing) must create network interfaces and routes,
// which needs root on macOS/Linux and Administrator on Windows. When the app
// isn't elevated, Run asks the operating system for permission (password
// dialog, UAC or polkit) and starts the same executable with HelperFlag. The
// two processes talk through files in a private directory:
//
//	request.json  app → helper  what to run
//	status.json   helper → app  state, session info, traffic counters
//	helper.log    helper → app  core logs
//	stop          app → helper  disconnect
//
// The helper also stops on its own when the app process goes away.
package elevate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	stateStarting = "starting"
	stateRunning  = "running"
	stateStopped  = "stopped"
	stateError    = "error"
)

type request struct {
	Profile   profile.Profile  `json:"profile"`
	Settings  profile.Settings `json:"settings"`
	ParentPID int              `json:"parent_pid"`
}

type status struct {
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	HostKey   string    `json:"host_key,omitempty"`
	Core      string    `json:"core,omitempty"`
	Inbounds  []string  `json:"inbounds,omitempty"`
	Outbound  string    `json:"outbound,omitempty"`
	Up        int64     `json:"up"`
	Down      int64     `json:"down"`
	TrafficOK bool      `json:"traffic_ok"`
	Updated   time.Time `json:"updated"`
}

// ErrDenied means the user declined the permission prompt.
var ErrDenied = errors.New("administrator permission was not granted; TUN mode needs it to create the virtual network interface")

const (
	promptTimeout = 3 * time.Minute // time to type the password
	pollInterval  = 300 * time.Millisecond
)

// launch starts the helper with elevated rights; replaced in tests.
var launch = launchElevated

// Run behaves like engine.Run, but the core runs in an elevated helper.
func Run(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
	if s.Core == profile.CoreExternal {
		return fmt.Errorf("TUN mode without administrator rights can't use an external core binary (it would run as root); choose sing-box or Xray")
	}
	dir, err := os.MkdirTemp("", "mkconnect-helper-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	data, err := json.Marshal(request{Profile: p, Settings: s, ParentPID: os.Getpid()})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	log.Printf("🔐 TUN mode needs administrator rights; asking the system for permission...")
	exited, err := launch(exe, dir)
	if err != nil {
		return err
	}

	stopLogs := tailLog(filepath.Join(dir, "helper.log"))
	defer stopLogs()

	var (
		st       status
		started  bool
		deadline = time.Now().Add(promptTimeout)
		stopAt   time.Time
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
		case err := <-exited:
			// The launcher (pkexec) returns when the helper ends.
			if errors.Is(err, ErrDenied) {
				return err
			}
			exited = nil
		case <-tick.C:
		}

		if cur, err := readStatus(dir); err == nil {
			st = cur
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
						return cur.Up, cur.Down, err == nil && cur.TrafficOK
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
			return fmt.Errorf("the TUN helper didn't stop in time")
		case st.State == "" && time.Now().After(deadline):
			return ErrDenied
		case started && time.Since(st.Updated) > 10*time.Second:
			return fmt.Errorf("the TUN helper stopped responding")
		}
	}
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

// tailLog copies the helper's log into this process's log output (which the
// GUI shows) until the returned function is called.
func tailLog(path string) func() {
	done := make(chan struct{})
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

// Serve is the privileged helper: it runs the requested profile until told to
// stop or until the app that started it exits.
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

	st := &statusWriter{dir: dir}
	st.set(func(s *status) { s.State = stateStarting })

	data, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		return st.fail(err)
	}
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		return st.fail(err)
	}
	if req.Settings.Core == profile.CoreExternal {
		return st.fail(errors.New("refusing to run an external core binary as root"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		t := time.NewTicker(pollInterval)
		defer t.Stop()
		for range t.C {
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				log.Printf("disconnect requested")
				cancel()
				return
			}
			if req.ParentPID > 0 && !processAlive(req.ParentPID) {
				log.Printf("MKConnect exited; stopping the tunnel")
				cancel()
				return
			}
		}
	}()

	var session *engine.Session
	stopTraffic := make(chan struct{})
	defer close(stopTraffic)
	err = engine.Run(ctx, req.Profile, req.Settings, engine.Hooks{
		OnHostKey: func(key string) { st.set(func(s *status) { s.HostKey = key }) },
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
	if err != nil {
		return st.fail(err)
	}
	st.set(func(s *status) { s.State = stateStopped })
	return nil
}

// statusWriter publishes the helper status atomically.
type statusWriter struct {
	dir string
	cur status
}

func (w *statusWriter) set(f func(*status)) {
	f(&w.cur)
	w.cur.Updated = time.Now()
	data, _ := json.Marshal(w.cur)
	tmp := filepath.Join(w.dir, "status.json.tmp")
	if os.WriteFile(tmp, data, 0o644) == nil {
		os.Rename(tmp, filepath.Join(w.dir, "status.json"))
	}
}

func (w *statusWriter) fail(err error) error {
	log.Printf("❌ %v", err)
	w.set(func(s *status) { s.State, s.Error = stateError, err.Error() })
	return err
}

// redirectOutput sends the cores' stdout/stderr output into the helper log.
func redirectOutput(f *os.File) {
	os.Stdout, os.Stderr = f, f
}

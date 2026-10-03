// Package recovery undoes what a crashed connection left in the system.
//
// A clean disconnect restores everything by itself. If the process is killed
// instead (kill -9, power loss of the app, a crash), TUN routing rules,
// sing-box's nftables table and changed settings such as IP forwarding would
// stay behind. To recover, a connection that changes system state first writes
// a journal: the original values it is about to change and, on Linux, the
// routing rules that existed before. The journal is removed on a clean stop.
// Recover, run before the next TUN connection or by `mkconnect cleanup`,
// restores whatever a journal of a dead process still describes.
package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Journal is the state of one running connection.
type Journal struct {
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`

	// Original values of settings the gateway changed ("" = unchanged).
	IPForward     string `json:"ip_forward,omitempty"`     // Linux net.ipv4.ip_forward
	MacForwarding string `json:"mac_forwarding,omitempty"` // macOS net.inet.ip.forwarding
	ICSPublic     string `json:"ics_public,omitempty"`     // Windows ICS adapters
	ICSPrivate    string `json:"ics_private,omitempty"`

	// Linux: policy routing rules present before the TUN started.
	Rules []Rule `json:"rules,omitempty"`
}

// Rule identifies a policy routing rule.
type Rule struct {
	Family   int    `json:"family"`
	Priority int    `json:"priority"`
	Table    int    `json:"table"`
	Mark     uint32 `json:"mark,omitempty"`
	Invert   bool   `json:"invert,omitempty"`
	Goto     int    `json:"goto,omitempty"`
}

var (
	mu      sync.Mutex
	current *Journal
)

func path() string { return filepath.Join(stateDir(), "journal.json") }

// Begin records the system state before a TUN connection changes it. It
// returns a function to call after a clean stop. Failing to write the journal
// (e.g. no permission) only disables crash recovery.
func Begin() (end func(), err error) {
	j := &Journal{PID: os.Getpid(), Started: time.Now()}
	j.Rules, err = currentRules()
	if err != nil {
		return func() {}, err
	}
	mu.Lock()
	current = j
	err = saveLocked()
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		current = nil
		os.Remove(path())
	}, err
}

// Record updates the running connection's journal (e.g. an original setting
// about to be changed). It is a no-op when no journal is active.
func Record(update func(*Journal)) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return
	}
	update(current)
	saveLocked()
}

func saveLocked() error {
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(current)
	if err != nil {
		return err
	}
	tmp := path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path())
}

// ErrRunning means the journal belongs to a connection that is still running.
var ErrRunning = errors.New("another MKConnect connection is running")

// Recover undoes what a crashed connection left behind. It returns what was
// cleaned (empty when there was nothing to do).
func Recover() ([]string, error) {
	data, err := os.ReadFile(path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(data, &j); err != nil {
		os.Remove(path())
		return nil, fmt.Errorf("unreadable journal removed: %w", err)
	}
	if j.PID != os.Getpid() && processAlive(j.PID) {
		return nil, ErrRunning
	}
	cleaned, err := undo(&j)
	if err == nil {
		os.Remove(path())
	}
	return cleaned, err
}

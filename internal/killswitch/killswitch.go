// Package killswitch keeps traffic from leaving the computer outside the
// tunnel while a TUN connection is meant to be up: after a drop and until the
// reconnect, while failover moves to another account, and when a core or the
// helper crashes. Without it, the system's routes fall back to the network
// itself for those seconds, and apps carry on without the tunnel.
//
// It is the operating system's own firewall (pf on macOS, nftables on Linux,
// WFP on Windows), so it holds whatever happens to the cores. While it is
// engaged, only these get out:
//
//   - the tunnel's interface, loopback and DHCP;
//   - the cores' own connections: to the server, and what they send straight
//     out (Iranian sites with DirectIran, the local network). macOS and Linux
//     tell them by the group the process switches to (Group), Windows by the
//     program;
//   - macOS and Linux: name lookups (port 53, so the next reconnect can look
//     its server up; no data goes with them) and the local network (printers,
//     the router, devices using the shared proxy).
//
// The kill switch outlives a connection by design: Engage again for the next
// one and Release when the user disconnects. A process that dies engaged
// leaves the block behind (macOS and Linux; Windows removes it with the
// process): Leftover tells, Cleanup removes it.
package killswitch

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Group is the group ID a process takes when it engages the kill switch
// (macOS and Linux): the firewall lets sockets of this group out, and the
// cores' sockets, opened afterwards, are of it.
const Group = 19787 // "MK"

// ErrUnsupported means this system has no kill switch.
var ErrUnsupported = errors.New("the kill switch isn't available on this system")

var (
	mu      sync.Mutex
	engaged bool
	shown   string // the tunnel interface the rules let through
)

// The system's side, per platform; replaced in tests.
var (
	engage   = engageRules
	release  = releaseRules
	stateDir = defaultStateDir
)

// Engage blocks everything that doesn't leave by tun (the tunnel's interface;
// "" while there is none) or from the cores. Called again, it replaces the
// rules: on macOS and Linux in one step, on Windows with a moment between.
func Engage(tun string) error {
	mu.Lock()
	defer mu.Unlock()
	if engaged && shown == tun {
		return nil
	}
	if err := engage(tun); err != nil {
		return err
	}
	if !engaged {
		log.Printf("🔒 kill switch on: nothing gets out without the tunnel")
	}
	engaged, shown = true, tun
	return nil
}

// Release lifts the block. It does nothing when this process hasn't engaged it.
func Release() error {
	mu.Lock()
	defer mu.Unlock()
	if !engaged {
		return nil
	}
	if err := release(); err != nil {
		return err
	}
	engaged, shown = false, ""
	log.Printf("🔓 kill switch off: the internet works without the tunnel again")
	return nil
}

// Engaged reports whether this process holds the block.
func Engaged() bool {
	mu.Lock()
	defer mu.Unlock()
	return engaged
}

// Leftover reports whether a process that has ended left the block behind:
// then nothing reaches the internet until Cleanup. Needs no rights.
func Leftover() bool {
	st, err := readState()
	return err == nil && st.PID != os.Getpid() && !processAlive(st.PID)
}

// Cleanup removes a block a process that has ended left behind (needs root).
// It reports whether there was one.
func Cleanup() (bool, error) {
	if !Leftover() {
		return false, nil
	}
	mu.Lock()
	defer mu.Unlock()
	if err := release(); err != nil {
		return true, err
	}
	engaged, shown = false, ""
	return true, nil
}

// state is what an engaged process leaves for Leftover and Cleanup, and for
// the process that takes over after a crash.
type state struct {
	PID int `json:"pid"`
	// Token is pf's reference for enabling it (macOS): releasing it turns pf
	// off again, unless something else had it on.
	Token string `json:"token,omitempty"`
}

// statePath is readable without rights: Leftover runs in the app.
func statePath() string { return filepath.Join(stateDir(), "mkconnect-killswitch.json") }

func readState() (state, error) {
	var st state
	data, err := os.ReadFile(statePath())
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(data, &st)
	return st, err
}

func writeState(st state) error {
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	// Readable by the app: Leftover runs without rights.
	tmp := statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, statePath())
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Package engine runs a profile through one of the supported cores (sing-box,
// Xray, an external binary, or the built-in SSH client) in proxy or TUN mode.
package engine

import "encoding/json"

// Engine is a running core.
type Engine interface {
	Close() error
}

// waiter is implemented by engines that can stop on their own (e.g. an external
// process exiting or the SSH server going away for good).
type waiter interface {
	Done() <-chan error
}

// Library cores are registered by build-tagged files so either can be left out
// of the binary with -tags no_singbox / -tags no_xray.
var (
	startSingBox func(config []byte) (Engine, error)
	startXray    func(config []byte) (Engine, error)
	parseSingBox func(config []byte) error // validates a config without starting it
)

// Available reports which cores were compiled into this binary.
func Available() []string {
	var cores []string
	if startSingBox != nil {
		cores = append(cores, "singbox")
	}
	if startXray != nil {
		cores = append(cores, "xray")
	}
	return append(cores, "external", "ssh (built-in)")
}

func marshal(cfg obj) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

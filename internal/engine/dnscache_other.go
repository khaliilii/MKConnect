//go:build !darwin && !windows && (!linux || android)

package engine

import "os/exec"

// Android's VpnService and other systems handle their own resolver state.
func flushCommands() [][]string { return nil }

func hideWindow(*exec.Cmd) {}

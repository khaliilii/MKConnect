package engine

import "os/exec"

func flushCommands() [][]string {
	return [][]string{{"dscacheutil", "-flushcache"}, {"killall", "-HUP", "mDNSResponder"}}
}

func hideWindow(*exec.Cmd) {}

//go:build linux && !android

package engine

import "os/exec"

// systemd-resolved is the common cache; without it, glibc doesn't cache.
func flushCommands() [][]string { return [][]string{{"resolvectl", "flush-caches"}} }

func hideWindow(*exec.Cmd) {}

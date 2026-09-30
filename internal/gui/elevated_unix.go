//go:build !windows

package gui

import "os"

func isElevated() bool { return os.Geteuid() == 0 }

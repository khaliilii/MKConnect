package engine

import (
	"os/exec"
	"syscall"
)

func flushCommands() [][]string { return [][]string{{"ipconfig", "/flushdns"}} }

// hideWindow keeps a console window from flashing up from the GUI.
func hideWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

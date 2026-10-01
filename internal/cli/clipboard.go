package cli

import (
	"errors"
	"os/exec"
	"runtime"
)

// readClipboard returns the system clipboard text using the platform's tool.
func readClipboard() (string, error) {
	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"pbpaste"}}
	case "windows":
		candidates = [][]string{{"powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"}}
	case "android":
		candidates = [][]string{{"termux-clipboard-get"}}
	default:
		candidates = [][]string{{"wl-paste", "--no-newline"}, {"xclip", "-selection", "clipboard", "-o"}, {"xsel", "--clipboard", "--output"}}
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		out, err := exec.Command(c[0], c[1:]...).Output()
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
	return "", errors.New("no clipboard tool found (install wl-clipboard, xclip or xsel)")
}

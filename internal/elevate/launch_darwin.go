package elevate

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// launchElevated shows the macOS administrator password dialog and starts the
// helper as root in the background.
func launchElevated(exe, dir string) (<-chan error, error) {
	script := fmt.Sprintf(`do shell script (quoted form of %s) & " %s " & (quoted form of %s) & " >/dev/null 2>&1 &" `+
		`with administrator privileges with prompt "MKConnect needs administrator rights to create the TUN virtual network interface."`,
		appleString(exe), HelperFlag, appleString(dir))
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "-128") { // "User canceled."
			return nil, ErrDenied
		}
		return nil, fmt.Errorf("start TUN helper: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil, nil
}

func appleString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// RunElevated runs this executable once with administrator rights (the
// system's password prompt) and waits for it, returning its output.
func RunElevated(prompt string, args ...string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := "quoted form of " + appleString(exe)
	for _, a := range args {
		cmd += ` & " " & quoted form of ` + appleString(a)
	}
	script := fmt.Sprintf(`do shell script (%s) & " 2>&1" with administrator privileges with prompt %s`, cmd, appleString(prompt))
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "-128") {
			return "", ErrDenied
		}
		return strings.TrimSpace(string(out)), fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

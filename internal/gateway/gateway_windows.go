package gateway

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// On Windows, Internet Connection Sharing shares the TUN adapter (public side)
// with each chosen adapter (private side): it forwards, NATs and runs DHCP, so
// devices plugged into those adapters need no settings.
func enable(s *Session, shared []string, tunName string) error {
	if len(shared) > 1 {
		return fmt.Errorf("Windows Internet Connection Sharing can share with only one adapter at a time")
	}
	script := fmt.Sprintf(icsScript, psQuote(tunName), psQuote(shared[0]), "$true")
	if err := powershell(script); err != nil {
		return fmt.Errorf("enable Internet Connection Sharing (needs Administrator): %w", err)
	}
	s.onStop(func() error {
		return powershell(fmt.Sprintf(icsScript, psQuote(tunName), psQuote(shared[0]), "$false"))
	})
	return nil
}

// icsScript enables (or disables) ICS from adapter {0} to adapter {1}.
const icsScript = `
$ErrorActionPreference = 'Stop'
$m = New-Object -ComObject HNetCfg.HNetShare
function Find($name) {
  foreach ($c in $m.EnumEveryConnection) { if ($m.NetConnectionProps.Invoke($c).Name -eq $name) { return $c } }
  throw "adapter not found: $name"
}
$public  = $m.INetSharingConfigurationForINetConnection.Invoke((Find %s))
$private = $m.INetSharingConfigurationForINetConnection.Invoke((Find %s))
if (%s) {
  # Only one ICS pair can exist; clear any previous one first.
  foreach ($c in $m.EnumEveryConnection) {
    $cfg = $m.INetSharingConfigurationForINetConnection.Invoke($c)
    if ($cfg.SharingEnabled) { $cfg.DisableSharing() }
  }
  $public.EnableSharing(0)
  $private.EnableSharing(1)
} else {
  $private.DisableSharing()
  $public.DisableSharing()
}
`

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func powershell(script string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hint(shared []string) string {
	return "Devices plugged into " + strings.Join(shared, ", ") +
		" get an address automatically (192.168.137.x) and use the tunnel. Only one adapter can be shared."
}

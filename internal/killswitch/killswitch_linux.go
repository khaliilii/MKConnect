package killswitch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Not /run/mkconnect: the crash journal's folder is root's alone.
func defaultStateDir() string {
	if fi, err := os.Stat("/run"); err == nil && fi.IsDir() {
		return "/run" // tmpfs: cleared on reboot, like the rules
	}
	return "/var/run"
}

func engageRules(tun string) error {
	if err := syscall.Setgid(Group); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	if err := writeState(state{PID: os.Getpid()}); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftRules(tun))
	if out, err := cmd.CombinedOutput(); errors.Is(err, exec.ErrNotFound) {
		return errors.New("the kill switch needs nftables: install the nftables package (it provides nft), or turn the kill switch off")
	} else if err != nil {
		return fmt.Errorf("kill switch: nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func releaseRules() error {
	out, err := exec.Command("nft", "delete", "table", "inet", nftTable).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("kill switch: nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	os.Remove(statePath())
	return nil
}

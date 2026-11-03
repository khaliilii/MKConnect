package killswitch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

// Not /var/run/mkconnect: the crash journal's folder is root's alone.
func defaultStateDir() string { return "/var/run" }

var tokenRE = regexp.MustCompile(`Token : (\d+)`)

func engageRules(tun string) error {
	if err := syscall.Setgid(Group); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	st, _ := readState()
	if st.PID != os.Getpid() || st.Token == "" {
		// pf is off unless something turned it on; -E turns it on and counts
		// this as one more user of it, so -X later only ends this one's.
		out, err := exec.Command("pfctl", "-E").CombinedOutput()
		m := tokenRE.FindSubmatch(out)
		if err != nil || m == nil {
			return fmt.Errorf("kill switch: pfctl -E: %v: %s", err, strings.TrimSpace(string(out)))
		}
		if st.Token != "" {
			// A helper that crashed holding the block: this one takes over.
			exec.Command("pfctl", "-X", st.Token).Run()
		}
		st.Token = string(m[1])
	}
	st.PID = os.Getpid()
	if err := writeState(st); err != nil {
		return fmt.Errorf("kill switch: %w", err)
	}
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(pfRules(tun))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kill switch: pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func releaseRules() error {
	st, _ := readState()
	var errs []error
	if out, err := exec.Command("pfctl", "-a", anchor, "-F", "rules").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Errorf("pfctl -F: %v: %s", err, strings.TrimSpace(string(out))))
	}
	if st.Token != "" {
		// A token pf no longer knows (it was restarted) is nothing to undo.
		exec.Command("pfctl", "-X", st.Token).Run()
	}
	if len(errs) == 0 {
		os.Remove(statePath())
	}
	return errors.Join(errs...)
}

package engine

import (
	"log"
	"os/exec"
	"strings"
)

// The system DNS cache is flushed when the tunnel comes up and when it goes
// down. On a filtered network the answers cached before connecting are often
// the filter's (Iran answers every blocked name with 10.10.34.36, TTL ~7
// minutes): without a flush, browsers keep using them for minutes through a
// working tunnel and blocked sites "don't load though it's connected". And
// the answers from inside the tunnel are useless once it is gone.

// flushDNSCache empties the operating system's DNS cache. Errors are logged:
// a failed flush only means old answers live until they expire.
func flushDNSCache(why string) {
	cmds := flushCommands()
	if len(cmds) == 0 {
		return
	}
	var failed []string
	for _, c := range cmds {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue // e.g. no systemd-resolved
		}
		cmd := exec.Command(c[0], c[1:]...)
		hideWindow(cmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			failed = append(failed, strings.Join(c, " ")+": "+strings.TrimSpace(string(out)+" "+err.Error()))
		}
	}
	if len(failed) > 0 {
		log.Printf("⚠️  could not flush the DNS cache (%s): %s", why, strings.Join(failed, "; "))
		return
	}
	log.Printf("🧹 flushed the system DNS cache (%s)", why)
}

package killswitch

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// fakeSystem replaces the firewall: it records the rules engaged (the tunnel
// interface each time) and the releases, and keeps the state in a temporary
// directory, as the real platforms do.
func fakeSystem(t *testing.T) (tunsEngaged *[]string, releases *int) {
	t.Helper()
	oldEngage, oldRelease, oldDir := engage, release, stateDir
	dir := t.TempDir()
	t.Cleanup(func() {
		engage, release, stateDir = oldEngage, oldRelease, oldDir
		mu.Lock()
		engaged, shown = false, ""
		mu.Unlock()
	})
	var tuns []string
	var n int
	stateDir = func() string { return dir }
	engage = func(tun string) error {
		tuns = append(tuns, tun)
		return writeState(state{PID: os.Getpid()})
	}
	release = func() error {
		n++
		os.Remove(statePath())
		return nil
	}
	return &tuns, &n
}

// TestEngageAndRelease: engaging again with the same tunnel changes nothing,
// a new tunnel replaces the rules, and only an engaged process releases.
func TestEngageAndRelease(t *testing.T) {
	tuns, released := fakeSystem(t)
	if err := Release(); err != nil || *released != 0 {
		t.Fatalf("release before engage: %v, %d releases", err, *released)
	}
	for _, tun := range []string{"", "utun7", "utun7", ""} {
		if err := Engage(tun); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(*tuns, ","); got != ",utun7," {
		t.Errorf("rules engaged for %q, want \",utun7,\"", got)
	}
	if !Engaged() {
		t.Error("not engaged")
	}
	if Leftover() {
		t.Error("this process's own block counted as a leftover")
	}
	if err := Release(); err != nil || *released != 1 || Engaged() {
		t.Fatalf("release: %v, %d releases, engaged %t", err, *released, Engaged())
	}
}

// TestFailedEngageStaysOff: rules the system refused don't count as engaged.
func TestFailedEngageStaysOff(t *testing.T) {
	fakeSystem(t)
	engage = func(string) error { return errors.New("pfctl: no") }
	if err := Engage(""); err == nil || Engaged() {
		t.Fatalf("Engage: %v, engaged %t", err, Engaged())
	}
}

// TestLeftover: the block of a process that has ended is a leftover, which
// Cleanup removes; a running one's is not.
func TestLeftover(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nothing is left on Windows: the filters end with the process")
	}
	_, released := fakeSystem(t)
	dead := exec.Command(os.Args[0], "-test.run=^$")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	writeState(state{PID: dead.Process.Pid, Token: "42"})
	if !Leftover() {
		t.Fatal("a dead process's block isn't a leftover")
	}
	if left, err := Cleanup(); !left || err != nil || *released != 1 || Leftover() {
		t.Fatalf("Cleanup: %t, %v, %d releases, leftover %t", left, err, *released, Leftover())
	}

	writeState(state{PID: os.Getppid()}) // alive: the test runner
	if Leftover() {
		t.Error("a running process's block counted as a leftover")
	}
	if left, _ := Cleanup(); left || *released != 1 {
		t.Errorf("Cleanup removed a running process's block")
	}
}

// TestRules: what the firewall lets out while the kill switch is on.
func TestRules(t *testing.T) {
	for name, rules := range map[string]func(string) string{"pf": pfRules, "nft": nftRules} {
		with, without := rules("utun9"), rules("")
		if !strings.Contains(with, `utun9`) || strings.Contains(without, "utun") {
			t.Errorf("%s: the tunnel interface isn't let through only when there is one:\n%s", name, with)
		}
		for _, want := range []string{"19787", "53", "192.168.0.0/16", "fe80::/10"} {
			if !strings.Contains(with, want) {
				t.Errorf("%s rules lack %s:\n%s", name, want, with)
			}
		}
	}
	pf := strings.Split(strings.TrimSpace(pfRules("utun9")), "\n")
	if last := pf[len(pf)-1]; last != "block return out quick all" {
		t.Errorf("pf: the last rule is %q, want the block", last)
	}
	if !strings.Contains(pf[1], "lo0") || !strings.Contains(pfRules(""), "group 19787") {
		t.Errorf("pf rules:\n%s", pfRules(""))
	}
	nft := nftRules("tun0")
	if !strings.HasPrefix(nft, "add table inet mkconnect_killswitch\ndelete table inet mkconnect_killswitch\n") ||
		!strings.Contains(nft, "meta skgid 19787 accept") || !strings.Contains(nft, `oifname "tun0" accept`) ||
		!strings.HasSuffix(strings.TrimSpace(nft), "reject with icmpx admin-prohibited\n\t}\n}") {
		t.Errorf("nft rules:\n%s", nft)
	}
}

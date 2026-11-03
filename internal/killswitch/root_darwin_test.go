//go:build roottest

package killswitch

// Run as root on a Mac whose MKConnect TUN connection is up:
//
//	go test -c -tags roottest -o kstest ./internal/killswitch
//	sudo ./kstest -test.run TestRootPF -test.v
//
// It engages the real pf rules for about ten seconds and checks what gets
// out: another user's connection only through the tunnel, this process's
// (the cores' group) straight out too.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// probe is one connection attempt, in a child process of the user's
// (MK_PROBE_UID) or in this one: "tcp|udp host:port iface" (iface "" for
// the routing table's choice, i.e. the tunnel).
func probe(t *testing.T, asUser bool, spec string) string {
	t.Helper()
	if !asUser {
		return dial(spec)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootPFProbe$")
	cmd.Env = append(os.Environ(), "MK_PROBE="+spec)
	uid := 501
	fmt.Sscan(os.Getenv("MK_PROBE_UID"), &uid)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: 20}}
	out, _ := cmd.CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "PROBE ") {
			return strings.TrimPrefix(line, "PROBE ")
		}
	}
	return "no result: " + string(out)
}

func dial(spec string) string {
	f := strings.Fields(spec + " ")
	network, addr, iface := f[0], f[1], ""
	if len(f) > 2 {
		iface = f[2]
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	if iface != "" {
		ifc, err := net.InterfaceByName(iface)
		if err != nil {
			return "FAIL " + err.Error()
		}
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25 /* IP_BOUND_IF */, ifc.Index)
			})
			return serr
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return "FAIL " + err.Error()
	}
	defer c.Close()
	if network == "udp" {
		// An SNTP request: only an answer shows the packet got out.
		req := make([]byte, 48)
		req[0] = 0x1b
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(req); err != nil {
			return "FAIL " + err.Error()
		}
		if _, err := c.Read(req); err != nil {
			return "FAIL " + err.Error()
		}
	}
	return "OK"
}

func TestRootPFProbe(t *testing.T) {
	spec := os.Getenv("MK_PROBE")
	if spec == "" {
		t.Skip("run by TestRootPF")
	}
	fmt.Println("PROBE " + dial(spec))
}

// ip looks host up past the tunnel (whose DNS answers placeholder FakeIP
// addresses): straight from the physical interface.
func ip(t *testing.T, host, iface string) string {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 25, ifc.Index) })
			return serr
		}}
		return d.DialContext(ctx, "udp", "8.8.8.8:53")
	}}
	addrs, err := r.LookupHost(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if net.ParseIP(a).To4() != nil {
			return a
		}
	}
	t.Fatalf("%s: no IPv4", host)
	return ""
}

func TestRootPF(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	physical := os.Getenv("MK_IFACE")
	if physical == "" {
		physical = "en0"
	}
	tun := ""
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if strings.HasPrefix(a.String(), "172.19.77.1/") {
				tun = ifc.Name
			}
		}
	}
	if tun == "" {
		t.Fatal("no MKConnect tunnel is up")
	}
	direct := ip(t, "www.aparat.com", physical) + ":443" // reachable without the tunnel
	ntp := ip(t, "time.apple.com", physical) + ":123"
	server := os.Getenv("MK_SERVER") // the running helper's connections: kept reachable
	t.Logf("tunnel %s, physical %s, direct %s, ntp %s, server %s", tun, physical, direct, ntp, server)
	pfBefore, _ := exec.Command("pfctl", "-s", "info").Output()

	type check struct {
		name   string
		asUser bool
		spec   string
		want   bool
	}
	run := func(checks []check) {
		for _, c := range checks {
			got := probe(t, c.asUser, c.spec)
			ok := got == "OK"
			mark := "✅"
			if ok != c.want {
				mark = "❌"
				t.Errorf("%s: %s (want %v)", c.name, got, map[bool]string{true: "out", false: "blocked"}[c.want])
			}
			t.Logf("%s %-48s %s", mark, c.name, got)
		}
	}
	run([]check{
		{"before: user, straight out", true, "tcp " + direct + " " + physical, true},
		{"before: user, NTP straight out", true, "udp " + ntp + " " + physical, true},
	})

	watchdog := time.AfterFunc(60*time.Second, func() { releaseRules(); os.Exit(3) })
	defer watchdog.Stop()
	defer Release()
	if err := Engage(tun); err != nil {
		t.Fatal(err)
	}
	if server != "" {
		// The running (older) helper's own connection isn't of the group:
		// let it through so the test doesn't cut the user's tunnel.
		cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
		cmd.Stdin = strings.NewReader("pass out quick to { " + server + " }\n" + pfRules(tun))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	rules, _ := exec.Command("pfctl", "-a", anchor, "-s", "rules").CombinedOutput()
	t.Logf("anchor rules:\n%s", rules)
	if g := os.Getegid(); g != Group {
		t.Errorf("the process's group is %d, want %d", g, Group)
	}
	run([]check{
		{"engaged: user, straight out", true, "tcp " + direct + " " + physical, false},
		{"engaged: user, NTP straight out", true, "udp " + ntp + " " + physical, false},
		{"engaged: user, through the tunnel", true, "tcp 1.1.1.1:443", true},
		{"engaged: user, through the tunnel (a site)", true, "tcp 142.250.185.78:443", true},
		{"engaged: cores' group, straight out", false, "tcp " + direct + " " + physical, true},
		{"engaged: cores' group, NTP straight out", false, "udp " + ntp + " " + physical, true},
	})
	if err := Release(); err != nil {
		t.Fatal(err)
	}
	run([]check{
		{"released: user, straight out", true, "tcp " + direct + " " + physical, true},
	})
	rules, _ = exec.Command("pfctl", "-a", anchor, "-s", "rules").Output() // stdout: no ALTQ notes
	if strings.TrimSpace(string(rules)) != "" {
		t.Errorf("rules left after release:\n%s", rules)
	}
	pfAfter, _ := exec.Command("pfctl", "-s", "info").Output()
	first := func(b []byte) string { return strings.SplitN(string(b), "\n", 2)[0] }
	t.Logf("pf before: %s | after: %s", first(pfBefore), first(pfAfter))
	if state := func(b []byte) string { return strings.Fields(first(b))[1] }; state(pfBefore) != state(pfAfter) {
		t.Errorf("pf was left %q, was %q", first(pfAfter), first(pfBefore))
	}
	if _, err := os.Stat(statePath()); err == nil {
		t.Error("the state file is left")
	}
}

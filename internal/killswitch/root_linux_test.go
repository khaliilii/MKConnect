//go:build roottest

package killswitch

// Run as root on Linux (a privileged container will do), with nft installed:
//
//	GOOS=linux go test -c -tags roottest -o kstest ./internal/killswitch
//	docker run --rm --privileged -v $PWD:/t kindest/node:v1.36.1 /t/kstest -test.run TestRootNFT -test.v
//
// It engages the real nftables rules and checks what gets out: another
// user's connections only by the "tunnel" interface (the container's own
// one stands in for it), this process's (the cores' group) always.

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

func dialLinux(addr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "FAIL " + err.Error()
	}
	c.Close()
	return "OK"
}

func TestRootNFTProbe(t *testing.T) {
	addr := os.Getenv("MK_PROBE")
	if addr == "" {
		t.Skip("run by TestRootNFT")
	}
	fmt.Println("PROBE " + dialLinux(addr))
}

// asNobody dials addr from a child process of another user and group.
func asNobody(addr string) string {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootNFTProbe$")
	cmd.Env = append(os.Environ(), "MK_PROBE="+addr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, _ := cmd.CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "PROBE ") {
			return strings.TrimPrefix(line, "PROBE ")
		}
	}
	return "no result: " + string(out)
}

func TestRootNFT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	outside := "1.1.1.1:443"
	expect := func(name, got string, out bool) {
		t.Helper()
		if (got == "OK") != out {
			t.Errorf("❌ %s: %s (want %v)", name, got, map[bool]string{true: "out", false: "blocked"}[out])
			return
		}
		t.Logf("✅ %-40s %s", name, got)
	}
	expect("before: another user", asNobody(outside), true)

	defer Release()
	if err := Engage(""); err != nil {
		t.Fatal(err)
	}
	rules, _ := exec.Command("nft", "list", "table", "inet", nftTable).CombinedOutput()
	t.Logf("rules:\n%s", rules)
	expect("engaged: another user", asNobody(outside), false)
	expect("engaged: another user, loopback", asNobody(l.Addr().String()), true)
	expect("engaged: another user, port 53", asNobody("1.1.1.1:53"), true)
	expect("engaged: the cores' group", dialLinux(outside), true)

	ifs, _ := net.Interfaces()
	tun := ""
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback == 0 && ifc.Flags&net.FlagUp != 0 {
			tun = ifc.Name
			break
		}
	}
	if err := Engage(tun); err != nil {
		t.Fatal(err)
	}
	expect("engaged: another user, by the tunnel ("+tun+")", asNobody(outside), true)

	if err := Release(); err != nil {
		t.Fatal(err)
	}
	expect("released: another user", asNobody(outside), true)
	if out, _ := exec.Command("nft", "list", "tables").CombinedOutput(); strings.Contains(string(out), nftTable) {
		t.Errorf("the table is left:\n%s", out)
	}
	if _, err := os.Stat(statePath()); err == nil {
		t.Error("the state file is left")
	}
}

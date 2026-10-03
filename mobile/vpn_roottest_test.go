//go:build roottest && linux

package mkmobile

// Run by scripts/test-mobile-vpn-linux.sh as root inside a network namespace
// setup where 203.0.113.10 is only reachable through a Shadowsocks server.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fakeVpnService does what Android's VpnService does for the app.
type fakeVpnService struct {
	t        *testing.T
	physical string
	tunFile  *os.File
}

func (f *fakeVpnService) OpenTun(cfg *TunConfig) (int32, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], "mktun0")
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return 0, errno
	}
	f.tunFile = os.NewFile(uintptr(fd), "tun")
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			f.t.Logf("ip %v: %v %s", args, err, out)
		}
	}
	for _, a := range strings.Split(cfg.Addresses(), ",") {
		run("addr", "add", a, "dev", "mktun0")
	}
	run("link", "set", "mktun0", "mtu", "1500", "up")
	for _, r := range strings.Split(cfg.Routes(), ",") {
		run("route", "replace", r, "dev", "mktun0") // like Android: the VPN takes over the default route
	}
	f.t.Logf("VPN: addresses %s, %d routes, DNS %s, MTU %d", cfg.Addresses(), len(strings.Split(cfg.Routes(), ",")), cfg.DnsServer(), cfg.Mtu())
	return int32(fd), nil
}

// Protect binds a core socket to the physical interface, like VpnService.protect.
func (f *fakeVpnService) Protect(fd int32) bool {
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, f.physical) == nil
}

func (f *fakeVpnService) Interfaces() string {
	ifaces, _ := net.Interfaces()
	var out []interfaceJSON
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		var as []string
		for _, a := range addrs {
			as = append(as, a.String())
		}
		out = append(out, interfaceJSON{Name: i.Name, Index: i.Index, MTU: i.MTU, Addresses: as, Flags: int(i.Flags), Type: 2})
	}
	data, _ := json.Marshal(out)
	return string(data)
}

func TestVPNThroughFakeVpnService(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	SetDataDir(dir)
	res, err := Import("Server: ss://YWVzLTI1Ni1nY206cHc@10.200.0.2:8388#remote")
	if err != nil || !strings.Contains(res, `"added":1`) {
		t.Fatalf("import: %s %v", res, err)
	}
	if err := SetSettings(`{"mode":"vpn","port":1080,"remote_dns":"1.1.1.1"}`); err != nil {
		t.Fatal(err)
	}
	wan, err := net.InterfaceByName("wan0")
	if err != nil {
		t.Fatal(err)
	}
	UpdateDefaultInterface("wan0", int32(wan.Index))

	app := &fakeVpnService{t: t, physical: "wan0"}
	if err := Start(app); err != nil {
		t.Fatalf("start: %v\n%s", err, Logs(30))
	}
	defer Stop()
	t.Logf("status: %s", Status())

	// This process is "an app on the phone": its traffic goes through the VPN.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://203.0.113.10:8080/")
	if err != nil {
		t.Fatalf("request through the VPN: %v\n%s", err, Logs(30))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("website says: %s", strings.TrimSpace(string(body)))
	if !strings.Contains(string(body), "hello from the internet") {
		t.Fatalf("unexpected body %q", body)
	}

	// Name lookup through the VPN: DNS to 1.1.1.1 is hijacked and answered through the tunnel.
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	addrs, err := r.LookupHost(t.Context(), "website.test")
	if err != nil || len(addrs) == 0 || addrs[0] != "203.0.113.10" {
		t.Fatalf("DNS through the VPN: %v %v\n%s", addrs, err, Logs(30))
	}
	t.Logf("website.test resolved through the VPN to %v", addrs)

	var st map[string]any
	json.Unmarshal([]byte(Status()), &st)
	if st["state"] != "connected" || st["down"].(float64) == 0 {
		t.Fatalf("status after traffic: %s", Status())
	}
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName("mktun0"); err == nil {
		t.Log("note: mktun0 still exists (the fake VpnService owns it)")
	}
	t.Logf("final status: %s", Status())
}

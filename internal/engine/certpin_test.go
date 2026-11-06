package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/khaliilii/MKConnect/internal/profile"
)

const testPin = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// TestEveryAccountGetsACoreThatRunsIt goes through every kind of account and
// setting: the core PreferredCore picks must be able to run it. A preference
// that wins over what a core can do shows up here (an allowInsecure account
// over WebSocket went to Xray, which refused it, whatever the settings said).
func TestEveryAccountGetsACoreThatRunsIt(t *testing.T) {
	if startSingBox == nil || startXray == nil {
		t.Skip("needs both cores")
	}
	uuid := "bf000d23-0752-40b4-affe-68f7707a9661"
	accounts := []profile.Profile{
		{Type: profile.TypeVMess, UUID: uuid},
		{Type: profile.TypeVLESS, UUID: uuid},
		{Type: profile.TypeTrojan, Password: "x"},
	}
	transports := []profile.Transport{
		{},
		{HeaderType: "http", Path: "/", Host: "a.com"},
		{Network: "ws", Path: "/", Host: "a.com"},
		{Network: "httpupgrade", Path: "/", Host: "a.com"},
		{Network: "grpc", ServiceName: "gun"},
		{Network: "xhttp", Path: "/", Host: "a.com"},
	}
	securities := []profile.TLS{
		{},
		{Mode: "tls", SNI: "a.com"},
		{Mode: "tls", SNI: "a.com", Insecure: true},
		{Mode: "tls", SNI: "a.com", PinnedCertSHA256: testPin},
		{Mode: "tls", SNI: "a.com", Insecure: true, PinnedCertSHA256: testPin},
		{Mode: "tls", SNI: "a.com", VerifyByName: "b.com"},
		{Mode: "tls", SNI: "a.com", Insecure: true, VerifyByName: "b.com"},
	}
	for _, base := range accounts {
		for _, tr := range transports {
			for _, sec := range securities {
				for _, core := range []string{profile.CoreSingBox, profile.CoreXray} {
					for _, mux := range []bool{false, true} {
						p := base
						p.Name, p.Server, p.Port, p.Transport, p.TLS = "x", "127.0.0.1", 443, tr, sec
						s := testSettings(t)
						s.Core, s.Mux = core, mux
						s.Core = PreferredCore(&p, &s)
						name := fmt.Sprintf("%s %+v %+v on %s, mux %t", p.Type, tr, sec, core, mux)
						var err error
						if s.Core == profile.CoreXray {
							if skipsCertCheck(&p) {
								if tr.Network != "xhttp" {
									t.Errorf("%s: Xray for an account sing-box could run", name)
								}
								p.TLS.PinnedCertSHA256, p.TLS.Insecure = testPin, false // pinPresentedCert
							}
							_, err = xrayConfig(&p, &s)
						} else {
							_, err = singBoxConfig(&p, &s, nil)
						}
						if err != nil {
							t.Errorf("%s: %s can't run it: %v", name, s.Core, err)
						}
					}
				}
			}
		}
	}
	for _, typ := range []string{profile.TypeHysteria2, profile.TypeTUIC} {
		p := profile.Profile{Type: typ, TLS: profile.TLS{Mode: "tls", Insecure: true}}
		if s := (profile.Settings{Core: profile.CoreXray}); PreferredCore(&p, &s) != profile.CoreSingBox {
			t.Errorf("%s isn't on sing-box", typ)
		}
	}
}

// TestSkippingTheCheckAndItsReason: the case from a user's log, and what the
// log says about it.
func TestSkippingTheCheckAndItsReason(t *testing.T) {
	if startSingBox == nil || startXray == nil {
		t.Skip("needs both cores")
	}
	p := profile.Profile{Type: profile.TypeVLESS, Transport: profile.Transport{Network: "ws"}, TLS: profile.TLS{Mode: "tls", Insecure: true}}
	xr := profile.Settings{Core: profile.CoreXray}
	if got := PreferredCore(&p, &profile.Settings{Core: profile.CoreSingBox}); got != profile.CoreSingBox {
		t.Errorf("ws with allowInsecure runs on %s", got)
	}
	if got := PreferredCore(&p, &xr); got != profile.CoreSingBox {
		t.Errorf("ws with allowInsecure, Xray chosen: runs on %s", got)
	}
	if got := coreReason(&p, &xr); !strings.Contains(got, "certificate check") {
		t.Errorf("reason: %q", got)
	}
	p.TLS.PinnedCertSHA256 = testPin // the pin decides: Xray is fine again
	if got := PreferredCore(&p, &profile.Settings{Core: profile.CoreSingBox}); got != profile.CoreXray {
		t.Errorf("pinned with allowInsecure runs on %s", got)
	}
}

// TestPinPresentedCert: an xhttp account that skips the check gets the hash of
// the certificate its server presents, and Xray accepts the result.
func TestPinPresentedCert(t *testing.T) {
	if startXray == nil {
		t.Skip("needs Xray")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	p := profile.Profile{Name: "x", Type: profile.TypeVLESS, Server: host, Port: n, UUID: "bf000d23-0752-40b4-affe-68f7707a9661",
		Transport: profile.Transport{Network: "xhttp", Path: "/"}, TLS: profile.TLS{Mode: "tls", SNI: "a.com", Insecure: true}}

	if err := pinPresentedCert(t.Context(), &p); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(srv.Certificate().Raw)
	if want := hex.EncodeToString(sum[:]); p.TLS.PinnedCertSHA256 != want || p.TLS.Insecure {
		t.Fatalf("pin %q insecure %t, want %q", p.TLS.PinnedCertSHA256, p.TLS.Insecure, want)
	}
	s := testSettings(t)
	s.Core = profile.CoreXray
	e, err := launchXray(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()

	// Nothing to learn from a server that isn't there: said, not hidden.
	srv.Close()
	p.TLS.PinnedCertSHA256, p.TLS.Insecure = "", true
	if err := pinPresentedCert(t.Context(), &p); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("server gone: %v", err)
	}
}

// TestPinWinsOverSkipping: a link with both a pin and allowInsecure (share
// links often carry both) runs on Xray, checked by the pin.
func TestPinWinsOverSkipping(t *testing.T) {
	p := profile.Profile{Name: "x", Type: profile.TypeTrojan, Server: "127.0.0.1", Port: 443, Password: "x",
		TLS: profile.TLS{Mode: "tls", Insecure: true, PinnedCertSHA256: testPin}}
	s := testSettings(t)
	cfg, err := xrayConfig(&p, &s)
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshal(cfg)
	if err != nil || !strings.Contains(string(data), testPin) || strings.Contains(string(data), "allowInsecure") {
		t.Errorf("config: %v\n%s", err, data)
	}
}

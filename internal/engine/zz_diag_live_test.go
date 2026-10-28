package engine

import (
	"encoding/json"
	"os"
	"os/signal"
	"testing"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// TestDiagXrayLive is a temporary diagnostic: it runs a stored account on
// Xray on a local port until interrupted, with DIAG_MUX=1 adding Mux.Cool
// and DIAG_FRAG=1 fragmenting the first packets, so a browser can be pointed
// at it. DIAG_ID names the account, DIAG_PORT the port.
func TestDiagXrayLive(t *testing.T) {
	id := os.Getenv("DIAG_ID")
	if id == "" {
		t.Skip("set DIAG_ID")
	}
	store, err := profile.Load(os.Getenv("DIAG_PROFILES"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.Find(id)
	if err != nil {
		t.Fatal(err)
	}
	s := store.Settings
	s.Mode, s.Core, s.LogLevel = profile.ModeProxy, profile.CoreXray, "warning"
	json.Unmarshal([]byte(os.Getenv("DIAG_PORT")), &s.ListenPort)
	cfg, err := xrayConfig(p, &s)
	if err != nil {
		t.Fatal(err)
	}
	outs := cfg["outbounds"].([]obj)
	if os.Getenv("DIAG_MUX") == "1" {
		outs[0]["mux"] = obj{"enabled": true, "concurrency": 8}
	}
	if os.Getenv("DIAG_FRAG") == "1" {
		outs[0]["streamSettings"].(obj)["sockopt"] = obj{"dialerProxy": "fragment"}
		outs = append(outs, obj{"tag": "fragment", "protocol": "freedom",
			"settings": obj{"fragment": obj{"packets": "1-3", "length": "100-200", "interval": "10-20"}}})
	}
	cfg["outbounds"] = outs
	data, _ := marshal(cfg)
	e, err := startXray(data)
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	defer e.Close()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	select {
	case <-stop:
	case <-time.After(15 * time.Minute):
	}
}

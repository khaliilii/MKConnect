package mkmobile

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The phone app drives everything through these functions, so they are tested
// the way it calls them: JSON in, JSON out, on a store in a temp directory.

func newTestStore(t *testing.T) {
	t.Helper()
	if err := Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		mu.Lock()
		store = nil
		mu.Unlock()
	})
}

func profilesOf(t *testing.T) map[string]any {
	t.Helper()
	data, err := Profiles()
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(data), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSaveAndEditProfile(t *testing.T) {
	newTestStore(t)

	id, err := SaveProfile(`{"name":"Home","type":"ssh","server":"1.2.3.4","port":22,"user":"root","password":"pw",
		"payload":"GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]","payload_proxy":"5.6.7.8:8080"}`)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("no id returned")
	}

	data, err := ProfileJSON(id)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatal(err)
	}
	if p["payload_proxy"] != "5.6.7.8:8080" || !strings.Contains(p["payload"].(string), "bug.example") {
		t.Fatalf("payload fields not stored: %s", data)
	}

	// Editing keeps the id and replaces the fields.
	p["name"] = "Home server"
	edited, _ := json.Marshal(p)
	if _, err := SaveProfile(string(edited)); err != nil {
		t.Fatal(err)
	}
	if again, _ := ProfileJSON(id); !strings.Contains(again, "Home server") {
		t.Fatalf("edit not saved: %s", again)
	}
	if list := profilesOf(t)["profiles"].([]any); len(list) != 1 {
		t.Fatalf("editing added an account instead of replacing it: %d", len(list))
	}

	// An invalid account is refused instead of being stored.
	if _, err := SaveProfile(`{"name":"bad","type":"ssh","server":"h","port":22}`); err == nil {
		t.Fatal("an SSH account without credentials was accepted")
	}
	if _, err := SaveProfile(`{"name":"bad","type":"vmess","server":"h","port":443,"uuid":"u","payload":"GET /"}`); err == nil {
		t.Fatal("a payload on a non-SSH account was accepted")
	}
}

func TestGroupsFromPhone(t *testing.T) {
	newTestStore(t)
	if _, err := Import("trojan://pw@a.example:443#one\ntrojan://pw@b.example:443#two"); err != nil {
		t.Fatal(err)
	}

	gid, err := AddGroup("Work")
	if err != nil {
		t.Fatal(err)
	}
	if err := RenameGroup(gid, "Office"); err != nil {
		t.Fatal(err)
	}
	list := profilesOf(t)
	first := list["profiles"].([]any)[0].(map[string]any)
	if err := SetGroup(first["id"].(string), gid); err != nil {
		t.Fatal(err)
	}
	groups := profilesOf(t)["groups"].([]any)
	var office map[string]any
	for _, g := range groups {
		if g.(map[string]any)["name"] == "Office" {
			office = g.(map[string]any)
		}
	}
	if office == nil {
		t.Fatalf("renamed group missing: %v", groups)
	}
	if n := office["count"].(float64); n != 1 {
		t.Fatalf("group holds %v accounts, want 1", n)
	}

	// Importing into a group puts the new accounts there.
	if _, err := ImportInto("trojan://pw@c.example:443#three", "Travel"); err != nil {
		t.Fatal(err)
	}
	for _, p := range profilesOf(t)["profiles"].([]any) {
		v := p.(map[string]any)
		if v["name"] == "three" && v["group"] == "" {
			t.Fatal("the imported account was not put in the group")
		}
	}
	if err := SetGroup(first["id"].(string), ""); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsRoundTripAndOptions(t *testing.T) {
	newTestStore(t)
	data, err := Settings()
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	json.Unmarshal([]byte(data), &s)
	if s["auto_reconnect"] != true {
		t.Errorf("auto-reconnect should default to on: %s", data)
	}
	if s["direct_iran"] != true {
		t.Errorf("Iranian sites should go direct by default: %s", data)
	}

	if s["failover"] != true {
		t.Errorf("failover should default to on: %s", data)
	}
	s["direct_iran"], s["failover"] = false, false
	s["mode"], s["port"], s["log_level"], s["sort_by"] = "proxy", 1081.0, "debug", "latency"
	s["auto_reconnect"], s["tun_stack"], s["tun_mtu"] = false, "gvisor", 1400.0
	changed, _ := json.Marshal(s)
	if err := SetSettings(string(changed)); err != nil {
		t.Fatal(err)
	}
	again, _ := Settings()
	json.Unmarshal([]byte(again), &s)
	for k, want := range map[string]any{"mode": "proxy", "port": 1081.0, "log_level": "debug",
		"sort_by": "latency", "auto_reconnect": false, "tun_stack": "gvisor", "tun_mtu": 1400.0, "direct_iran": false, "failover": false} {
		if s[k] != want {
			t.Errorf("%s = %v, want %v", k, s[k], want)
		}
	}

	// Invalid settings are refused, not stored.
	s["tun_mtu"] = 10.0
	bad, _ := json.Marshal(s)
	if err := SetSettings(string(bad)); err == nil {
		t.Error("an impossible MTU was accepted")
	}

	var opts map[string]any
	if err := json.Unmarshal([]byte(Options()), &opts); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"types", "vmess_ciphers", "networks", "tls_modes", "log_levels", "payload_tags"} {
		if list, ok := opts[key].([]any); !ok || len(list) == 0 {
			t.Errorf("option list %q is missing or empty", key)
		}
	}
}

func TestStartTestWithoutAccounts(t *testing.T) {
	newTestStore(t)
	if err := StartTest("", false); err == nil {
		t.Fatal("testing an empty account list should fail")
	}
	var p map[string]any
	if err := json.Unmarshal([]byte(TestProgress()), &p); err != nil {
		t.Fatal(err)
	}
	if p["running"] == true {
		t.Fatal("no test should be running")
	}
}

// TestStartTestRunsAndSaves drives the server test the way the app does:
// start it, poll the progress, and find the measurement on the account
// afterwards. The server doesn't exist, so the measurement is a failure —
// which is exactly what the list has to be able to show.
func TestStartTestRunsAndSaves(t *testing.T) {
	newTestStore(t)
	if _, err := Import("trojan://pw@127.0.0.1:1#dead"); err != nil {
		t.Fatal(err)
	}
	id := profilesOf(t)["profiles"].([]any)[0].(map[string]any)["id"].(string)

	if err := StartTest(id, false); err != nil {
		t.Fatal(err)
	}
	if err := StartTest(id, false); err == nil {
		t.Error("a second test should be refused while one runs")
	}

	deadline := time.Now().Add(60 * time.Second)
	var p map[string]any
	for time.Now().Before(deadline) {
		if err := json.Unmarshal([]byte(TestProgress()), &p); err != nil {
			t.Fatal(err)
		}
		if p["running"] == false && p["done"].(float64) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if p["running"] != false {
		t.Fatalf("the test did not finish: %v", p)
	}
	results := p["results"].(map[string]any)
	if _, ok := results[id]; !ok {
		t.Fatalf("no result for the account: %v", results)
	}

	// The measurement is kept, so the list shows it after the run.
	shown := profilesOf(t)["profiles"].([]any)[0].(map[string]any)
	if shown["test"] != "failed" || shown["test_ok"] == true {
		t.Fatalf("the failed measurement was not stored: %v", shown)
	}
}

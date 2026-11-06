package gateway

import (
	"strings"
	"testing"
)

// TestSharingRules: devices reach their own network and multicast directly,
// everything else goes into the tunnel, in that order.
func TestSharingRules(t *testing.T) {
	got := sharingRules([]SharedNet{{"bridge100", "192.168.2.0/24"}}, "utun4", "172.19.77.1")
	local := strings.Index(got, "pass in quick on bridge100 inet to { 192.168.2.0/24, 224.0.0.0/4, 255.255.255.255 } keep state")
	tunnel := strings.Index(got, "pass in quick on bridge100 route-to (utun4 172.19.77.1) inet from 192.168.2.0/24 to any keep state")
	if local < 0 || tunnel < local {
		t.Fatalf("rules:\n%s", got)
	}
	if !sameNets([]SharedNet{{"a", "1"}, {"b", "2"}}, []SharedNet{{"b", "2"}, {"a", "1"}}) || sameNets(nil, []SharedNet{{"a", "1"}}) {
		t.Error("sameNets")
	}
}

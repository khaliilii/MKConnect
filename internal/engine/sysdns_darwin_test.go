package engine

import (
	"os"
	"slices"
	"testing"
)

// TestLeftoverDetectedLive checks the detection against the real system. It
// only runs when a test script has left a service pointing into the tunnel
// on purpose (MKCONNECT_LEFTOVER_SERVICE names it).
func TestLeftoverDetectedLive(t *testing.T) {
	want := os.Getenv("MKCONNECT_LEFTOVER_SERVICE")
	if want == "" {
		t.Skip("set MKCONNECT_LEFTOVER_SERVICE to run against the real system")
	}
	if left := LeftoverTunnelDNS(); !slices.Contains(left, want) {
		t.Fatalf("leftover DNS on %q not detected; found %v", want, left)
	}
}

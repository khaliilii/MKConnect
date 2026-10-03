package profile

import (
	"fmt"
	"sort"
	"time"
)

// Sort orders for the account list.
const (
	SortLatency = "latency"
	SortSpeed   = "speed"
)

// TestResult is how a server performed in a test through the proxy.
type TestResult struct {
	At       time.Time `json:"at"`
	Sent     int       `json:"sent"`               // latency probes sent
	Received int       `json:"received"`           // probes that succeeded
	Latency  int       `json:"latency_ms"`         // average of the successful probes
	Jitter   int       `json:"jitter_ms"`          // max - min of the successful probes
	Speed    int64     `json:"speed_bps,omitzero"` // download bytes/s, 0 = not measured
	Error    string    `json:"error,omitempty"`    // why the server failed
}

// OK reports whether the server answered at least once.
func (r *TestResult) OK() bool { return r != nil && r.Received > 0 }

// Summary is a short text for lists: "182 ms · 3/3 · 4.2 MB/s" or the error.
func (r *TestResult) Summary() string {
	if r == nil {
		return ""
	}
	if !r.OK() {
		return "failed"
	}
	s := fmt.Sprintf("%d ms", r.Latency)
	if r.Received < r.Sent {
		s += fmt.Sprintf(" · %d/%d", r.Received, r.Sent)
	}
	if r.Speed > 0 {
		s += " · " + FormatBytes(r.Speed) + "/s"
	}
	return s
}

// SortProfiles orders indices into profiles by the given sort order:
// tested servers that work first (lowest latency, or fastest), then failed
// ones, then untested ones. Lossy servers rank behind clean ones with similar
// latency: each lost probe counts as one more average round trip.
func SortProfiles(profiles []Profile, idx []int, by string) {
	if by != SortLatency && by != SortSpeed {
		return
	}
	rank := func(r *TestResult) int {
		switch {
		case r.OK():
			return 0
		case r != nil:
			return 1
		}
		return 2
	}
	score := func(r *TestResult) int {
		lost := r.Sent - r.Received
		return r.Latency * (r.Sent + lost) / max(r.Sent, 1)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ra, rb := profiles[idx[a]].Test, profiles[idx[b]].Test
		if ka, kb := rank(ra), rank(rb); ka != kb {
			return ka < kb
		}
		if !ra.OK() {
			return false
		}
		if by == SortSpeed && ra.Speed != rb.Speed {
			return ra.Speed > rb.Speed
		}
		return score(ra) < score(rb)
	})
}

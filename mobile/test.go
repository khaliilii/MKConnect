package mkmobile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// Measuring accounts (latency, how many probes answered, optionally download
// speed) is how the desktop app picks a usable server out of a subscription of
// sixty. It runs in the background here too: StartTest returns at once and the
// app polls TestProgress.

var (
	testMu     sync.Mutex
	testCancel context.CancelFunc
	testState  testProgress
)

type testProgress struct {
	Running bool   `json:"running"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Error   string `json:"error,omitempty"`
	// Results maps an account id to its measurement, for the accounts
	// measured in this run.
	Results map[string]testResultView `json:"results"`
}

type testResultView struct {
	Latency int    `json:"latency_ms"`
	Jitter  int    `json:"jitter_ms"`
	Sent    int    `json:"sent"`
	Got     int    `json:"received"`
	Speed   int64  `json:"speed_bps"`
	Error   string `json:"error,omitempty"`
	Summary string `json:"summary"`
}

func viewOf(r *profile.TestResult) testResultView {
	if r == nil {
		return testResultView{}
	}
	return testResultView{Latency: r.Latency, Jitter: r.Jitter, Sent: r.Sent, Got: r.Received,
		Speed: r.Speed, Error: r.Error, Summary: r.Summary()}
}

// StartTest measures accounts in the background: ids is a comma-separated
// list, or empty for every account. With speed, the download speed of each
// account that answers is measured too (slower, and it uses data).
func StartTest(ids string, speed bool) error {
	mu.Lock()
	s, err := loaded()
	if err != nil {
		mu.Unlock()
		return err
	}
	// A copy of the profiles: the test runs without the store lock held.
	profiles := append([]profile.Profile(nil), s.Profiles...)
	settings := s.Settings
	mu.Unlock()

	var idx []int
	if ids = strings.TrimSpace(ids); ids == "" {
		for i := range profiles {
			idx = append(idx, i)
		}
	} else {
		want := map[string]bool{}
		for _, id := range strings.Split(ids, ",") {
			want[strings.TrimSpace(id)] = true
		}
		for i := range profiles {
			if want[profiles[i].ID] {
				idx = append(idx, i)
			}
		}
	}
	if len(idx) == 0 {
		return errors.New("no accounts to test")
	}

	testMu.Lock()
	if testState.Running {
		testMu.Unlock()
		return errors.New("a test is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	testCancel = cancel
	testState = testProgress{Running: true, Total: len(idx), Results: map[string]testResultView{}}
	testMu.Unlock()

	// The core needs sing-box for every protocol, and the test must not touch
	// the system or the running connection: it uses its own local ports.
	settings.Core, settings.Mode = profile.CoreSingBox, profile.ModeProxy

	go func() {
		defer cancel()
		results := engine.TestMany(ctx, profiles, idx, settings, engine.TestOptions{Speed: speed}, 4,
			func(i int, r *profile.TestResult) {
				testMu.Lock()
				if r.Speed == 0 {
					testState.Done++ // the speed pass reports a second time
				}
				testState.Results[profiles[i].ID] = viewOf(r)
				testMu.Unlock()
			})

		// Keep the measurements, like the desktop app, so the list can show
		// and sort by them later.
		mu.Lock()
		if s, err := loaded(); err == nil {
			for i, r := range results {
				if p, err := s.Find(profiles[i].ID); err == nil {
					p.Test = r
				}
			}
			s.Save()
		}
		mu.Unlock()

		testMu.Lock()
		testState.Running = false
		if ctx.Err() != nil {
			testState.Error = "cancelled"
		}
		testMu.Unlock()
	}()
	return nil
}

// TestProgress returns {"running","done","total","results":{id:{...}}} as JSON.
func TestProgress() string {
	testMu.Lock()
	defer testMu.Unlock()
	data, _ := json.Marshal(testState)
	return string(data)
}

// CancelTest stops a running test.
func CancelTest() {
	testMu.Lock()
	cancel := testCancel
	testMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

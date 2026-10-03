package gui

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// testEngine runs the server tests; replaced in GUI tests.
var testEngine = engine.TestMany

var sortLabels = []struct{ value, label string }{
	{"", "As added"},
	{profile.SortLatency, "Latency (low → high)"},
	{profile.SortSpeed, "Speed (fast → slow)"},
}

// newTestControls builds the Test and Sort buttons and the progress bar shown
// while a test runs.
func (u *ui) newTestControls() (testBtn, sortBtn *widget.Button, bar *fyne.Container) {
	testBtn = widget.NewButtonWithIcon(wide("Test"), theme.MediaPlayIcon(), nil)
	testBtn.OnTapped = func() {
		menu := fyne.NewMenu("",
			fyne.NewMenuItem("Test latency of the accounts shown", func() { u.testShown(false) }),
			fyne.NewMenuItem("Test latency and speed of the accounts shown", func() { u.testShown(true) }),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Test the selected account (with speed)", u.testSelected),
		)
		widget.ShowPopUpMenuAtRelativePosition(menu, u.win.Canvas(), fyne.NewPos(0, testBtn.Size().Height), testBtn)
	}
	u.testBtn = testBtn

	sortBtn = widget.NewButtonWithIcon(wide("Sort"), theme.MenuDropDownIcon(), nil)
	sortBtn.OnTapped = func() {
		var items []*fyne.MenuItem
		for _, s := range sortLabels {
			item := fyne.NewMenuItem(s.label, func() { u.setSort(s.value) })
			item.Checked = u.store.Settings.SortBy == s.value
			items = append(items, item)
		}
		widget.ShowPopUpMenuAtRelativePosition(fyne.NewMenu("", items...), u.win.Canvas(), fyne.NewPos(0, sortBtn.Size().Height), sortBtn)
	}
	u.sortBtn = sortBtn

	u.testProgress = widget.NewProgressBar()
	u.testLabel = widget.NewLabel("")
	u.testLabel.SizeName = theme.SizeNameCaptionText
	cancel := widget.NewButtonWithIcon("", theme.CancelIcon(), func() {
		if u.testCancel != nil {
			u.testCancel()
		}
	})
	bar = container.NewBorder(nil, nil, nil, cancel, container.NewVBox(u.testLabel, u.testProgress))
	bar.Hide()
	u.testBar = bar
	return testBtn, sortBtn, bar
}

// sortButtonText names the current order: "Sort: Latency".
func (u *ui) sortButtonText() string {
	switch u.store.Settings.SortBy {
	case profile.SortLatency:
		return wide("Sort: Latency")
	case profile.SortSpeed:
		return wide("Sort: Speed")
	}
	return wide("Sort")
}

func (u *ui) setSort(by string) {
	u.store.Settings.SortBy = by
	u.save()
	u.refreshProfiles()
}

func (u *ui) testShown(speed bool) {
	idx := append([]int(nil), u.visible...)
	u.runTests(idx, speed)
}

func (u *ui) testSelected() {
	p := u.activeProfile()
	if p == nil {
		return
	}
	for i := range u.store.Profiles {
		if u.store.Profiles[i].ID == p.ID {
			u.runTests([]int{i}, true)
			return
		}
	}
}

// runTests tests the given accounts in the background, shows each result as
// it arrives and sorts the list when done.
func (u *ui) runTests(idx []int, speed bool) {
	if u.testCancel != nil || len(idx) == 0 {
		return
	}
	if u.state != stateIdle && u.store.Settings.Mode == profile.ModeTUN {
		dialog.ShowInformation("Disconnect first",
			"VPN (TUN) mode is on, so the test traffic would go through the current connection.\n"+
				"Disconnect, or switch to proxy mode, to test the servers themselves.", u.win)
		return
	}
	// Tests work on copies, keyed by id: the list may change meanwhile.
	profiles := make([]profile.Profile, len(idx))
	ids := make([]string, len(idx))
	order := make([]int, len(idx))
	for n, i := range idx {
		profiles[n], ids[n], order[n] = u.store.Profiles[i], u.store.Profiles[i].ID, n
	}
	settings := u.store.Settings
	total := len(idx)
	if speed {
		total *= 2 // latency pass + speed pass (an upper bound: failed servers skip the speed test)
	}

	ctx, cancel := context.WithCancel(context.Background())
	u.testCancel = cancel
	u.testBtn.Disable()
	u.testProgress.SetValue(0)
	u.testLabel.SetText(fmt.Sprintf("Testing %d account(s)…", len(idx)))
	u.testBar.Show()
	u.profilesPanel.Refresh()

	done, working := 0, 0
	tested := map[int]bool{} // accounts with a latency result
	go func() {
		testEngine(ctx, profiles, order, settings, engine.TestOptions{Speed: speed}, 8, func(n int, r *profile.TestResult) {
			fyne.Do(func() {
				done++
				if p := u.findProfile(ids[n]); p != nil {
					p.Test = r
				}
				if !tested[n] {
					tested[n] = true
					if r.OK() {
						working++
					}
				}
				u.testProgress.SetValue(min(1, float64(done)/float64(total)))
				if len(tested) < len(idx) {
					u.testLabel.SetText(fmt.Sprintf("Latency: %d of %d tested · %d working", len(tested), len(idx), working))
				} else if speed {
					u.testLabel.SetText(fmt.Sprintf("Speed: %d of %d working accounts measured", done-len(idx), working))
					total = len(idx) + working
				}
				u.list.Refresh()
			})
		})
		fyne.Do(func() {
			cancel()
			u.testCancel = nil
			u.testBtn.Enable()
			u.testBar.Hide()
			u.save()
			if u.store.Settings.SortBy == "" && len(idx) > 1 {
				// The point of testing many is usually picking the best one.
				u.store.Settings.SortBy = profile.SortLatency
				if speed {
					u.store.Settings.SortBy = profile.SortSpeed
				}
				u.save()
			}
			u.refreshProfiles()
			u.logf("🧪 tested %d account(s): %d working", len(idx), working)
		})
	}()
}

func (u *ui) findProfile(id string) *profile.Profile {
	for i := range u.store.Profiles {
		if u.store.Profiles[i].ID == id {
			return &u.store.Profiles[i]
		}
	}
	return nil
}

// testText returns the right-hand text of a list row and how to color it.
func testText(r *profile.TestResult) (main, extra string, imp widget.Importance) {
	switch {
	case r == nil:
		return "", "", widget.LowImportance
	case !r.OK():
		return "failed", r.Error, widget.DangerImportance
	}
	main = fmt.Sprintf("%d ms", r.Latency)
	imp = widget.SuccessImportance
	if r.Latency >= 800 || r.Received < r.Sent {
		imp = widget.WarningImportance
	}
	extra = fmt.Sprintf("%d/%d ok", r.Received, r.Sent)
	if r.Speed > 0 {
		extra = profile.FormatBytes(r.Speed) + "/s"
		if r.Received < r.Sent {
			extra += fmt.Sprintf(" · %d/%d", r.Received, r.Sent)
		}
	}
	return main, extra, imp
}

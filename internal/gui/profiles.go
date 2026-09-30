package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/profile"
)

var typeLabels = map[string]string{
	profile.TypeSSH:         "SSH",
	profile.TypeVMess:       "VMess",
	profile.TypeVLESS:       "VLESS",
	profile.TypeTrojan:      "Trojan",
	profile.TypeShadowsocks: "Shadowsocks",
}

// Group filter values besides group ids.
const (
	filterAll        = "*"
	filterUngrouped  = ""
	labelAllGroups   = "All accounts"
	labelUngrouped   = "Ungrouped"
)

func (u *ui) newProfilesPanel() fyne.CanvasObject {
	u.groupFilter = filterAll
	u.list = widget.NewList(
		func() int { return len(u.visible) },
		func() fyne.CanvasObject {
			name := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			name.Truncation = fyne.TextTruncateEllipsis
			detail := widget.NewLabel("")
			detail.SizeName = theme.SizeNameCaptionText
			detail.Importance = widget.LowImportance
			detail.Truncation = fyne.TextTruncateEllipsis
			return container.New(layout.NewCustomPaddedVBoxLayout(-2*theme.Padding()), name, detail)
		},
		func(id widget.ListItemID, o fyne.CanvasObject) {
			p := &u.store.Profiles[u.visible[id]]
			box := o.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(p.Name)
			box.Objects[1].(*widget.Label).SetText(profileSummary(p))
		},
	)
	u.list.OnSelected = func(id widget.ListItemID) {
		p := &u.store.Profiles[u.visible[id]]
		if u.store.Active == p.ID {
			return
		}
		u.store.Active = p.ID
		u.save()
		// Switching servers while connected reconnects with the new one.
		if u.state != stateIdle {
			u.reconnect()
		}
	}

	var addBtn *widget.Button
	addBtn = widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		var items []*fyne.MenuItem
		for _, t := range profile.Types {
			items = append(items, fyne.NewMenuItem(typeLabels[t], func() {
				p := profile.Profile{Type: t, Group: u.targetGroup()}
				if t == profile.TypeSSH {
					p.Port = 22
				} else {
					p.Port = 443
				}
				u.openEditor(p, true)
			}))
		}
		widget.ShowPopUpMenuAtRelativePosition(fyne.NewMenu("", items...), u.win.Canvas(),
			fyne.NewPos(0, addBtn.Size().Height), addBtn)
	})
	addBtn.Importance = widget.HighImportance

	importBtn := widget.NewButtonWithIcon("Import", theme.ContentPasteIcon(), u.showImport)
	editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
		if p := u.activeProfile(); p != nil {
			u.openEditor(*p, false)
		}
	})
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		if p := u.activeProfile(); p != nil {
			u.app.Clipboard().SetContent(p.Link())
			u.lastClipboard = p.Link() // don't re-import our own link
			u.app.SendNotification(fyne.NewNotification("MKConnect", "Share link of "+p.Name+" copied"))
		}
	})
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), u.confirmDelete)
	aboutBtn := widget.NewButtonWithIcon("About", theme.InfoIcon(), u.showAbout)

	toolbar := container.NewBorder(nil, nil, container.NewHBox(addBtn, importBtn), container.NewHBox(editBtn, copyBtn, deleteBtn))
	title := container.NewBorder(nil, nil, widget.NewLabelWithStyle("Accounts", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), aboutBtn)

	u.groupSelect = widget.NewSelect(nil, func(label string) {
		u.groupFilter = u.groupLabels[label]
		u.refreshProfiles()
	})
	u.groupUpdateBtn = widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
		if g, err := u.store.FindGroup(u.groupFilter); err == nil {
			u.updateSubscription(g.ID, true)
		}
	})
	u.groupDeleteBtn = widget.NewButtonWithIcon("", theme.DeleteIcon(), u.confirmDeleteGroup)
	groupBar := container.NewBorder(nil, nil, nil, container.NewHBox(u.groupUpdateBtn, u.groupDeleteBtn), u.groupSelect)

	u.usageCard = u.newUsageCard()

	u.emptyHint = widget.NewLabel("No accounts yet.\nUse Add or Import to create one.")
	u.emptyHint.Alignment = fyne.TextAlignCenter

	top := container.NewVBox(title, toolbar, groupBar, u.usageCard)
	u.profilesPanel = container.NewBorder(top, nil, nil, nil, container.NewStack(u.emptyHint, u.list))
	u.refreshProfiles()
	return u.profilesPanel
}

func profileSummary(p *profile.Profile) string {
	parts := []string{typeLabels[p.Type], p.Address()}
	if p.Transport.Network != "" {
		parts = append(parts, p.Transport.Network)
	}
	if p.TLS.Mode != "" {
		parts = append(parts, p.TLS.Mode)
	}
	return strings.Join(parts, " · ")
}

// targetGroup is the group new accounts go into: the one being viewed, unless it's a subscription.
func (u *ui) targetGroup() string {
	if g, err := u.store.FindGroup(u.groupFilter); err == nil && !g.IsSubscription() {
		return g.ID
	}
	return ""
}

// activeProfile returns the selected profile, or nil after telling the user to pick one.
func (u *ui) activeProfile() *profile.Profile {
	p, err := u.store.ActiveProfile()
	if err != nil {
		dialog.ShowInformation("No account selected", "Select an account in the list first.", u.win)
		return nil
	}
	return p
}

// refreshProfiles rebuilds the group picker, the filtered list and the usage card.
func (u *ui) refreshProfiles() {
	if u.groupFilter != filterAll && u.groupFilter != filterUngrouped {
		if _, err := u.store.FindGroup(u.groupFilter); err != nil {
			u.groupFilter = filterAll // the group was deleted
		}
	}

	u.groupLabels = map[string]string{labelAllGroups: filterAll}
	options := []string{labelAllGroups}
	selected := labelAllGroups
	for _, g := range u.store.Groups {
		label := fmt.Sprintf("%s (%d)", g.Name, u.store.GroupSize(g.ID))
		if g.IsSubscription() {
			label += " · subscription"
		}
		options = append(options, label)
		u.groupLabels[label] = g.ID
		if g.ID == u.groupFilter {
			selected = label
		}
	}
	if n := u.store.GroupSize(""); n > 0 && len(u.store.Groups) > 0 {
		label := fmt.Sprintf("%s (%d)", labelUngrouped, n)
		options = append(options, label)
		u.groupLabels[label] = filterUngrouped
		if u.groupFilter == filterUngrouped {
			selected = label
		}
	}
	u.groupSelect.Options = options
	u.groupSelect.Selected = selected
	u.groupSelect.Refresh()

	u.visible = u.visible[:0]
	for i := range u.store.Profiles {
		if u.groupFilter == filterAll || u.store.Profiles[i].Group == u.groupFilter {
			u.visible = append(u.visible, i)
		}
	}
	u.list.Refresh()
	u.list.UnselectAll()
	for row, i := range u.visible {
		if u.store.Profiles[i].ID == u.store.Active {
			u.list.Select(row)
			u.list.ScrollTo(row)
			break
		}
	}

	g, err := u.store.FindGroup(u.groupFilter)
	isGroup := err == nil
	setShown(u.groupDeleteBtn, isGroup)
	setShown(u.groupUpdateBtn, isGroup && g.IsSubscription())
	u.updateUsageCard()
	setShown(u.emptyHint, len(u.visible) == 0)
	// Showing/hiding the usage card changes the header height; re-layout the panel.
	u.profilesPanel.Refresh()
}

func setShown(o fyne.CanvasObject, visible bool) {
	if visible {
		o.Show()
	} else {
		o.Hide()
	}
}

// usage card: data quota of the selected subscription, like Hiddify's profile card.
func (u *ui) newUsageCard() *fyne.Container {
	u.usageTitle = widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	u.usageBar = widget.NewProgressBar()
	u.usageBar.TextFormatter = func() string { return "" }
	u.usageText = widget.NewLabel("")
	u.usageText.SizeName = theme.SizeNameCaptionText
	u.usageText.Wrapping = fyne.TextWrapWord
	return container.NewVBox(u.usageTitle, u.usageBar, u.usageText)
}

func (u *ui) updateUsageCard() {
	g, err := u.store.FindGroup(u.groupFilter)
	if err != nil || !g.IsSubscription() {
		u.usageCard.Hide()
		return
	}
	u.usageCard.Show()
	u.usageTitle.SetText(g.Name)
	lines := []string{}
	if usage := g.Usage; usage != nil {
		used := usage.Used()
		if usage.Total > 0 {
			u.usageBar.SetValue(min(1, float64(used)/float64(usage.Total)))
			u.usageBar.Show()
			left := max(0, usage.Total-used)
			lines = append(lines, fmt.Sprintf("%s of %s used · %s left", profile.FormatBytes(used), profile.FormatBytes(usage.Total), profile.FormatBytes(left)))
		} else {
			u.usageBar.Hide()
			lines = append(lines, fmt.Sprintf("%s used · unlimited", profile.FormatBytes(used)))
		}
		lines = append(lines, fmt.Sprintf("Upload %s · Download %s", profile.FormatBytes(usage.Upload), profile.FormatBytes(usage.Download)))
		if !usage.Expire.IsZero() {
			days := int(time.Until(usage.Expire).Hours() / 24)
			if days < 0 {
				lines = append(lines, "Expired on "+usage.Expire.Format("2006-01-02"))
			} else {
				lines = append(lines, fmt.Sprintf("Expires %s (%d days left)", usage.Expire.Format("2006-01-02"), days))
			}
		}
	} else {
		u.usageBar.Hide()
		lines = append(lines, "The provider doesn't report data usage.")
	}
	if !g.UpdatedAt.IsZero() {
		lines = append(lines, "Updated "+humanSince(g.UpdatedAt))
	}
	u.usageText.SetText(strings.Join(lines, "\n"))
}

func humanSince(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func (u *ui) confirmDelete() {
	p := u.activeProfile()
	if p == nil {
		return
	}
	id, name := p.ID, p.Name
	dialog.ShowConfirm("Delete account", fmt.Sprintf("Delete %q?", name), func(ok bool) {
		if !ok {
			return
		}
		if u.state != stateIdle && u.store.Active == id {
			u.disconnect(nil)
		}
		if err := u.store.Remove(id); err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		u.save()
		u.refreshProfiles()
	}, u.win)
}

func (u *ui) confirmDeleteGroup() {
	g, err := u.store.FindGroup(u.groupFilter)
	if err != nil {
		return
	}
	id := g.ID
	msg := fmt.Sprintf("Delete group %q and its %d account(s)?", g.Name, u.store.GroupSize(id))
	dialog.ShowConfirm("Delete group", msg, func(ok bool) {
		if !ok {
			return
		}
		if p, err := u.store.ActiveProfile(); err == nil && p.Group == id && u.state != stateIdle {
			u.disconnect(nil)
		}
		u.store.RemoveGroup(id)
		u.save()
		u.refreshProfiles()
	}, u.win)
}

// updateSubscription downloads a subscription in the background and applies it.
// interactive reports errors in a dialog; background refreshes only log them.
func (u *ui) updateSubscription(groupID string, interactive bool) {
	g, err := u.store.FindGroup(groupID)
	if err != nil || !g.IsSubscription() {
		return
	}
	url, name := g.URL, g.Name
	u.groupUpdateBtn.Disable()
	go func() {
		data, err := profile.FetchSubscription(url)
		fyne.Do(func() {
			u.groupUpdateBtn.Enable()
			if err != nil {
				u.logf("❌ subscription %s: %v", name, err)
				if interactive {
					dialog.ShowError(fmt.Errorf("update %s: %w", name, err), u.win)
				}
				return
			}
			g, gerr := u.store.FindGroup(groupID)
			if gerr != nil {
				return // deleted while downloading
			}
			n, errs := u.store.ApplySubscription(g, data, time.Now())
			for _, e := range errs {
				u.logf("⚠️  %s: %v", g.Name, e)
			}
			if n == 0 {
				if interactive {
					dialog.ShowError(fmt.Errorf("%s: no usable accounts", g.Name), u.win)
				}
				return
			}
			u.logf("✅ subscription %s updated: %d account(s)", g.Name, n)
			u.save()
			u.refreshProfiles()
		})
	}()
}

// autoUpdateSubscriptions refreshes subscriptions that are due, now and every 30 minutes.
func (u *ui) autoUpdateSubscriptions() {
	check := func() {
		for _, g := range u.store.Groups {
			if g.NeedsUpdate(time.Now()) {
				u.updateSubscription(g.ID, false)
			}
		}
	}
	check()
	go func() {
		for range time.Tick(30 * time.Minute) {
			fyne.Do(check)
		}
	}()
}

func (u *ui) showImport() {
	input := widget.NewMultiLineEntry()
	input.SetPlaceHolder("Paste vmess://, vless://, trojan://, ss://, ssh:// links (one per line)\nor a subscription URL (https://…)")
	input.Wrapping = fyne.TextWrapBreak
	input.SetMinRowsVisible(8)
	paste := widget.NewButtonWithIcon("Paste from clipboard", theme.ContentPasteIcon(), func() {
		input.SetText(u.app.Clipboard().Content())
	})

	var groupNames []string
	for _, g := range u.store.Groups {
		if !g.IsSubscription() {
			groupNames = append(groupNames, g.Name)
		}
	}
	group := widget.NewSelectEntry(groupNames)
	group.SetPlaceHolder("Group (optional): pick one or type a new name")
	if g, err := u.store.FindGroup(u.targetGroup()); err == nil {
		group.SetText(g.Name)
	}

	var d dialog.Dialog
	importBtn := widget.NewButtonWithIcon("Import", theme.ConfirmIcon(), nil)
	importBtn.Importance = widget.HighImportance
	importBtn.OnTapped = func() {
		text := strings.TrimSpace(input.Text)
		if text == "" {
			return
		}
		groupName := strings.TrimSpace(group.Text)
		d.Hide()
		if isURL(text) {
			// A URL becomes a subscription group that can be refreshed later.
			g := u.store.AddGroup(groupName, text)
			if g.Name == "" {
				g.Name = profile.SubscriptionName(text, "")
			}
			u.groupFilter = g.ID
			u.save()
			u.refreshProfiles()
			u.updateSubscription(g.ID, true)
			return
		}
		u.importText(text, groupName)
	}
	content := container.NewBorder(group, container.NewHBox(paste, layout.NewSpacer(), importBtn), nil, nil, input)
	d = dialog.NewCustom("Import accounts", "Cancel", content, u.win)
	d.Resize(fyne.NewSize(640, 400))
	d.Show()
}

func isURL(s string) bool {
	return !strings.Contains(s, "\n") && (strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"))
}

// importText adds every link in text, optionally into a (new or existing) local group.
func (u *ui) importText(text, groupName string) {
	groupID := ""
	if groupName != "" {
		g, err := u.store.FindGroup(groupName)
		if err != nil || g.IsSubscription() {
			g = u.store.AddGroup(groupName, "")
		}
		groupID = g.ID
	}
	profiles, errs := profile.ParseLinks(text)
	added := 0
	for _, p := range profiles {
		p.Group = groupID
		if _, err := u.store.Add(p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			continue
		}
		added++
	}
	if added > 0 {
		u.save()
		if groupID != "" {
			u.groupFilter = groupID
		}
		u.refreshProfiles()
	}
	msg := fmt.Sprintf("Imported %d account(s).", added)
	if len(errs) > 0 {
		lines := make([]string, 0, len(errs))
		for i, e := range errs {
			if i == 10 {
				lines = append(lines, fmt.Sprintf("… and %d more", len(errs)-10))
				break
			}
			lines = append(lines, "• "+e.Error())
		}
		msg += fmt.Sprintf("\n\nSkipped %d:\n%s", len(errs), strings.Join(lines, "\n"))
	}
	dialog.ShowInformation("Import", msg, u.win)
}

// checkClipboard imports share links found on the clipboard (Hiddify-style),
// skipping accounts that already exist.
func (u *ui) checkClipboard() {
	if !u.store.Settings.ClipboardImport {
		return
	}
	text := u.app.Clipboard().Content()
	if text == u.lastClipboard || !strings.Contains(text, "://") {
		return
	}
	u.lastClipboard = text
	profiles, _ := profile.ParseLinks(text)
	added := 0
	for _, p := range profiles {
		if ok, _ := u.store.AddUnique(p); ok {
			added++
		}
	}
	if added == 0 {
		return
	}
	u.save()
	u.refreshProfiles()
	msg := fmt.Sprintf("Added %d account(s) from the clipboard", added)
	u.logf("📋 %s", msg)
	u.app.SendNotification(fyne.NewNotification("MKConnect", msg))
}

package gui

import (
	"fmt"
	"strings"

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

func (u *ui) newProfilesPanel() fyne.CanvasObject {
	u.list = widget.NewList(
		func() int { return len(u.store.Profiles) },
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
			p := &u.store.Profiles[id]
			box := o.(*fyne.Container)
			box.Objects[0].(*widget.Label).SetText(p.Name)
			box.Objects[1].(*widget.Label).SetText(profileSummary(p))
		},
	)
	u.list.OnSelected = func(id widget.ListItemID) {
		p := &u.store.Profiles[id]
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
	u.selectActive()

	var addBtn *widget.Button
	addBtn = widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() {
		var items []*fyne.MenuItem
		for _, t := range profile.Types {
			items = append(items, fyne.NewMenuItem(typeLabels[t], func() {
				p := profile.Profile{Type: t}
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
			u.app.SendNotification(fyne.NewNotification("MKConnect", "Share link of "+p.Name+" copied"))
		}
	})
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), u.confirmDelete)

	toolbar := container.NewBorder(nil, nil, container.NewHBox(addBtn, importBtn), container.NewHBox(editBtn, copyBtn, deleteBtn))
	title := widget.NewLabelWithStyle("Accounts", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	u.emptyHint = widget.NewLabel("No accounts yet.\nUse Add or Import to create one.")
	u.emptyHint.Alignment = fyne.TextAlignCenter
	u.updateEmptyHint()
	return container.NewBorder(container.NewVBox(title, toolbar), nil, nil, nil, container.NewStack(u.emptyHint, u.list))
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

// activeProfile returns the selected profile, or nil after telling the user to pick one.
func (u *ui) activeProfile() *profile.Profile {
	p, err := u.store.ActiveProfile()
	if err != nil {
		dialog.ShowInformation("No account selected", "Select an account in the list first.", u.win)
		return nil
	}
	return p
}

func (u *ui) selectActive() {
	for i := range u.store.Profiles {
		if u.store.Profiles[i].ID == u.store.Active {
			u.list.Select(i)
			return
		}
	}
	u.list.UnselectAll()
}

func (u *ui) refreshProfiles() {
	u.list.Refresh()
	u.selectActive()
	u.updateEmptyHint()
}

func (u *ui) updateEmptyHint() {
	if len(u.store.Profiles) == 0 {
		u.emptyHint.Show()
	} else {
		u.emptyHint.Hide()
	}
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

func (u *ui) showImport() {
	input := widget.NewMultiLineEntry()
	input.SetPlaceHolder("Paste vmess://, vless://, trojan://, ss://, ssh:// links (one per line)\nor a subscription URL (https://…)")
	input.Wrapping = fyne.TextWrapBreak
	input.SetMinRowsVisible(8)
	paste := widget.NewButtonWithIcon("Paste from clipboard", theme.ContentPasteIcon(), func() {
		input.SetText(u.app.Clipboard().Content())
	})

	var d dialog.Dialog
	importBtn := widget.NewButtonWithIcon("Import", theme.ConfirmIcon(), nil)
	importBtn.Importance = widget.HighImportance
	importBtn.OnTapped = func() {
		text := strings.TrimSpace(input.Text)
		if text == "" {
			return
		}
		if isURL(text) {
			importBtn.Disable()
			importBtn.SetText("Downloading…")
			go func() {
				data, err := profile.FetchSubscription(text)
				fyne.Do(func() {
					importBtn.Enable()
					importBtn.SetText("Import")
					if err != nil {
						dialog.ShowError(err, u.win)
						return
					}
					d.Hide()
					u.importText(string(data))
				})
			}()
			return
		}
		d.Hide()
		u.importText(text)
	}
	content := container.NewBorder(nil, container.NewHBox(paste, widget.NewLabel(""), importBtn), nil, nil, input)
	d = dialog.NewCustom("Import accounts", "Cancel", content, u.win)
	d.Resize(fyne.NewSize(620, 360))
	d.Show()
}

func isURL(s string) bool {
	return !strings.Contains(s, "\n") && (strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://"))
}

func (u *ui) importText(text string) {
	profiles, errs := profile.ParseLinks(text)
	added := 0
	for _, p := range profiles {
		if _, err := u.store.Add(p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			continue
		}
		added++
	}
	if added > 0 {
		u.save()
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

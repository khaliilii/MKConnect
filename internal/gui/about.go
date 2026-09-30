package gui

import (
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/version"
)

func (u *ui) showAbout() {
	icon := canvas.NewImageFromResource(u.app.Icon())
	icon.FillMode = canvas.ImageFillContain
	icon.SetMinSize(fyne.NewSize(72, 72))

	title := widget.NewLabelWithStyle("MKConnect", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	ver := widget.NewLabelWithStyle("Version "+appVersion(u.app), fyne.TextAlignCenter, fyne.TextStyle{})
	desc := widget.NewLabelWithStyle("SSH, VMess, VLESS, Trojan and Shadowsocks client\nwith proxy, LAN sharing and TUN modes.", fyne.TextAlignCenter, fyne.TextStyle{})

	profileURL, _ := url.Parse(version.AuthorURL)
	projectURL, _ := url.Parse(version.ProjectURL)
	author := widget.NewHyperlinkWithStyle("github.com/"+version.Author, profileURL, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	project := widget.NewHyperlinkWithStyle("Source code & releases", projectURL, fyne.TextAlignCenter, fyne.TextStyle{})
	by := widget.NewLabelWithStyle("Developed by", fyne.TextAlignCenter, fyne.TextStyle{})

	content := container.NewVBox(
		container.NewCenter(icon), title, ver, desc,
		widget.NewSeparator(),
		by, author, project,
	)
	dialog.ShowCustom("About", "Close", content, u.win)
}

// appVersion prefers the version injected with -ldflags; packaged builds made
// by `fyne package` (fyne-cross, Android) override ldflags, so fall back to the
// version recorded in the app metadata.
func appVersion(a fyne.App) string {
	if version.Version != "dev" {
		return version.Version
	}
	if v := a.Metadata().Version; v != "" && v != "0.0.0" {
		return v
	}
	return version.Version
}

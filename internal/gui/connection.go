package gui

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

var (
	coreLabels = []string{"sing-box", "Xray", "External binary"}
	coreValues = []string{profile.CoreSingBox, profile.CoreXray, profile.CoreExternal}
	modeLabels = []string{"Proxy", "TUN (whole system)"}
	modeValues = []string{profile.ModeProxy, profile.ModeTUN}
)

func (u *ui) newConnectionPanel() fyne.CanvasObject {
	s := &u.store.Settings
	form := &rowForm{labels: map[fyne.CanvasObject]*widget.Label{}}

	core := widget.NewSelect(coreLabels, nil)
	core.SetSelected(labelFor(coreValues, coreLabels, s.Core))

	extPath := entry(s.ExternalPath, "path to sing-box or xray binary")
	extBrowse := widget.NewButtonWithIcon("", theme.FolderOpenIcon(), func() {
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err == nil && r != nil {
				extPath.SetText(r.URI().Path())
				r.Close()
			}
		}, u.win)
	})
	extKind := widget.NewSelect([]string{"sing-box", "Xray"}, nil)
	extKind.SetSelected(labelFor([]string{profile.CoreSingBox, profile.CoreXray}, []string{"sing-box", "Xray"}, s.ExternalKind))
	extBox := container.NewVBox(
		container.NewBorder(nil, nil, nil, extBrowse, extPath),
		container.NewBorder(nil, nil, widget.NewLabel("Config format"), nil, extKind),
	)

	mode := widget.NewRadioGroup(modeLabels, nil)
	mode.Horizontal = true
	mode.Required = true
	mode.SetSelected(labelFor(modeValues, modeLabels, s.Mode))
	tunWarning := widget.NewLabel("TUN mode needs administrator rights: start MKConnect with sudo (Linux/macOS) or \"Run as administrator\" (Windows).")
	tunWarning.Wrapping = fyne.TextWrapWord
	tunWarning.Importance = widget.WarningImportance

	port := entry(strconv.Itoa(s.ListenPort), "1080")
	port.Validator = validatePort
	lan := widget.NewCheck("Share with other devices on the network (LAN)", nil)
	lan.SetChecked(s.AllowLAN)
	proxyUser := entry(s.ProxyUser, "optional")
	proxyPass := widget.NewPasswordEntry()
	proxyPass.SetText(s.ProxyPass)
	proxyPass.SetPlaceHolder("optional")
	lanInfo := widget.NewLabel("")
	lanInfo.Wrapping = fyne.TextWrapWord
	lanInfo.Importance = widget.LowImportance
	remoteDNS := entry(s.RemoteDNS, "1.1.1.1")
	clipboard := widget.NewCheck("Auto-add links copied to the clipboard", nil)
	clipboard.SetChecked(s.ClipboardImport)

	updateVisibility := func() {
		form.setVisible(extBox, s.Core == profile.CoreExternal)
		form.setVisible(tunWarning, s.Mode == profile.ModeTUN && !isElevated())
		form.setVisible(lanInfo, s.AllowLAN)
		lanInfo.SetText(lanAddresses(s))
	}
	// Every change is saved immediately; a running connection picks it up on reconnect.
	changed := func() {
		s.Core = valueFor(coreValues, coreLabels, core.Selected)
		s.ExternalPath = strings.TrimSpace(extPath.Text)
		s.ExternalKind = valueFor([]string{profile.CoreSingBox, profile.CoreXray}, []string{"sing-box", "Xray"}, extKind.Selected)
		s.Mode = valueFor(modeValues, modeLabels, mode.Selected)
		if n, err := strconv.Atoi(strings.TrimSpace(port.Text)); err == nil && validatePort(port.Text) == nil {
			s.ListenPort = n
		}
		s.AllowLAN = lan.Checked
		s.ProxyUser, s.ProxyPass = strings.TrimSpace(proxyUser.Text), proxyPass.Text
		s.RemoteDNS = strings.TrimSpace(remoteDNS.Text)
		s.ClipboardImport = clipboard.Checked
		updateVisibility()
		u.save()
	}
	core.OnChanged = func(string) { changed() }
	extKind.OnChanged = func(string) { changed() }
	mode.OnChanged = func(string) { changed() }
	lan.OnChanged = func(bool) { changed() }
	clipboard.OnChanged = func(bool) { changed() }
	for _, e := range []*widget.Entry{extPath, port, proxyUser, proxyPass, remoteDNS} {
		e.OnChanged = func(string) { changed() }
	}

	settings := form.build([]*widget.FormItem{
		{Text: "Core", Widget: core},
		{Text: "", Widget: extBox},
		{Text: "Mode", Widget: mode},
		{Text: "", Widget: tunWarning},
		{Text: "Local port", Widget: port},
		{Text: "", Widget: lan},
		{Text: "", Widget: lanInfo},
		{Text: "Proxy user", Widget: proxyUser},
		{Text: "Proxy password", Widget: proxyPass},
		{Text: "Tunnel DNS", Widget: remoteDNS},
		{Text: "", Widget: clipboard},
	})
	updateVisibility()
	u.settingsBox = settings

	u.statusLabel = widget.NewLabelWithStyle("Disconnected", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	u.connectBtn = widget.NewButtonWithIcon("Connect", theme.MediaPlayIcon(), u.toggleConnection)
	u.connectBtn.Importance = widget.HighImportance

	header := widget.NewLabelWithStyle("Connection", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	footer := container.NewVBox(u.statusLabel, u.connectBtn)
	return container.NewBorder(header, footer, nil, nil, container.NewVScroll(settings))
}

func (u *ui) toggleConnection() {
	if u.state == stateIdle {
		u.connect()
	} else {
		u.disconnect(nil)
	}
}

func (u *ui) connect() {
	p := u.activeProfile()
	if p == nil {
		return
	}
	if err := u.store.Settings.Validate(); err != nil {
		dialog.ShowError(err, u.win)
		return
	}
	pc, s, id := *p, u.store.Settings, p.ID
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u.cancel, u.done = cancel, done
	u.setState(stateConnecting, pc.Name)

	go func() {
		err := engine.Run(ctx, pc, s, engine.Hooks{
			OnHostKey: func(key string) {
				fyne.Do(func() {
					if saved, err := u.store.Find(id); err == nil {
						saved.HostKey = key
						u.save()
					}
				})
			},
			OnStarted: func(session *engine.Session) {
				fyne.Do(func() {
					u.session = session
					u.setState(stateConnected, pc.Name)
				})
			},
		})
		fyne.Do(func() {
			if u.done == done {
				u.cancel, u.done, u.session = nil, nil, nil
				u.setState(stateIdle, "")
			}
			if err != nil && ctx.Err() == nil {
				dialog.ShowError(err, u.win)
			}
		})
		close(done)
	}()
}

// disconnect stops the running connection and calls then once it has fully closed.
func (u *ui) disconnect(then func()) {
	if u.cancel == nil {
		if then != nil {
			then()
		}
		return
	}
	done := u.done
	u.cancel()
	u.statusLabel.SetText("Disconnecting…")
	go func() {
		<-done
		if then != nil {
			fyne.Do(then)
		}
	}()
}

func (u *ui) reconnect() {
	u.disconnect(u.connect)
}

func (u *ui) setState(st connState, name string) {
	u.state = st
	switch st {
	case stateIdle:
		u.statusLabel.SetText("Disconnected")
		u.statusLabel.Importance = widget.MediumImportance
		u.connectBtn.SetText("Connect")
		u.connectBtn.SetIcon(theme.MediaPlayIcon())
		u.connectBtn.Importance = widget.HighImportance
	case stateConnecting:
		u.statusLabel.SetText("Connecting to " + name + "…")
		u.connectBtn.SetText("Cancel")
		u.connectBtn.SetIcon(theme.CancelIcon())
		u.connectBtn.Importance = widget.MediumImportance
	case stateConnected:
		s := &u.store.Settings
		u.statusLabel.SetText(fmt.Sprintf("Connected to %s (%s, %s)", name, s.Core, s.Mode))
		u.statusLabel.Importance = widget.SuccessImportance
		u.connectBtn.SetText("Disconnect")
		u.connectBtn.SetIcon(theme.MediaStopIcon())
		u.connectBtn.Importance = widget.DangerImportance
	}
	u.statusLabel.Refresh()
	u.connectBtn.Refresh()
	if u.trayConnect != nil {
		u.trayConnect.Label = map[bool]string{true: "Connect", false: "Disconnect"}[st == stateIdle]
		u.trayMenu.Refresh()
	}
}

// lanAddresses tells the user what other devices should enter as their proxy.
func lanAddresses(s *profile.Settings) string {
	var ips []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			ips = append(ips, net.JoinHostPort(ipnet.IP.String(), strconv.Itoa(s.ListenPort)))
		}
	}
	if len(ips) == 0 {
		return "No network address found."
	}
	proto := "SOCKS5 / HTTP"
	if s.Core != profile.CoreSingBox {
		proto = "SOCKS5"
	}
	msg := "Other devices can use " + proto + " proxy: " + strings.Join(ips, ", ")
	if s.ProxyUser == "" {
		msg += "\n⚠ No proxy password set: anyone on the network can use it."
	}
	return msg
}

func labelFor(values, labels []string, v string) string {
	for i := range values {
		if values[i] == v {
			return labels[i]
		}
	}
	return labels[0]
}

func valueFor(values, labels []string, l string) string {
	for i := range labels {
		if labels[i] == l {
			return values[i]
		}
	}
	return values[0]
}

// newSessionBox shows the inbound/outbound of the running connection and live traffic.
// relayout is called when the box appears or disappears so the parent can resize.
func (u *ui) newSessionBox(relayout func()) fyne.CanvasObject {
	caption := func() *widget.Label {
		l := widget.NewLabel("")
		l.SizeName = theme.SizeNameCaptionText
		l.Truncation = fyne.TextTruncateEllipsis
		return l
	}
	inbound, outbound, core := caption(), caption(), caption()
	upload := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	download := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})

	form := &rowForm{labels: map[fyne.CanvasObject]*widget.Label{}}
	box := form.build([]*widget.FormItem{
		{Text: "Inbound", Widget: inbound},
		{Text: "Outbound", Widget: outbound},
		{Text: "Core", Widget: core},
		{Text: "Upload", Widget: upload},
		{Text: "Download", Widget: download},
	})
	box.Hide()

	var (
		shown          *engine.Session
		lastUp, lastDn int64
		lastAt         time.Time
	)
	refresh := func() {
		s := u.session
		if s == nil {
			if shown != nil {
				box.Hide()
				shown = nil
				relayout()
			}
			return
		}
		if s != shown {
			shown, lastUp, lastDn, lastAt = s, 0, 0, time.Now()
			inbound.SetText(strings.Join(s.Inbounds, "  |  "))
			outbound.SetText(s.Outbound)
			core.SetText(s.Core)
			box.Show()
			relayout()
		}
		up, down, ok := s.Traffic()
		if !ok {
			upload.SetText("n/a (external core)")
			download.SetText("n/a (external core)")
			return
		}
		secs := time.Since(lastAt).Seconds()
		upload.SetText(fmt.Sprintf("%10s/s   total %s", profile.FormatBytes(int64(float64(up-lastUp)/secs)), profile.FormatBytes(up)))
		download.SetText(fmt.Sprintf("%10s/s   total %s", profile.FormatBytes(int64(float64(down-lastDn)/secs)), profile.FormatBytes(down)))
		lastUp, lastDn, lastAt = up, down, time.Now()
	}
	go func() {
		for range time.Tick(time.Second) {
			fyne.Do(refresh)
		}
	}()
	return box
}

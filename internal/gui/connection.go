package gui

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/elevate"
	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/gateway"
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

	labels := modeLabels
	if isMobile {
		labels = modeLabels[:1] // TUN on Android needs the VPN service (planned)
	}
	mode := widget.NewRadioGroup(labels, nil)
	mode.Horizontal = true
	mode.Required = true
	mode.SetSelected(labelFor(modeValues, modeLabels, s.Mode))
	tunWarning := widget.NewLabel(tunPrivilegeHint())
	tunWarning.Wrapping = fyne.TextWrapWord
	tunWarning.Importance = widget.LowImportance

	// Gateway mode: route devices on other network interfaces through the tunnel.
	shareNames := map[string]string{} // check label -> interface name
	share := widget.NewCheckGroup(nil, nil)
	shareHint := widget.NewLabel("")
	shareHint.Wrapping = fyne.TextWrapWord
	shareHint.Importance = widget.LowImportance
	shareHint.SizeName = theme.SizeNameCaptionText
	loadInterfaces := func() {
		ifaces, _ := gateway.Interfaces()
		shareNames = map[string]string{}
		var options, selected []string
		for _, ifc := range ifaces {
			label := ifc.String()
			shareNames[label] = ifc.Name
			options = append(options, label)
			if slices.Contains(s.ShareInterfaces, ifc.Name) {
				selected = append(selected, label)
			}
		}
		share.Options, share.Selected = options, selected
		share.Refresh()
	}
	loadInterfaces()
	refreshIfaces := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), loadInterfaces)
	shareBox := container.NewVBox(container.NewBorder(nil, nil, nil, refreshIfaces, share), shareHint)

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
	ipv6 := widget.NewCheck("IPv6 through the tunnel (only if the server has IPv6)", nil)
	ipv6.SetChecked(s.IPv6)
	autoReconnect := widget.NewCheck("Reconnect automatically when the connection drops or stops working", nil)
	autoReconnect.SetChecked(s.AutoReconnect)

	updateVisibility := func() {
		form.setVisible(extBox, s.Core == profile.CoreExternal)
		form.setVisible(tunWarning, s.Mode == profile.ModeTUN && !isElevated())
		form.setVisible(shareBox, s.Mode == profile.ModeTUN && !isMobile)
		shareHint.SetText(shareHintText(s.ShareInterfaces))
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
		s.IPv6 = ipv6.Checked
		s.AutoReconnect = autoReconnect.Checked
		updateVisibility()
		u.save()
	}
	core.OnChanged = func(string) { changed() }
	extKind.OnChanged = func(string) { changed() }
	mode.OnChanged = func(string) { changed() }
	lan.OnChanged = func(bool) { changed() }
	clipboard.OnChanged = func(bool) { changed() }
	ipv6.OnChanged = func(bool) { changed() }
	autoReconnect.OnChanged = func(bool) { changed() }
	share.OnChanged = func(labels []string) {
		if runtime.GOOS == "windows" && len(labels) > 1 {
			// Internet Connection Sharing supports one adapter: keep the newest choice.
			share.SetSelected(labels[len(labels)-1:])
			return
		}
		s.ShareInterfaces = s.ShareInterfaces[:0]
		for _, l := range labels {
			s.ShareInterfaces = append(s.ShareInterfaces, shareNames[l])
		}
		changed()
	}
	for _, e := range []*widget.Entry{extPath, port, proxyUser, proxyPass, remoteDNS} {
		e.OnChanged = func(string) { changed() }
	}

	settings := form.build([]*widget.FormItem{
		{Text: "Core", Widget: core},
		{Text: "", Widget: extBox},
		{Text: "Mode", Widget: mode},
		{Text: "", Widget: tunWarning},
		{Text: "Share with", Widget: shareBox},
		{Text: "Local port", Widget: port},
		{Text: "", Widget: lan},
		{Text: "", Widget: lanInfo},
		{Text: "Proxy user", Widget: proxyUser},
		{Text: "Proxy password", Widget: proxyPass},
		{Text: "Tunnel DNS", Widget: remoteDNS},
		{Text: "", Widget: clipboard},
		{Text: "", Widget: ipv6},
		{Text: "", Widget: autoReconnect},
	})
	updateVisibility()
	u.settingsBox = settings

	u.statusLabel = widget.NewLabelWithStyle("Disconnected", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	u.connectBtn = widget.NewButtonWithIcon("Connect", theme.MediaPlayIcon(), u.toggleConnection)
	u.connectBtn.Importance = widget.HighImportance

	// The status and Connect button are placed by build(): under the settings on
	// desktop, under the account list on mobile.
	u.connectFooter = container.NewVBox(u.statusLabel, u.connectBtn)
	header := widget.NewLabelWithStyle("Connection", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	return container.NewBorder(header, nil, nil, nil, container.NewVScroll(settings))
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
	u.health = health{}
	u.setState(stateConnecting, pc.Name)

	run := runConnection

	go func() {
		defer close(done)
		var lastErr error
		for attempt := 1; ; attempt++ {
			// Each attempt gets its own context, so a connection that stops
			// carrying traffic can be dropped without ending the whole run.
			attemptCtx, attemptCancel := context.WithCancel(ctx)
			fails := 0
			err := run(attemptCtx, pc, s, engine.Hooks{
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
						if u.done != done {
							return
						}
						u.session = session
						u.setState(stateConnected, pc.Name)
					})
				},
				OnHealth: func(latency time.Duration, herr error) {
					if herr == nil {
						fails, attempt = 0, 1 // a working connection starts the count over
					} else {
						fails++
					}
					fyne.Do(func() {
						if u.done != done {
							return
						}
						u.health = health{at: time.Now(), latency: latency, err: herr}
						if u.state == stateConnected {
							u.setState(stateConnected, pc.Name)
						}
					})
					if fails == healthFailsBeforeReconnect && s.AutoReconnect {
						u.logf("⚠️  no traffic through %s after %d checks; reconnecting", pc.Name, fails)
						attemptCancel()
					}
				},
			})
			attemptCancel()
			if err != nil {
				lastErr = err
			}
			if ctx.Err() != nil {
				return // the user disconnected
			}
			if !s.AutoReconnect || attempt >= maxReconnectAttempts {
				if lastErr != nil {
					fyne.Do(func() { dialog.ShowError(lastErr, u.win) })
				}
				return
			}
			wait := reconnectDelay(attempt)
			if err != nil {
				u.logf("⚠️  %s stopped: %v", pc.Name, err)
			}
			u.logf("🔄 reconnecting to %s in %s (attempt %d of %d)", pc.Name, wait, attempt+1, maxReconnectAttempts)
			fyne.Do(func() {
				if u.done != done {
					return
				}
				u.session, u.health = nil, health{}
				u.setState(stateReconnecting, pc.Name)
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			fyne.Do(func() {
				if u.done == done {
					u.setState(stateConnecting, pc.Name)
				}
			})
		}
	}()
	go func() {
		<-done
		fyne.Do(func() {
			if u.done == done {
				u.cancel, u.done, u.session = nil, nil, nil
				u.health = health{}
				u.setState(stateIdle, "")
			}
		})
	}()
}

// Reconnect policy: a dropped connection is retried with a growing delay,
// and a connection that runs but carries no traffic is dropped and retried
// too. A healthy connection resets the attempt count.
const (
	maxReconnectAttempts       = 10
	healthFailsBeforeReconnect = 2
)

// reconnectDelay is how long to wait before attempt+1; a variable so tests
// don't have to wait.
var reconnectDelay = func(attempt int) time.Duration {
	return min(time.Duration(attempt)*2*time.Second, 30*time.Second)
}

// runConnection runs one connection and blocks until it ends. TUN mode
// creates network interfaces, which needs root/Administrator: rather than
// asking users to start the app elevated, the core then runs in a helper that
// the system's own permission prompt starts. Tests replace this.
var runConnection = func(ctx context.Context, p profile.Profile, s profile.Settings, hooks engine.Hooks) error {
	if s.Mode == profile.ModeTUN && !isElevated() && !isMobile {
		return elevate.Run(ctx, p, s, hooks)
	}
	return engine.Run(ctx, p, s, hooks)
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
	case stateConnecting, stateReconnecting:
		text := "Connecting to " + name + "…"
		if st == stateReconnecting {
			text = "Connection lost; reconnecting to " + name + "…"
		}
		u.statusLabel.SetText(text)
		u.statusLabel.Importance = widget.MediumImportance
		u.connectBtn.SetText("Cancel")
		u.connectBtn.SetIcon(theme.CancelIcon())
		u.connectBtn.Importance = widget.MediumImportance
	case stateConnected:
		s := &u.store.Settings
		text := fmt.Sprintf("Connected to %s (%s, %s)", name, s.Core, s.Mode)
		importance := widget.SuccessImportance
		switch {
		case u.health.at.IsZero():
			text += " · checking the connection…"
		case u.health.err != nil:
			// The core is up but nothing reaches the internet: say so instead
			// of showing a green "Connected" the user can't use.
			text = fmt.Sprintf("Connected to %s, but no internet: %s", name, u.health.err)
			importance = widget.WarningImportance
		default:
			text += fmt.Sprintf(" · %d ms", u.health.latency.Milliseconds())
		}
		u.statusLabel.SetText(text)
		u.statusLabel.Importance = importance
		u.connectBtn.SetText("Disconnect")
		u.connectBtn.SetIcon(theme.MediaStopIcon())
		u.connectBtn.Importance = widget.DangerImportance
	}
	u.statusLabel.Refresh()
	u.connectBtn.Refresh()
	if u.refreshSession != nil {
		u.refreshSession() // show or hide the session box right away
	}
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
	u.refreshSession = refresh
	go func() {
		for range time.Tick(sessionRefreshInterval) {
			fyne.Do(refresh)
		}
	}()
	return box
}

// sessionRefreshInterval is how often the traffic counters update; tests
// make it long, so the background refresh doesn't race the test driver.
var sessionRefreshInterval = time.Second

func tunPrivilegeHint() string {
	switch runtime.GOOS {
	case "windows":
		return "TUN mode needs administrator rights: Windows will ask for permission when you connect."
	case "darwin":
		return "TUN mode needs administrator rights: macOS will ask for your password when you connect."
	}
	return "TUN mode needs root: the system will ask for your password when you connect."
}

func shareHintText(shared []string) string {
	if len(shared) == 0 {
		return "Optional: tick network cards (Ethernet, a second Wi-Fi, hotspot) whose devices should " +
			"reach the internet through this tunnel (gateway mode)."
	}
	return gateway.Hint(shared)
}

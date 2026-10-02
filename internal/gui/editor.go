package gui

import (
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

var (
	vmessCiphers  = []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
	vlessFlows    = []string{"", "xtls-rprx-vision"}
	ssMethods     = []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none"}
	networks      = []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"}
	tlsModes      = []string{"none", "tls", "reality"}
	fingerprints  = []string{"", "chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized"}
	optionalLabel = "(none)"
)

// openEditor shows a window for creating or editing a profile.
func (u *ui) openEditor(p profile.Profile, isNew bool) {
	title := "Edit " + p.Name
	if isNew {
		title = "New " + typeLabels[p.Type] + " account"
	}
	w := u.app.NewWindow(title)

	name := entry(p.Name, "My server")
	server := entry(p.Server, "example.com or 1.2.3.4")
	port := entry(strconv.Itoa(p.Port), "443")
	port.Validator = validatePort
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Server", server),
		widget.NewFormItem("Port", port),
	}

	// Each collector copies its widgets back onto the profile being saved.
	var collect []func(*profile.Profile)
	collect = append(collect, func(p *profile.Profile) {
		p.Name, p.Server = strings.TrimSpace(name.Text), strings.TrimSpace(server.Text)
		p.Port, _ = strconv.Atoi(strings.TrimSpace(port.Text))
	})

	switch p.Type {
	case profile.TypeSSH:
		user := entry(p.User, "root")
		pass := widget.NewPasswordEntry()
		pass.SetText(p.Password)
		key := entry(p.PrivateKeyPath, "optional, e.g. ~/.ssh/id_ed25519")
		browse := widget.NewButtonWithIcon("", theme.FolderOpenIcon(), func() {
			dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
				if err == nil && r != nil {
					key.SetText(r.URI().Path())
					r.Close()
				}
			}, w)
		})
		hostKey := p.HostKey
		hostKeyLabel := widget.NewLabel(hostKeyText(hostKey))
		hostKeyLabel.Wrapping = fyne.TextWrapBreak
		resetHostKey := widget.NewButton("Forget", func() {
			hostKey = ""
			hostKeyLabel.SetText(hostKeyText(""))
		})
		items = append(items,
			widget.NewFormItem("Username", user),
			widget.NewFormItem("Password", pass),
			widget.NewFormItem("Private key", container.NewBorder(nil, nil, nil, browse, key)),
			widget.NewFormItem("Host key", container.NewBorder(nil, nil, nil, resetHostKey, hostKeyLabel)),
		)
		collect = append(collect, func(p *profile.Profile) {
			p.User, p.Password = strings.TrimSpace(user.Text), pass.Text
			p.PrivateKeyPath, p.HostKey = strings.TrimSpace(key.Text), hostKey
		})

	case profile.TypeVMess, profile.TypeVLESS:
		uuid := entry(p.UUID, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
		items = append(items, widget.NewFormItem("UUID", uuid))
		if p.Type == profile.TypeVMess {
			cipher := selectOf(vmessCiphers, orDefault(p.Security, "auto"))
			alterID := entry(strconv.Itoa(p.AlterID), "0")
			items = append(items, widget.NewFormItem("Encryption", cipher), widget.NewFormItem("Alter ID", alterID))
			collect = append(collect, func(p *profile.Profile) {
				p.Security = cipher.Selected
				p.AlterID, _ = strconv.Atoi(strings.TrimSpace(alterID.Text))
			})
		} else {
			flow := selectOf(vlessFlows, p.Flow)
			items = append(items, widget.NewFormItem("Flow", flow))
			collect = append(collect, func(p *profile.Profile) { p.Flow = fromOptional(flow.Selected) })
		}
		collect = append(collect, func(p *profile.Profile) { p.UUID = strings.TrimSpace(uuid.Text) })

	case profile.TypeTrojan:
		pass := widget.NewPasswordEntry()
		pass.SetText(p.Password)
		items = append(items, widget.NewFormItem("Password", pass))
		collect = append(collect, func(p *profile.Profile) { p.Password = pass.Text })

	case profile.TypeShadowsocks:
		method := widget.NewSelectEntry(ssMethods)
		method.SetText(orDefault(p.Method, "2022-blake3-aes-128-gcm"))
		pass := widget.NewPasswordEntry()
		pass.SetText(p.Password)
		items = append(items, widget.NewFormItem("Method", method), widget.NewFormItem("Password", pass))
		collect = append(collect, func(p *profile.Profile) {
			p.Method, p.Password = strings.TrimSpace(method.Text), pass.Text
		})
	}

	if p.Type == profile.TypeHysteria2 || p.Type == profile.TypeTUIC {
		quicItems, collectQUIC := quicForm(&p)
		items = append(items, quicItems...)
		collect = append(collect, collectQUIC)
	}

	form := &rowForm{labels: map[fyne.CanvasObject]*widget.Label{}}
	var applyVisibility func()
	if p.Type == profile.TypeVMess || p.Type == profile.TypeVLESS || p.Type == profile.TypeTrojan {
		transportItems, collectTransport, apply := transportForm(&p, form.setVisible)
		items = append(items, transportItems...)
		collect = append(collect, collectTransport)
		applyVisibility = apply
	}
	formBox := form.build(items)
	if applyVisibility != nil {
		applyVisibility()
	}

	save := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		edited := p
		for _, c := range collect {
			c(&edited)
		}
		if err := u.saveProfile(edited, isNew); err != nil {
			dialog.ShowError(err, w)
			return
		}
		w.Close()
	})
	save.Importance = widget.HighImportance
	cancel := widget.NewButton("Cancel", w.Close)

	buttons := container.NewHBox(widget.NewLabel(""), cancel, save)
	w.SetContent(container.NewBorder(nil, container.NewPadded(container.NewBorder(nil, nil, nil, buttons)), nil, nil,
		container.NewVScroll(container.NewPadded(formBox))))
	w.Resize(fyne.NewSize(560, 640))
	w.CenterOnScreen()
	w.Show()
}

// transportForm builds the transport and TLS rows shared by VMess, VLESS and Trojan.
func transportForm(p *profile.Profile, setVisible func(fyne.CanvasObject, bool)) ([]*widget.FormItem, func(*profile.Profile), func()) {
	network := selectOf(networks, orDefault(p.Transport.Network, "tcp"))
	path := entry(p.Transport.Path, "/path (ws, httpupgrade, xhttp)")
	host := entry(p.Transport.Host, "Host header (ws, httpupgrade, xhttp)")
	service := entry(p.Transport.ServiceName, "gRPC service name")

	security := selectOf(tlsModes, orDefault(p.TLS.Mode, "none"))
	sni := entry(p.TLS.SNI, "server name (defaults to server)")
	alpn := entry(strings.Join(p.TLS.ALPN, ","), "h2,http/1.1")
	fp := selectOf(fingerprints, p.TLS.Fingerprint)
	insecure := widget.NewCheck("Allow insecure certificate (sing-box only)", nil)
	insecure.SetChecked(p.TLS.Insecure)
	pbk := entry(p.TLS.RealityPublicKey, "REALITY public key")
	sid := entry(p.TLS.RealityShortID, "REALITY short id")

	// Only show the rows that apply to the chosen transport and security.
	updateTransport := func(n string) {
		setVisible(path, n == "ws" || n == "httpupgrade" || n == "xhttp")
		setVisible(host, n == "ws" || n == "httpupgrade" || n == "xhttp")
		setVisible(service, n == "grpc")
	}
	updateSecurity := func(m string) {
		setVisible(sni, m != "none")
		setVisible(fp, m != "none")
		setVisible(alpn, m == "tls")
		setVisible(insecure, m == "tls")
		setVisible(pbk, m == "reality")
		setVisible(sid, m == "reality")
	}
	network.OnChanged = updateTransport
	security.OnChanged = updateSecurity
	apply := func() {
		updateTransport(network.Selected)
		updateSecurity(security.Selected)
	}

	items := []*widget.FormItem{
		{Text: "Transport", Widget: network},
		{Text: "Path", Widget: path},
		{Text: "Host", Widget: host},
		{Text: "Service name", Widget: service},
		{Text: "Security", Widget: security},
		{Text: "SNI", Widget: sni},
		{Text: "ALPN", Widget: alpn},
		{Text: "Fingerprint", Widget: fp},
		{Text: "", Widget: insecure},
		{Text: "Public key", Widget: pbk},
		{Text: "Short ID", Widget: sid},
	}
	collect := func(p *profile.Profile) {
		p.Transport = profile.Transport{}
		switch n := network.Selected; n {
		case "ws", "httpupgrade", "xhttp":
			p.Transport = profile.Transport{Network: n, Path: strings.TrimSpace(path.Text), Host: strings.TrimSpace(host.Text)}
		case "grpc":
			p.Transport = profile.Transport{Network: n, ServiceName: strings.TrimSpace(service.Text)}
		}
		p.TLS = profile.TLS{}
		if m := security.Selected; m != "none" {
			p.TLS = profile.TLS{Mode: m, SNI: strings.TrimSpace(sni.Text), Fingerprint: fromOptional(fp.Selected)}
			if m == "tls" {
				p.TLS.ALPN = splitComma(alpn.Text)
				p.TLS.Insecure = insecure.Checked
			} else {
				p.TLS.RealityPublicKey, p.TLS.RealityShortID = strings.TrimSpace(pbk.Text), strings.TrimSpace(sid.Text)
			}
		}
	}
	return items, collect, apply
}

var (
	congestionControls = []string{"bbr", "cubic", "new_reno"}
	udpRelayModes      = []string{"native", "quic"}
)

// quicForm builds the rows for Hysteria2 and TUIC (QUIC with TLS).
func quicForm(p *profile.Profile) ([]*widget.FormItem, func(*profile.Profile)) {
	var items []*widget.FormItem
	var collect []func(*profile.Profile)

	pass := widget.NewPasswordEntry()
	pass.SetText(p.Password)
	if p.Type == profile.TypeTUIC {
		uuid := entry(p.UUID, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
		cc := selectOf(congestionControls, orDefault(p.CongestionControl, "bbr"))
		relay := selectOf(udpRelayModes, orDefault(p.UDPRelayMode, "native"))
		items = append(items, widget.NewFormItem("UUID", uuid), widget.NewFormItem("Password", pass),
			widget.NewFormItem("Congestion", cc), widget.NewFormItem("UDP relay", relay))
		collect = append(collect, func(p *profile.Profile) {
			p.UUID, p.CongestionControl, p.UDPRelayMode = strings.TrimSpace(uuid.Text), cc.Selected, relay.Selected
		})
	} else {
		items = append(items, widget.NewFormItem("Password", pass))
	}
	collect = append(collect, func(p *profile.Profile) { p.Password = pass.Text })

	if p.Type == profile.TypeHysteria2 {
		obfs := entry(p.ObfsPassword, "salamander password (optional)")
		up := entry(intText(p.UpMbps), "optional")
		down := entry(intText(p.DownMbps), "optional")
		items = append(items, widget.NewFormItem("Obfs password", obfs),
			widget.NewFormItem("Up Mbps", up), widget.NewFormItem("Down Mbps", down))
		collect = append(collect, func(p *profile.Profile) {
			p.ObfsPassword = strings.TrimSpace(obfs.Text)
			p.UpMbps, _ = strconv.Atoi(strings.TrimSpace(up.Text))
			p.DownMbps, _ = strconv.Atoi(strings.TrimSpace(down.Text))
		})
	}

	sni := entry(p.TLS.SNI, "server name (defaults to server)")
	alpn := entry(strings.Join(p.TLS.ALPN, ","), "h3")
	insecure := widget.NewCheck("Allow insecure certificate", nil)
	insecure.SetChecked(p.TLS.Insecure)
	tlsItems := []*widget.FormItem{
		widget.NewFormItem("SNI", sni), widget.NewFormItem("ALPN", alpn), widget.NewFormItem("", insecure),
	}
	collect = append(collect, func(p *profile.Profile) {
		p.TLS = profile.TLS{Mode: "tls", SNI: strings.TrimSpace(sni.Text), ALPN: splitComma(alpn.Text), Insecure: insecure.Checked}
	})
	return append(items, tlsItems...), func(p *profile.Profile) {
		for _, c := range collect {
			c(p)
		}
	}
}

func intText(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// saveProfile validates and stores a new or edited profile.
func (u *ui) saveProfile(p profile.Profile, isNew bool) error {
	if p.Name == "" {
		p.Name = p.Type + "-" + p.Server
	}
	if isNew {
		added, err := u.store.Add(p)
		if err != nil {
			return err
		}
		u.store.Active = added.ID
	} else {
		if err := p.Validate(); err != nil {
			return err
		}
		existing, err := u.store.Find(p.ID)
		if err != nil {
			return err
		}
		if p.Type == profile.TypeSSH && (existing.Server != p.Server || existing.Port != p.Port) {
			p.HostKey = "" // a different server has a different host key
		}
		*existing = p
	}
	u.save()
	u.refreshProfiles()
	return nil
}

func hostKeyText(key string) string {
	if key == "" {
		return "Not pinned yet (saved on first connect)"
	}
	return engine.Fingerprint(key)
}

func entry(text, placeholder string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(text)
	e.SetPlaceHolder(placeholder)
	return e
}

// selectOf returns a Select where the empty option is shown as "(none)".
func selectOf(options []string, selected string) *widget.Select {
	shown := make([]string, len(options))
	for i, o := range options {
		shown[i] = orDefault(o, optionalLabel)
	}
	s := widget.NewSelect(shown, nil)
	s.SetSelected(orDefault(selected, optionalLabel))
	return s
}

func fromOptional(s string) string {
	if s == optionalLabel {
		return ""
	}
	return s
}

// rowForm is a two-column form whose rows can be hidden together with their
// labels (widget.Form keeps the label of a hidden widget on screen).
type rowForm struct {
	labels map[fyne.CanvasObject]*widget.Label
}

func (f *rowForm) build(items []*widget.FormItem) *fyne.Container {
	objs := make([]fyne.CanvasObject, 0, 2*len(items))
	for _, it := range items {
		if isMobile {
			// Phones are too narrow for a label column: put each label above its field.
			if it.Text != "" {
				l := widget.NewLabelWithStyle(it.Text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
				l.SizeName = theme.SizeNameCaptionText
				f.labels[it.Widget] = l
				objs = append(objs, l)
			}
			objs = append(objs, it.Widget)
			continue
		}
		l := widget.NewLabelWithStyle(it.Text, fyne.TextAlignTrailing, fyne.TextStyle{Bold: true})
		f.labels[it.Widget] = l
		objs = append(objs, l, it.Widget)
	}
	if isMobile {
		return container.NewVBox(objs...)
	}
	return container.New(layout.NewFormLayout(), objs...)
}

func (f *rowForm) setVisible(o fyne.CanvasObject, visible bool) {
	objs := []fyne.CanvasObject{o}
	if l, ok := f.labels[o]; ok && l != nil {
		objs = append(objs, l)
	}
	for _, c := range objs {
		if visible {
			c.Show()
		} else {
			c.Hide()
		}
	}
}

func validatePort(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func splitComma(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

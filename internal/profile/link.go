package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ParseLink converts a share link (vmess://, vless://, trojan://, ss://, ssh://) into a profile.
func ParseLink(link string) (Profile, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return Profile{}, fmt.Errorf("not a share link: %q", link)
	}
	var (
		p   Profile
		err error
	)
	switch strings.ToLower(scheme) {
	case "vmess":
		p, err = parseVMess(link)
	case "vless", "trojan":
		p, err = parseURLLink(link)
	case "ss":
		p, err = parseShadowsocks(link)
	case "ssh":
		p, err = parseSSH(link)
	case "hysteria2", "hy2":
		p, err = parseHysteria2(link)
	case "tuic":
		p, err = parseTUIC(link)
	default:
		return Profile{}, fmt.Errorf("unsupported link scheme %q", scheme)
	}
	if err != nil {
		return Profile{}, err
	}
	if p.Name == "" {
		p.Name = p.Type + "-" + p.Server
	}
	return p, p.Validate()
}

// linkPattern finds share links inside arbitrary text, e.g. a chat message
// like "Server 1: vless://... Server 2: trojan://...".
var linkPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>` + "`" + `]+`)

// ExtractLinks returns the share links found in text, in order. Plain
// http(s) URLs (e.g. a subscription address) are not share links and are skipped.
// A base64-encoded list (subscription content) is decoded first.
func ExtractLinks(text string) []string {
	text = strings.TrimSpace(text)
	if !strings.Contains(text, "://") {
		if decoded, err := decodeBase64(strings.Join(strings.Fields(text), "")); err == nil {
			text = string(decoded)
		}
	}
	var links []string
	for _, l := range linkPattern.FindAllString(text, -1) {
		scheme, _, _ := strings.Cut(strings.ToLower(l), "://")
		if scheme == "http" || scheme == "https" {
			continue
		}
		links = append(links, strings.TrimRight(l, ".,;)]}"))
	}
	return links
}

// ParseLinks parses every share link found in text (one or many, separated by
// newlines, spaces or surrounding text, or a base64-encoded subscription body).
func ParseLinks(text string) ([]Profile, []error) {
	var (
		out  []Profile
		errs []error
	)
	for _, link := range ExtractLinks(text) {
		p, err := ParseLink(link)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, p)
	}
	return out, errs
}

// flexInt accepts both 443 and "443" as used by different vmess link generators.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	*f = flexInt(n)
	return err
}

// vmessLink is the v2rayN vmess:// JSON payload.
type vmessLink struct {
	PS   string  `json:"ps"`
	Add  string  `json:"add"`
	Port flexInt `json:"port"`
	ID   string  `json:"id"`
	Aid  flexInt `json:"aid"`
	Scy  string  `json:"scy"`
	Net  string  `json:"net"`
	Type string  `json:"type"`
	Host string  `json:"host"`
	Path string  `json:"path"`
	TLS  string  `json:"tls"`
	SNI  string  `json:"sni"`
	ALPN string  `json:"alpn"`
	FP   string  `json:"fp"`
}

func parseVMess(link string) (Profile, error) {
	raw, err := decodeBase64(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return Profile{}, fmt.Errorf("vmess: bad base64: %w", err)
	}
	var v vmessLink
	if err := json.Unmarshal(raw, &v); err != nil {
		return Profile{}, fmt.Errorf("vmess: bad json: %w", err)
	}
	p := Profile{
		Name:     v.PS,
		Type:     TypeVMess,
		Server:   v.Add,
		Port:     int(v.Port),
		UUID:     v.ID,
		AlterID:  int(v.Aid),
		Security: v.Scy,
	}
	p.Transport = Transport{Network: normalizeNetwork(v.Net), Path: v.Path, Host: v.Host}
	if p.Transport.Network == "grpc" {
		p.Transport.ServiceName, p.Transport.Path = v.Path, ""
	}
	if v.TLS == "tls" || v.TLS == "reality" {
		p.TLS = TLS{Mode: v.TLS, SNI: v.SNI, Fingerprint: v.FP, ALPN: splitList(v.ALPN)}
	}
	return p, nil
}

// parseURLLink handles the shared URL format of vless:// and trojan://.
func parseURLLink(link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, fmt.Errorf("%s: bad port %q", u.Scheme, u.Port())
	}
	q := u.Query()
	p := Profile{Name: u.Fragment, Server: u.Hostname(), Port: port}
	switch u.Scheme {
	case "vless":
		p.Type, p.UUID, p.Flow = TypeVLESS, u.User.Username(), q.Get("flow")
	case "trojan":
		p.Type, p.Password = TypeTrojan, u.User.Username()
	}
	p.Transport = Transport{
		Network:     normalizeNetwork(q.Get("type")),
		Path:        q.Get("path"),
		Host:        q.Get("host"),
		ServiceName: q.Get("serviceName"),
	}
	security := q.Get("security")
	if security == "" && p.Type == TypeTrojan {
		security = "tls" // trojan is TLS by definition
	}
	if security == "tls" || security == "reality" {
		p.TLS = TLS{
			Mode:             security,
			SNI:              q.Get("sni"),
			Fingerprint:      q.Get("fp"),
			ALPN:             splitList(q.Get("alpn")),
			Insecure:         q.Get("allowInsecure") == "1" || q.Get("insecure") == "1",
			RealityPublicKey: q.Get("pbk"),
			RealityShortID:   q.Get("sid"),
		}
	}
	return p, nil
}

func parseShadowsocks(link string) (Profile, error) {
	body := strings.TrimPrefix(link, "ss://")
	body, name, _ := strings.Cut(body, "#")
	name, _ = url.PathUnescape(name)
	body, _, _ = strings.Cut(body, "?") // plugins are not supported

	var userinfo, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		// SIP002: ss://base64(method:password)@host:port
		userinfo, hostport = body[:at], body[at+1:]
		if dec, err := decodeBase64(userinfo); err == nil {
			userinfo = string(dec)
		} else if unescaped, err := url.PathUnescape(userinfo); err == nil {
			userinfo = unescaped
		}
	} else {
		// Legacy: ss://base64(method:password@host:port)
		dec, err := decodeBase64(body)
		if err != nil {
			return Profile{}, fmt.Errorf("ss: bad base64: %w", err)
		}
		at := strings.LastIndex(string(dec), "@")
		if at < 0 {
			return Profile{}, fmt.Errorf("ss: missing server")
		}
		userinfo, hostport = string(dec[:at]), string(dec[at+1:])
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok {
		return Profile{}, fmt.Errorf("ss: missing method or password")
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Profile{}, fmt.Errorf("ss: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Profile{}, fmt.Errorf("ss: bad port %q", portStr)
	}
	return Profile{Name: name, Type: TypeShadowsocks, Server: host, Port: port, Method: method, Password: password}, nil
}

func parseSSH(link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, err
	}
	port := 22
	if u.Port() != "" {
		if port, err = strconv.Atoi(u.Port()); err != nil {
			return Profile{}, fmt.Errorf("ssh: bad port %q", u.Port())
		}
	}
	pass, _ := u.User.Password()
	return Profile{
		Name: u.Fragment, Type: TypeSSH, Server: u.Hostname(), Port: port,
		User: u.User.Username(), Password: pass,
	}, nil
}

// portHopping matches a port-hopping authority ("host:443,20000-30000") to its
// first port, which net/url can parse. Port hopping itself isn't supported.
var portHopping = regexp.MustCompile(`^([^/?#]*:)(\d+)[,-][\d,-]*`)

func parseHysteria2(link string) (Profile, error) {
	scheme, rest, _ := strings.Cut(link, "://")
	u, err := url.Parse(scheme + "://" + portHopping.ReplaceAllString(rest, "${1}${2}"))
	if err != nil {
		return Profile{}, err
	}
	port := 443
	if u.Port() != "" {
		if port, err = strconv.Atoi(u.Port()); err != nil {
			return Profile{}, fmt.Errorf("hysteria2: bad port %q", u.Port())
		}
	}
	auth := u.User.Username()
	if pass, ok := u.User.Password(); ok {
		auth += ":" + pass
	}
	q := u.Query()
	p := Profile{
		Name: u.Fragment, Type: TypeHysteria2, Server: u.Hostname(), Port: port, Password: auth,
		TLS: TLS{Mode: "tls", SNI: q.Get("sni"), ALPN: splitList(q.Get("alpn")),
			Insecure: q.Get("insecure") == "1"},
	}
	if q.Get("obfs") == "salamander" {
		p.ObfsPassword = q.Get("obfs-password")
	}
	p.UpMbps, _ = strconv.Atoi(q.Get("upmbps"))
	p.DownMbps, _ = strconv.Atoi(q.Get("downmbps"))
	return p, nil
}

func parseTUIC(link string) (Profile, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Profile{}, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Profile{}, fmt.Errorf("tuic: bad port %q", u.Port())
	}
	pass, _ := u.User.Password()
	q := u.Query()
	insecure := q.Get("allow_insecure") == "1" || q.Get("insecure") == "1"
	return Profile{
		Name: u.Fragment, Type: TypeTUIC, Server: u.Hostname(), Port: port,
		UUID: u.User.Username(), Password: pass,
		CongestionControl: q.Get("congestion_control"), UDPRelayMode: q.Get("udp_relay_mode"),
		TLS: TLS{Mode: "tls", SNI: q.Get("sni"), ALPN: splitList(q.Get("alpn")), Insecure: insecure},
	}, nil
}

// Link renders the profile back into a share link.
func (p *Profile) Link() string {
	switch p.Type {
	case TypeVMess:
		v := vmessLink{
			PS: p.Name, Add: p.Server, Port: flexInt(p.Port), ID: p.UUID, Aid: flexInt(p.AlterID),
			Scy: p.Security, Net: p.Transport.Network, Host: p.Transport.Host, Path: p.Transport.Path,
			TLS: p.TLS.Mode, SNI: p.TLS.SNI, FP: p.TLS.Fingerprint, ALPN: strings.Join(p.TLS.ALPN, ","),
		}
		if v.Net == "grpc" {
			v.Path = p.Transport.ServiceName
		}
		data, _ := json.Marshal(struct {
			V string `json:"v"`
			vmessLink
		}{"2", v})
		return "vmess://" + base64.StdEncoding.EncodeToString(data)
	case TypeVLESS, TypeTrojan:
		scheme, user := "vless", p.UUID
		if p.Type == TypeTrojan {
			scheme, user = "trojan", p.Password
		}
		q := url.Values{}
		setIf(q, "flow", p.Flow)
		setIf(q, "type", p.Transport.Network)
		setIf(q, "path", p.Transport.Path)
		setIf(q, "host", p.Transport.Host)
		setIf(q, "serviceName", p.Transport.ServiceName)
		setIf(q, "security", p.TLS.Mode)
		setIf(q, "sni", p.TLS.SNI)
		setIf(q, "fp", p.TLS.Fingerprint)
		setIf(q, "alpn", strings.Join(p.TLS.ALPN, ","))
		setIf(q, "pbk", p.TLS.RealityPublicKey)
		setIf(q, "sid", p.TLS.RealityShortID)
		if p.Type == TypeVLESS {
			q.Set("encryption", "none")
		}
		u := url.URL{Scheme: scheme, User: url.User(user), Host: p.Address(), RawQuery: q.Encode(), Fragment: p.Name}
		return u.String()
	case TypeShadowsocks:
		info := base64.RawURLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password))
		return "ss://" + info + "@" + p.Address() + "#" + url.PathEscape(p.Name)
	case TypeHysteria2:
		q := url.Values{}
		setIf(q, "sni", p.TLS.SNI)
		setIf(q, "alpn", strings.Join(p.TLS.ALPN, ","))
		if p.TLS.Insecure {
			q.Set("insecure", "1")
		}
		if p.ObfsPassword != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", p.ObfsPassword)
		}
		u := url.URL{Scheme: "hysteria2", User: url.User(p.Password), Host: p.Address(), Path: "/", RawQuery: q.Encode(), Fragment: p.Name}
		return u.String()
	case TypeTUIC:
		q := url.Values{}
		setIf(q, "congestion_control", p.CongestionControl)
		setIf(q, "udp_relay_mode", p.UDPRelayMode)
		setIf(q, "sni", p.TLS.SNI)
		setIf(q, "alpn", strings.Join(p.TLS.ALPN, ","))
		if p.TLS.Insecure {
			q.Set("allow_insecure", "1")
		}
		u := url.URL{Scheme: "tuic", User: url.UserPassword(p.UUID, p.Password), Host: p.Address(), RawQuery: q.Encode(), Fragment: p.Name}
		return u.String()
	case TypeSSH:
		// The password is deliberately left out of exported SSH links.
		u := url.URL{Scheme: "ssh", User: url.User(p.User), Host: p.Address(), Fragment: p.Name}
		return u.String()
	}
	return ""
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func normalizeNetwork(n string) string {
	switch n {
	case "", "tcp", "raw", "none":
		return ""
	case "splithttp":
		return "xhttp"
	}
	return n
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

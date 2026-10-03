// Package mkmobile is the API of MKConnect's core for the native Android app,
// bound to Kotlin with gomobile. Accounts, link import and subscriptions reuse
// the desktop code; the VPN runs sing-box on the TUN that Android's
// VpnService creates (see vpn.go).
//
// gomobile only exports simple types, so structured data crosses as JSON.
package mkmobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
	"github.com/khaliilii/MKConnect/internal/version"
)

var (
	mu    sync.Mutex
	store *profile.Store
)

// Init loads the accounts from dir (the app's private files directory).
func Init(dir string) error {
	mu.Lock()
	defer mu.Unlock()
	s, err := profile.Load(filepath.Join(dir, "profiles.json"))
	if err != nil {
		return err
	}
	store = s
	return nil
}

// Version returns the app version.
func Version() string { return version.Version }

func loaded() (*profile.Store, error) {
	if store == nil {
		return nil, errors.New("mkmobile: Init was not called")
	}
	return store, nil
}

type profileView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Summary string `json:"summary"`
	Group   string `json:"group,omitempty"`
}

type groupView struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	URL      string         `json:"url,omitempty"`
	Count    int            `json:"count"`
	Usage    *profile.Usage `json:"usage,omitempty"`
	Updated  int64          `json:"updated,omitempty"` // unix seconds
	UsedText string         `json:"used_text,omitempty"`
}

// Profiles returns {"active": id, "profiles": [...], "groups": [...]} as JSON.
func Profiles() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	out := struct {
		Active   string        `json:"active"`
		Profiles []profileView `json:"profiles"`
		Groups   []groupView   `json:"groups"`
	}{Active: s.Active, Profiles: []profileView{}, Groups: []groupView{}}
	for _, p := range s.Profiles {
		out.Profiles = append(out.Profiles, profileView{ID: p.ID, Name: p.Name, Type: p.Type, Summary: summary(&p), Group: p.Group})
	}
	for _, g := range s.Groups {
		v := groupView{ID: g.ID, Name: g.Name, URL: g.URL, Count: s.GroupSize(g.ID), Usage: g.Usage}
		if !g.UpdatedAt.IsZero() {
			v.Updated = g.UpdatedAt.Unix()
		}
		if g.Usage != nil {
			if g.Usage.Total > 0 {
				v.UsedText = profile.FormatBytes(g.Usage.Used()) + " / " + profile.FormatBytes(g.Usage.Total)
			} else {
				v.UsedText = profile.FormatBytes(g.Usage.Used()) + " used"
			}
		}
		out.Groups = append(out.Groups, v)
	}
	data, err := json.Marshal(out)
	return string(data), err
}

func summary(p *profile.Profile) string {
	parts := []string{strings.ToUpper(p.Type[:1]) + p.Type[1:], p.Address()}
	if p.Transport.Network != "" {
		parts = append(parts, p.Transport.Network)
	}
	if p.TLS.Mode != "" {
		parts = append(parts, p.TLS.Mode)
	}
	return strings.Join(parts, " · ")
}

// Import adds every share link found in text (one or many, any surrounding
// text, or base64), skipping duplicates. A subscription URL becomes a group and
// is downloaded. Returns {"added", "existing", "skipped": [...]} as JSON.
func Import(text string) (string, error) {
	text = strings.TrimSpace(text)
	if !strings.ContainsAny(text, " \n") && (strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://")) {
		return addSubscription(text)
	}
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	profiles, errs := profile.ParseLinks(text)
	res := importResult{Skipped: []string{}}
	for _, p := range profiles {
		ok, err := s.AddUnique(p)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
		case ok:
			res.Added++
			if s.Active == "" {
				s.Active = s.Profiles[len(s.Profiles)-1].ID
			}
		default:
			res.Existing++
		}
	}
	for _, e := range errs {
		res.Skipped = append(res.Skipped, e.Error())
	}
	if res.Added > 0 {
		if err := s.Save(); err != nil {
			return "", err
		}
	}
	data, _ := json.Marshal(res)
	return string(data), nil
}

type importResult struct {
	Added    int      `json:"added"`
	Existing int      `json:"existing"`
	Skipped  []string `json:"skipped"`
}

func addSubscription(url string) (string, error) {
	data, err := profile.FetchSubscription(url) // network: outside the lock
	if err != nil {
		return "", err
	}
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	g := s.AddGroup("", url)
	n, errs := s.ApplySubscription(g, data, time.Now())
	res := importResult{Added: n, Skipped: []string{}}
	for _, e := range errs {
		res.Skipped = append(res.Skipped, e.Error())
	}
	if s.Active == "" && n > 0 {
		for _, p := range s.Profiles {
			if p.Group == g.ID {
				s.Active = p.ID
				break
			}
		}
	}
	if err := s.Save(); err != nil {
		return "", err
	}
	out, _ := json.Marshal(res)
	return string(out), nil
}

// UpdateSubscriptions refreshes every subscription; returns how many succeeded.
func UpdateSubscriptions() (int32, error) {
	mu.Lock()
	s, err := loaded()
	if err != nil {
		mu.Unlock()
		return 0, err
	}
	var urls, ids []string
	for _, g := range s.Groups {
		if g.IsSubscription() {
			urls, ids = append(urls, g.URL), append(ids, g.ID)
		}
	}
	mu.Unlock()

	var ok int32
	var lastErr error
	for i, url := range urls {
		data, err := profile.FetchSubscription(url)
		if err != nil {
			lastErr = err
			continue
		}
		mu.Lock()
		if g, err := s.FindGroup(ids[i]); err == nil {
			if n, _ := s.ApplySubscription(g, data, time.Now()); n > 0 {
				ok++
			}
		}
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	if err := s.Save(); err != nil {
		return ok, err
	}
	if ok == 0 && lastErr != nil {
		return 0, lastErr
	}
	return ok, nil
}

// SetActive selects the account to connect with.
func SetActive(id string) error {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return err
	}
	if _, err := s.Find(id); err != nil {
		return err
	}
	s.Active = id
	return s.Save()
}

// Delete removes an account.
func Delete(id string) error {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return err
	}
	if err := s.Remove(id); err != nil {
		return err
	}
	return s.Save()
}

// DeleteGroup removes a group or subscription with its accounts.
func DeleteGroup(id string) error {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return err
	}
	s.RemoveGroup(id)
	return s.Save()
}

// ShareLink returns the share link of an account.
func ShareLink(id string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	p, err := s.Find(id)
	if err != nil {
		return "", err
	}
	return p.Link(), nil
}

// mobileSettings is the subset of settings the phone app exposes.
type mobileSettings struct {
	Mode      string `json:"mode"` // vpn or proxy
	Port      int    `json:"port"`
	AllowLAN  bool   `json:"allow_lan"`
	ProxyUser string `json:"proxy_user"`
	ProxyPass string `json:"proxy_pass"`
	RemoteDNS string `json:"remote_dns"`
}

// Settings returns the phone settings as JSON.
func Settings() (string, error) {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	st := s.Settings
	mode := st.PhoneMode
	if mode != "proxy" {
		mode = "vpn"
	}
	data, _ := json.Marshal(mobileSettings{Mode: mode, Port: st.ListenPort, AllowLAN: st.AllowLAN,
		ProxyUser: st.ProxyUser, ProxyPass: st.ProxyPass, RemoteDNS: st.RemoteDNS})
	return string(data), nil
}

// SetSettings stores the phone settings (JSON as returned by Settings).
func SetSettings(data string) error {
	var in mobileSettings
	if err := json.Unmarshal([]byte(data), &in); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return err
	}
	st := s.Settings
	st.ListenPort, st.AllowLAN, st.ProxyUser, st.ProxyPass = in.Port, in.AllowLAN, in.ProxyUser, in.ProxyPass
	if in.RemoteDNS != "" {
		st.RemoteDNS = in.RemoteDNS
	}
	st.Core = profile.CoreSingBox // the VPN runs sing-box; it covers every protocol
	if err := st.Validate(); err != nil {
		return err
	}
	if in.Mode == "proxy" || in.Mode == "vpn" {
		st.PhoneMode = in.Mode
	}
	s.Settings = st
	return s.Save()
}

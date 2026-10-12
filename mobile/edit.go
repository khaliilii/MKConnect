package mkmobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

// Editing accounts by hand, which the desktop app has always had: the phone
// app sends and receives a whole profile as JSON (the same fields that are
// stored in profiles.json), so one form per protocol can be built in Kotlin
// without a binding per field.

// ProfileJSON returns one account as JSON, for an edit form.
func ProfileJSON(id string) (string, error) {
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
	data, err := json.Marshal(p)
	return string(data), err
}

// SaveProfile adds or replaces an account. An empty "id" adds one; an id that
// exists replaces it. Returns the account's id.
func SaveProfile(data string) (string, error) {
	var p profile.Profile
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return "", err
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Server = strings.TrimSpace(p.Server)
	if err := p.Validate(); err != nil {
		return "", err
	}
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	if p.ID == "" {
		added, err := s.Add(p)
		if err != nil {
			return "", err
		}
		if s.Active == "" {
			s.Active = added.ID
		}
		return added.ID, s.Save()
	}
	old, err := s.Find(p.ID)
	if err != nil {
		return "", err
	}
	if p.Type == profile.TypeSSH && (old.Server != p.Server || old.Port != p.Port) {
		p.HostKey = "" // a different server has a different host key
	}
	p.Test = old.Test // keep the last measurement
	*old = p
	return p.ID, s.Save()
}

// Options lists the choices the account form offers, so the phone app shows
// the same ones as the desktop app: {"types":[],"vmess_ciphers":[],...}.
func Options() string {
	data, _ := json.Marshal(map[string]any{
		"types":               profile.Types,
		"vmess_ciphers":       []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"},
		"ss_methods":          []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"},
		"networks":            []string{"tcp", "ws", "grpc", "httpupgrade", "xhttp"},
		"header_types":        []string{"", "http"},
		"tls_modes":           []string{"", "tls", "reality"},
		"fingerprints":        []string{"", "chrome", "firefox", "safari", "ios", "android", "edge", "random"},
		"flows":               []string{"", "xtls-rprx-vision"},
		"congestion_controls": []string{"bbr", "cubic", "new_reno"},
		"udp_relay_modes":     []string{"native", "quic"},
		"log_levels":          []string{"error", "warn", "info", "debug", "trace"},
		"sort_by":             []string{"", "latency", "speed"},
		"cores":               engine.Available(),
		"payload_tags":        []string{"[host]", "[port]", "[host_port]", "[raw]", "[crlf]", "[cr]", "[lf]", "[split]", "[delay_split]"},
	})
	return string(data)
}

// SetGroup moves an account into a group, or out of every group when
// groupID is empty.
func SetGroup(id, groupID string) error {
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return err
	}
	p, err := s.Find(id)
	if err != nil {
		return err
	}
	if groupID != "" {
		if _, err := s.FindGroup(groupID); err != nil {
			return err
		}
	}
	p.Group = groupID
	return s.Save()
}

// AddGroup creates an empty local group and returns its id.
func AddGroup(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("the group needs a name")
	}
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return "", err
	}
	g := s.AddGroup(name, "")
	return g.ID, s.Save()
}

// RenameGroup renames a group or subscription.
func RenameGroup(id, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("the group needs a name")
	}
	mu.Lock()
	defer mu.Unlock()
	s, err := loaded()
	if err != nil {
		return err
	}
	g, err := s.FindGroup(id)
	if err != nil {
		return err
	}
	g.Name = name
	return s.Save()
}

// ImportInto is Import, with every added account placed in the named group
// (created when it doesn't exist yet). An empty group behaves like Import.
func ImportInto(text, group string) (string, error) {
	group = strings.TrimSpace(group)
	if group == "" {
		return Import(text)
	}
	before := map[string]bool{}
	mu.Lock()
	s, err := loaded()
	if err != nil {
		mu.Unlock()
		return "", err
	}
	for _, p := range s.Profiles {
		before[p.ID] = true
	}
	mu.Unlock()

	out, err := Import(text)
	if err != nil {
		return "", err
	}

	mu.Lock()
	defer mu.Unlock()
	var g *profile.Group
	for i := range s.Groups {
		if strings.EqualFold(s.Groups[i].Name, group) && !s.Groups[i].IsSubscription() {
			g = &s.Groups[i]
			break
		}
	}
	if g == nil {
		g = s.AddGroup(group, "")
	}
	for i := range s.Profiles {
		if !before[s.Profiles[i].ID] {
			s.Profiles[i].Group = g.ID
		}
	}
	if err := s.Save(); err != nil {
		return "", fmt.Errorf("save: %w", err)
	}
	return out, nil
}

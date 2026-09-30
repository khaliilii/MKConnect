package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Core names.
const (
	CoreSingBox  = "singbox"
	CoreXray     = "xray"
	CoreExternal = "external"
)

// Mode names.
const (
	ModeProxy = "proxy" // local SOCKS5/HTTP proxy
	ModeTUN   = "tun"   // virtual network interface capturing all traffic
)

// Settings controls how the active profile is run.
type Settings struct {
	Core string `json:"core"` // singbox, xray, external
	Mode string `json:"mode"` // proxy, tun

	// ExternalPath is the sing-box or xray binary used by the external core.
	ExternalPath string `json:"external_path,omitempty"`
	// ExternalKind is the config format the external binary expects: singbox or xray.
	ExternalKind string `json:"external_kind,omitempty"`

	ListenPort int `json:"listen_port"`
	// AllowLAN makes the proxy listen on all interfaces so other devices can use it.
	AllowLAN  bool   `json:"allow_lan"`
	ProxyUser string `json:"proxy_user,omitempty"`
	ProxyPass string `json:"proxy_pass,omitempty"`

	// RemoteDNS is the resolver used through the tunnel in TUN mode.
	RemoteDNS string `json:"remote_dns,omitempty"`
	LogLevel  string `json:"log_level,omitempty"`
}

// DefaultSettings returns the settings used for a fresh install.
func DefaultSettings() Settings {
	return Settings{
		Core:         CoreSingBox,
		Mode:         ModeProxy,
		ExternalKind: CoreSingBox,
		ListenPort:   1080,
		RemoteDNS:    "1.1.1.1",
		LogLevel:     "info",
	}
}

// ListenAddress returns the IP the local proxy binds to.
func (s *Settings) ListenAddress() string {
	if s.AllowLAN {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// Validate checks settings for inconsistent values.
func (s *Settings) Validate() error {
	switch s.Core {
	case CoreSingBox, CoreXray:
	case CoreExternal:
		if s.ExternalPath == "" {
			return fmt.Errorf("external core needs external_path")
		}
		if s.ExternalKind != CoreSingBox && s.ExternalKind != CoreXray {
			return fmt.Errorf("external_kind must be %s or %s", CoreSingBox, CoreXray)
		}
	default:
		return fmt.Errorf("unknown core %q", s.Core)
	}
	if s.Mode != ModeProxy && s.Mode != ModeTUN {
		return fmt.Errorf("unknown mode %q", s.Mode)
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port %d", s.ListenPort)
	}
	return nil
}

// Store is the on-disk state: settings plus all profiles.
type Store struct {
	Settings Settings  `json:"settings"`
	Active   string    `json:"active,omitempty"`
	Profiles []Profile `json:"profiles"`

	path string
}

// DefaultPath returns $MKCONNECT_CONFIG, or <user config dir>/mkconnect/profiles.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("MKCONNECT_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mkconnect", "profiles.json"), nil
}

// Load reads the store at path, returning an empty store if it doesn't exist yet.
func Load(path string) (*Store, error) {
	s := &Store{Settings: DefaultSettings(), path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

// Save writes the store atomically with owner-only permissions, since it holds credentials.
func (s *Store) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Path returns the file the store is saved to.
func (s *Store) Path() string { return s.path }

// Find returns the profile whose id or name matches ref.
func (s *Store) Find(ref string) (*Profile, error) {
	for i := range s.Profiles {
		if s.Profiles[i].ID == ref {
			return &s.Profiles[i], nil
		}
	}
	var match *Profile
	for i := range s.Profiles {
		if strings.EqualFold(s.Profiles[i].Name, ref) {
			if match != nil {
				return nil, fmt.Errorf("name %q is ambiguous, use the id", ref)
			}
			match = &s.Profiles[i]
		}
	}
	if match == nil {
		return nil, fmt.Errorf("profile %q not found", ref)
	}
	return match, nil
}

// ActiveProfile returns the selected profile, or the only one if just one exists.
func (s *Store) ActiveProfile() (*Profile, error) {
	if s.Active != "" {
		return s.Find(s.Active)
	}
	if len(s.Profiles) == 1 {
		return &s.Profiles[0], nil
	}
	if len(s.Profiles) == 0 {
		return nil, fmt.Errorf("no profiles yet, add one with `mkconnect profile add` or `mkconnect profile import`")
	}
	return nil, fmt.Errorf("no active profile, choose one with `mkconnect profile use <id|name>`")
}

// Add validates p, assigns an id and appends it.
func (s *Store) Add(p Profile) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	p.ID = NewID()
	s.Profiles = append(s.Profiles, p)
	if len(s.Profiles) == 1 {
		s.Active = p.ID
	}
	return &s.Profiles[len(s.Profiles)-1], nil
}

// Remove deletes the profile matching ref.
func (s *Store) Remove(ref string) error {
	p, err := s.Find(ref)
	if err != nil {
		return err
	}
	id := p.ID
	for i := range s.Profiles {
		if s.Profiles[i].ID == id {
			s.Profiles = append(s.Profiles[:i], s.Profiles[i+1:]...)
			break
		}
	}
	if s.Active == id {
		s.Active = ""
	}
	return nil
}

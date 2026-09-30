package profile

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultUpdateInterval is used when a subscription doesn't announce one.
const DefaultUpdateInterval = 12 * time.Hour

// Group is a named set of profiles. A group with a URL is a subscription and
// can be refreshed from it.
type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	// UpdateHours is the refresh interval announced by the provider (profile-update-interval).
	UpdateHours int    `json:"update_hours,omitempty"`
	Usage       *Usage `json:"usage,omitempty"`
}

// IsSubscription reports whether the group is backed by a URL.
func (g *Group) IsSubscription() bool { return g.URL != "" }

// NeedsUpdate reports whether the subscription is older than its interval.
func (g *Group) NeedsUpdate(now time.Time) bool {
	if !g.IsSubscription() {
		return false
	}
	interval := DefaultUpdateInterval
	if g.UpdateHours > 0 {
		interval = time.Duration(g.UpdateHours) * time.Hour
	}
	return now.Sub(g.UpdatedAt) >= interval
}

// Usage is the data quota reported by a subscription's subscription-userinfo header.
type Usage struct {
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Total    int64     `json:"total"` // 0 = unlimited
	Expire   time.Time `json:"expire,omitzero"`
}

// Used returns upload + download.
func (u *Usage) Used() int64 { return u.Upload + u.Download }

// ParseUserInfo parses "upload=1; download=2; total=3; expire=1700000000".
func ParseUserInfo(header string) *Usage {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	u := &Usage{}
	found := false
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64) // some panels send floats
		if err != nil {
			continue
		}
		found = true
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			u.Upload = int64(n)
		case "download":
			u.Download = int64(n)
		case "total":
			u.Total = int64(n)
		case "expire":
			if n > 0 {
				u.Expire = time.Unix(int64(n), 0)
			}
		}
	}
	if !found {
		return nil
	}
	return u
}

// SubscriptionData is what a subscription URL returned.
type SubscriptionData struct {
	Body        string
	Title       string
	Usage       *Usage
	UpdateHours int
}

// userAgent makes panels (Marzban, 3x-ui, Hiddify Manager, ...) return plain
// share links rather than a Clash or sing-box config.
const userAgent = "v2rayN/7.0 MKConnect"

// FetchSubscription downloads a subscription and its metadata headers.
func FetchSubscription(rawURL string) (*SubscriptionData, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	data := &SubscriptionData{
		Body:  string(body),
		Title: decodeTitle(resp.Header.Get("Profile-Title")),
		Usage: ParseUserInfo(resp.Header.Get("Subscription-Userinfo")),
	}
	data.UpdateHours, _ = strconv.Atoi(strings.TrimSpace(resp.Header.Get("Profile-Update-Interval")))
	return data, nil
}

// decodeTitle handles the "base64:<...>" form of the profile-title header.
func decodeTitle(t string) string {
	if rest, ok := strings.CutPrefix(t, "base64:"); ok {
		if b, err := decodeBase64(rest); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return strings.TrimSpace(t)
}

// SubscriptionName suggests a group name for a subscription URL.
func SubscriptionName(rawURL, title string) string {
	if title != "" {
		return title
	}
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return "Subscription"
}

// Fingerprint identifies a server account regardless of its display name, so
// re-imported or refreshed links can be matched to existing profiles.
func (p *Profile) Fingerprint() string {
	c := *p
	c.ID, c.Name, c.Group, c.HostKey = "", "", "", ""
	return c.Link() + "|" + c.Password + "|" + c.PrivateKeyPath
}

// FindGroup returns the group with the given id or (case-insensitive) name.
func (s *Store) FindGroup(ref string) (*Group, error) {
	for i := range s.Groups {
		if s.Groups[i].ID == ref {
			return &s.Groups[i], nil
		}
	}
	for i := range s.Groups {
		if strings.EqualFold(s.Groups[i].Name, ref) {
			return &s.Groups[i], nil
		}
	}
	return nil, fmt.Errorf("group %q not found", ref)
}

// AddGroup creates a group; url may be empty for a local group.
func (s *Store) AddGroup(name, url string) *Group {
	s.Groups = append(s.Groups, Group{ID: NewID(), Name: name, URL: url})
	return &s.Groups[len(s.Groups)-1]
}

// RemoveGroup deletes a group and all of its profiles.
func (s *Store) RemoveGroup(id string) {
	kept := s.Profiles[:0]
	for _, p := range s.Profiles {
		if p.Group == id {
			if s.Active == p.ID {
				s.Active = ""
			}
			continue
		}
		kept = append(kept, p)
	}
	s.Profiles = kept
	for i := range s.Groups {
		if s.Groups[i].ID == id {
			s.Groups = append(s.Groups[:i], s.Groups[i+1:]...)
			break
		}
	}
}

// GroupSize returns how many profiles belong to the group ("" = ungrouped).
func (s *Store) GroupSize(id string) int {
	n := 0
	for i := range s.Profiles {
		if s.Profiles[i].Group == id {
			n++
		}
	}
	return n
}

// AddUnique adds p unless an identical account already exists. It reports whether p was added.
func (s *Store) AddUnique(p Profile) (bool, error) {
	fp := p.Fingerprint()
	for i := range s.Profiles {
		if s.Profiles[i].Fingerprint() == fp {
			return false, nil
		}
	}
	_, err := s.Add(p)
	return err == nil, err
}

// ApplySubscription replaces the group's profiles with the fetched ones.
// Accounts that are still present keep their id (so the active selection and
// pinned SSH host keys survive a refresh).
func (s *Store) ApplySubscription(g *Group, data *SubscriptionData, now time.Time) (int, []error) {
	profiles, errs := ParseLinks(data.Body)
	if len(profiles) == 0 {
		if len(errs) == 0 {
			errs = append(errs, fmt.Errorf("subscription is empty"))
		}
		return 0, errs
	}

	existing := map[string]Profile{}
	var kept []Profile
	for _, p := range s.Profiles {
		if p.Group == g.ID {
			existing[p.Fingerprint()] = p
		} else {
			kept = append(kept, p)
		}
	}
	activeStillThere := false
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			continue
		}
		p.Group = g.ID
		if old, ok := existing[p.Fingerprint()]; ok {
			p.ID, p.HostKey = old.ID, old.HostKey
		} else {
			p.ID = NewID()
		}
		if p.ID == s.Active {
			activeStillThere = true
		}
		kept = append(kept, p)
	}
	for _, old := range existing {
		if old.ID == s.Active && !activeStillThere {
			s.Active = ""
		}
	}
	s.Profiles = kept

	g.UpdatedAt = now
	if data.Usage != nil {
		g.Usage = data.Usage
	}
	if data.UpdateHours > 0 {
		g.UpdateHours = data.UpdateHours
	}
	if g.Name == "" {
		g.Name = SubscriptionName(g.URL, data.Title)
	}
	return s.GroupSize(g.ID), errs
}

// FormatBytes renders a byte count like "1.5 GB".
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

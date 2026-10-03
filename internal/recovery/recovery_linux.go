package recovery

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/sagernet/netlink"
	"github.com/sagernet/nftables"
	"golang.org/x/sys/unix"
)

func stateDir() string {
	if fi, err := os.Stat("/run"); err == nil && fi.IsDir() {
		return "/run/mkconnect" // tmpfs: cleared on reboot, like the state it describes
	}
	return "/var/run/mkconnect"
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func currentRules() ([]Rule, error) {
	var out []Rule
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			out = append(out, key(family, r))
		}
	}
	return out, nil
}

func key(family int, r netlink.Rule) Rule {
	return Rule{Family: family, Priority: r.Priority, Table: r.Table, Mark: r.Mark, Invert: r.Invert, Goto: r.Goto}
}

// singBoxRule reports rules of the kind sing-tun installs: its auto_route rules
// (priority 9000+, table 2022), the auto_redirect fallback (32768 → 2022) and
// the redirect route rule (priority 1, random table).
func singBoxRule(r netlink.Rule) bool {
	switch {
	case r.Table == 2022:
		return true
	case r.Priority >= 9000 && r.Priority < 9100:
		return true
	case r.Priority == 1 && r.Table > 255:
		return true
	}
	return false
}

func undo(j *Journal) ([]string, error) {
	var cleaned, errs []string
	note := func(err error, done string) {
		if err != nil {
			errs = append(errs, err.Error())
		} else if done != "" {
			cleaned = append(cleaned, done)
		}
	}

	// Rules that weren't there before and look like sing-box's.
	before := map[Rule]bool{}
	for _, r := range j.Rules {
		before[r] = true
	}
	tables := map[int]bool{}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			note(err, "")
			continue
		}
		for _, r := range rules {
			if before[key(family, r)] || !singBoxRule(r) {
				continue
			}
			r := r
			// RuleList doesn't report the rule's action; deleting needs it to match.
			switch {
			case r.Goto > 0:
				r.Type, r.Table = unix.FR_ACT_GOTO, -1
			case r.Table == 0:
				r.Type, r.Table = unix.FR_ACT_NOP, -1
			}
			what := fmt.Sprintf("routing rule %d (table %d)", r.Priority, r.Table)
			if r.Table < 0 {
				what = fmt.Sprintf("routing rule %d", r.Priority)
			}
			note(netlink.RuleDel(&r), what)
			if r.Table > 255 {
				tables[r.Table] = true
			}
		}
	}
	// Routes left in sing-box's tables.
	for table := range tables {
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				continue
			}
			for _, rt := range routes {
				rt := rt
				netlink.RouteDel(&rt)
			}
		}
		cleaned = append(cleaned, fmt.Sprintf("routing table %d", table))
	}

	// sing-box's nftables table (auto_redirect).
	if conn, err := nftables.New(); err == nil {
		if tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet); err == nil {
			for _, t := range tables {
				if t.Name == "sing-box" {
					conn.DelTable(t)
					note(conn.Flush(), "nftables table inet sing-box")
				}
			}
		}
	}

	if j.IPForward != "" {
		note(os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(j.IPForward), 0o644),
			"net.ipv4.ip_forward="+strings.TrimSpace(j.IPForward))
	}
	if len(errs) > 0 {
		return cleaned, fmt.Errorf("recovery: %s", strings.Join(errs, "; "))
	}
	return cleaned, nil
}

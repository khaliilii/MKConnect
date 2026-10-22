package engine

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/khaliilii/MKConnect/internal/recovery"
)

// tunDNSAddr is where the system's DNS queries are sent while the TUN is up:
// an address inside the TUN's /30, so they can only travel through it, where
// sing-box answers them through the tunnel (hijack-dns).
const tunDNSAddr = "172.19.77.2"

// pointSystemDNSIntoTunnel makes macOS resolve names through the tunnel.
//
// Routing alone doesn't do it: macOS ties each resolver to the interface its
// servers were reached on when the DNS configuration was made (the Wi-Fi, for
// servers from DHCP), and mDNSResponder — which Chrome and Safari use — keeps
// sending its queries out that interface after the TUN's routes take over. On
// a filtered network those queries get the filter's forged answers (Iran:
// every blocked name -> 10.10.34.36), so blocked sites don't load although the
// tunnel works. Setting every network service's DNS to an address inside the
// TUN (what wg-quick does) makes macOS tie the resolver to the TUN. The old
// servers are journaled first, so a crash can't leave the Mac without DNS.
func pointSystemDNSIntoTunnel() (restore func(), err error) {
	services, err := networkServices()
	if err != nil {
		return func() {}, err
	}
	original := map[string]string{}
	for _, svc := range services {
		servers, err := dnsServersOf(svc)
		if err != nil {
			continue
		}
		if servers == tunDNSAddr {
			servers = "Empty" // left from a crash that wasn't cleaned up
		}
		original[svc] = servers
	}
	recovery.Record(func(j *recovery.Journal) { j.MacDNS = original })

	var changed []string
	for svc := range original {
		if out, err := exec.Command("networksetup", "-setdnsservers", svc, tunDNSAddr).CombinedOutput(); err != nil {
			log.Printf("⚠️  could not point the DNS of %s into the tunnel: %v: %s", svc, err, strings.TrimSpace(string(out)))
			continue
		}
		changed = append(changed, svc)
	}
	if len(changed) > 0 {
		log.Printf("🧭 system DNS goes through the tunnel (%s → %s)", strings.Join(changed, ", "), tunDNSAddr)
	}
	return func() {
		for _, svc := range changed {
			args := append([]string{"-setdnsservers", svc}, strings.Fields(original[svc])...)
			if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
				log.Printf("⚠️  could not restore the DNS of %s: %v: %s", svc, err, strings.TrimSpace(string(out)))
			}
		}
		recovery.Record(func(j *recovery.Journal) { j.MacDNS = nil })
	}, nil
}

// networkServices lists the network services ("Wi-Fi", "Ethernet", ...),
// leaving out disabled ones (marked with an asterisk).
func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	var services []string
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue // the first line is an explanation
		}
		services = append(services, line)
	}
	return services, nil
}

// dnsServersOf returns a service's DNS servers as networksetup takes them
// back: the addresses, or "Empty" when none are set (DHCP's are used).
func dnsServersOf(service string) (string, error) {
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, "aren't any DNS Servers") {
		return "Empty", nil
	}
	return strings.Join(strings.Fields(text), " "), nil
}

// LeftoverTunnelDNS lists the network services whose DNS still points into
// a tunnel that isn't there: what a connection killed before it could clean
// up (a crash, a forced quit, a power cut) leaves behind. Such a Mac resolves
// no names at all. Readable without administrator rights.
func LeftoverTunnelDNS() []string {
	services, err := networkServices()
	if err != nil {
		return nil
	}
	var left []string
	for _, svc := range services {
		if servers, err := dnsServersOf(svc); err == nil && servers == tunDNSAddr {
			left = append(left, svc)
		}
	}
	return left
}

// RepairTunnelDNS puts the DNS of the services LeftoverTunnelDNS reports back:
// to what the crash journal recorded, or, when the journal is gone (it lives
// in /var/run, which a restart empties), to the network's own servers (DHCP).
// Needs administrator rights.
func RepairTunnelDNS() ([]string, error) {
	cleaned, err := recovery.Recover()
	if errors.Is(err, recovery.ErrRunning) {
		return nil, fmt.Errorf("a MKConnect connection is running; disconnect it to restore the DNS")
	}
	if err != nil {
		log.Printf("⚠️  crash journal: %v", err)
	}
	for _, svc := range LeftoverTunnelDNS() {
		if out, err := exec.Command("networksetup", "-setdnsservers", svc, "Empty").CombinedOutput(); err != nil {
			return cleaned, fmt.Errorf("restore DNS of %s: %v: %s", svc, err, strings.TrimSpace(string(out)))
		}
		cleaned = append(cleaned, "DNS of "+svc+" = the network's own (DHCP)")
	}
	return cleaned, nil
}

package killswitch

import (
	"fmt"
	"strings"
)

// The local network stays reachable (macOS and Linux): the router, printers,
// and devices that use the shared proxy.
var (
	lan4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"}
	lan6 = []string{"fe80::/10", "ff00::/8"}
)

// anchor is where the macOS rules go: the system's /etc/pf.conf evaluates
// every anchor under com.apple.
const anchor = "com.apple/mkconnect"

// pfRules are the macOS rules. They keep no state but for the cores' own
// connections: pf would create state only from a connection's first packet
// going out, and so block the answers of connections that came in, such as
// those sing-box's TUN stack accepts on the tunnel's interface, or the shared
// proxy's on the local network. "block return" rather than "drop": an app's
// connection fails at once instead of hanging until it times out.
func pfRules(tun string) string {
	var b strings.Builder
	b.WriteString("# MKConnect kill switch: nothing gets out without the tunnel\n")
	b.WriteString("pass out quick on lo0 all no state\n")
	if tun != "" {
		fmt.Fprintf(&b, "pass out quick on %s all no state\n", tun)
	}
	fmt.Fprintf(&b, "pass out quick proto { tcp, udp } all group %d\n", Group)
	b.WriteString("pass out quick proto { tcp, udp } to any port 53 no state\n")
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67 no state\n")
	fmt.Fprintf(&b, "pass out quick inet to { %s } no state\n", strings.Join(lan4, ", "))
	fmt.Fprintf(&b, "pass out quick inet6 to { %s } no state\n", strings.Join(lan6, ", "))
	b.WriteString("block return out quick all\n")
	return b.String()
}

// nftTable is the Linux table of the kill switch.
const nftTable = "mkconnect_killswitch"

// nftRules are the Linux rules, as one nft script that replaces the table
// (if any) atomically: add makes sure delete has a table to delete.
func nftRules(tun string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", nftTable)
	fmt.Fprintf(&b, "delete table inet %s\n", nftTable)
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority filter; policy accept;\n")
	b.WriteString("\t\toifname \"lo\" accept\n")
	if tun != "" {
		fmt.Fprintf(&b, "\t\toifname %q accept\n", tun)
	}
	fmt.Fprintf(&b, "\t\tmeta skgid %d accept\n", Group)
	b.WriteString("\t\tmeta l4proto { tcp, udp } th dport 53 accept\n")
	b.WriteString("\t\tudp sport 68 udp dport 67 accept\n")
	fmt.Fprintf(&b, "\t\tip daddr { %s } accept\n", strings.Join(lan4, ", "))
	fmt.Fprintf(&b, "\t\tip6 daddr { %s } accept\n", strings.Join(lan6, ", "))
	b.WriteString("\t\tmeta l4proto tcp reject with tcp reset\n")
	b.WriteString("\t\treject with icmpx admin-prohibited\n")
	b.WriteString("\t}\n}\n")
	return b.String()
}

package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/khaliilii/MKConnect/internal/profile"
)

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "profile",
		Aliases: []string{"profiles", "p"},
		Short:   "Add, edit, remove, import and select accounts",
	}
	cmd.AddCommand(
		newProfileListCmd(), newProfileShowCmd(), newProfileAddCmd(), newProfileEditCmd(),
		newProfileRemoveCmd(), newProfileUseCmd(), newProfileImportCmd(),
	)
	return cmd
}

func newProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			if len(store.Profiles) == 0 {
				fmt.Println("No profiles yet. Add one with `mkconnect profile add` or `mkconnect profile import`.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "\tID\tNAME\tGROUP\tTYPE\tSERVER\tTRANSPORT")
			for _, p := range store.Profiles {
				mark := ""
				if p.ID == store.Active {
					mark = "*"
				}
				transport := orDash(p.Transport.Network)
				if p.TLS.Mode != "" {
					transport += "+" + p.TLS.Mode
				}
				group := "-"
				if g, err := store.FindGroup(p.Group); p.Group != "" && err == nil {
					group = g.Name
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", mark, p.ID, p.Name, group, p.Type, p.Address(), transport)
			}
			return w.Flush()
		},
	}
}

func newProfileShowCmd() *cobra.Command {
	var link bool
	cmd := &cobra.Command{
		Use:   "show <id|name>",
		Short: "Show a profile (secrets hidden) or its share link",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			p, err := store.Find(args[0])
			if err != nil {
				return err
			}
			if link {
				fmt.Println(p.Link())
				return nil
			}
			fmt.Printf("id:        %s\nname:      %s\ntype:      %s\nserver:    %s\n", p.ID, p.Name, p.Type, p.Address())
			printIf("user", p.User)
			printIf("password", mask(p.Password))
			printIf("key", p.PrivateKeyPath)
			printIf("host key", p.HostKey)
			printIf("uuid", mask(p.UUID))
			printIf("security", p.Security)
			printIf("flow", p.Flow)
			printIf("method", p.Method)
			printIf("network", p.Transport.Network)
			printIf("path", p.Transport.Path)
			printIf("host", p.Transport.Host)
			printIf("service", p.Transport.ServiceName)
			printIf("tls", p.TLS.Mode)
			printIf("sni", p.TLS.SNI)
			printIf("alpn", strings.Join(p.TLS.ALPN, ","))
			printIf("fp", p.TLS.Fingerprint)
			printIf("pbk", p.TLS.RealityPublicKey)
			printIf("sid", p.TLS.RealityShortID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&link, "link", false, "print the share link instead")
	return cmd
}

// profileFlags binds the editable profile fields to command flags.
type profileFlags struct {
	p           profile.Profile
	alpn        string
	askPassword bool
}

func (pf *profileFlags) register(f *pflag.FlagSet) {
	p := &pf.p
	f.StringVar(&p.Name, "name", "", "display name")
	f.StringVar(&p.Server, "server", "", "server host or IP")
	f.IntVar(&p.Port, "port", 0, "server port")
	f.StringVar(&p.User, "user", "", "SSH username")
	f.StringVar(&p.Password, "password", "", "SSH / Trojan / Shadowsocks password (prefer --ask-password)")
	f.BoolVar(&pf.askPassword, "ask-password", false, "prompt for the password without echoing it")
	f.StringVar(&p.PrivateKeyPath, "key", "", "SSH private key file")
	f.StringVar(&p.HostKey, "host-key", "", "pin the SSH host key (authorized_keys format); empty = trust on first use")
	f.StringVar(&p.UUID, "uuid", "", "VMess / VLESS user id")
	f.IntVar(&p.AlterID, "alter-id", 0, "VMess alterId")
	f.StringVar(&p.Security, "security", "", "VMess cipher (auto, aes-128-gcm, chacha20-poly1305, none)")
	f.StringVar(&p.Flow, "flow", "", "VLESS flow, e.g. xtls-rprx-vision")
	f.StringVar(&p.Method, "method", "", "Shadowsocks method")
	f.StringVar(&p.Transport.Network, "network", "", "transport: tcp, ws, grpc, httpupgrade, xhttp")
	f.StringVar(&p.Transport.Path, "path", "", "ws / httpupgrade / xhttp path")
	f.StringVar(&p.Transport.Host, "host", "", "ws / httpupgrade / xhttp Host header")
	f.StringVar(&p.Transport.ServiceName, "service-name", "", "gRPC service name")
	f.StringVar(&p.TLS.Mode, "tls", "", "security: none, tls, reality")
	f.StringVar(&p.TLS.SNI, "sni", "", "TLS server name")
	f.StringVar(&pf.alpn, "alpn", "", "comma-separated ALPN list")
	f.StringVar(&p.TLS.Fingerprint, "fp", "", "uTLS fingerprint, e.g. chrome")
	f.BoolVar(&p.TLS.Insecure, "insecure", false, "skip TLS certificate verification (sing-box only)")
	f.StringVar(&p.TLS.RealityPublicKey, "pbk", "", "REALITY public key")
	f.StringVar(&p.TLS.RealityShortID, "sid", "", "REALITY short id")
}

// apply copies every flag the user set onto dst.
func (pf *profileFlags) apply(f *pflag.FlagSet, dst *profile.Profile) error {
	src := &pf.p
	set := func(name string, fn func()) {
		if f.Changed(name) {
			fn()
		}
	}
	set("name", func() { dst.Name = src.Name })
	set("server", func() { dst.Server = src.Server })
	set("port", func() { dst.Port = src.Port })
	set("user", func() { dst.User = src.User })
	set("password", func() { dst.Password = src.Password })
	set("key", func() { dst.PrivateKeyPath = src.PrivateKeyPath })
	set("host-key", func() { dst.HostKey = src.HostKey })
	set("uuid", func() { dst.UUID = src.UUID })
	set("alter-id", func() { dst.AlterID = src.AlterID })
	set("security", func() { dst.Security = src.Security })
	set("flow", func() { dst.Flow = src.Flow })
	set("method", func() { dst.Method = src.Method })
	set("network", func() { dst.Transport.Network = src.Transport.Network })
	set("path", func() { dst.Transport.Path = src.Transport.Path })
	set("host", func() { dst.Transport.Host = src.Transport.Host })
	set("service-name", func() { dst.Transport.ServiceName = src.Transport.ServiceName })
	set("tls", func() {
		dst.TLS.Mode = src.TLS.Mode
		if dst.TLS.Mode == "none" {
			dst.TLS.Mode = ""
		}
	})
	set("sni", func() { dst.TLS.SNI = src.TLS.SNI })
	set("alpn", func() { dst.TLS.ALPN = splitComma(pf.alpn) })
	set("fp", func() { dst.TLS.Fingerprint = src.TLS.Fingerprint })
	set("insecure", func() { dst.TLS.Insecure = src.TLS.Insecure })
	set("pbk", func() { dst.TLS.RealityPublicKey = src.TLS.RealityPublicKey })
	set("sid", func() { dst.TLS.RealityShortID = src.TLS.RealityShortID })

	if pf.askPassword {
		pass, err := readSecret("Password: ")
		if err != nil {
			return err
		}
		dst.Password = pass
	}
	return nil
}

func newProfileAddCmd() *cobra.Command {
	var pf profileFlags
	cmd := &cobra.Command{
		Use:   "add <" + strings.Join(profile.Types, "|") + ">",
		Short: "Add a profile",
		Example: `  mkconnect profile add ssh --name home --server 1.2.3.4 --port 22 --user root --ask-password
  mkconnect profile add vless --name de --server de.example.com --port 443 --uuid <uuid> --tls reality --sni www.microsoft.com --pbk <key> --sid 6ba8
  mkconnect profile add vmess --name ws --server cdn.example.com --port 443 --uuid <uuid> --network ws --path /ray --tls tls`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			p := profile.Profile{Type: strings.ToLower(args[0])}
			if p.Type == "ss" {
				p.Type = profile.TypeShadowsocks
			}
			if p.Type == profile.TypeSSH {
				p.Port = 22
			}
			if err := pf.apply(cmd.Flags(), &p); err != nil {
				return err
			}
			if p.Type == profile.TypeSSH && p.Password == "" && p.PrivateKeyPath == "" {
				if p.Password, err = readSecret("SSH password: "); err != nil {
					return err
				}
			}
			if p.Name == "" {
				p.Name = p.Type + "-" + p.Server
			}
			added, err := store.Add(p)
			if err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Printf("✅ Added %s (%s)\n", added.Name, added.ID)
			return nil
		},
	}
	pf.register(cmd.Flags())
	return cmd
}

func newProfileEditCmd() *cobra.Command {
	var pf profileFlags
	cmd := &cobra.Command{
		Use:   "edit <id|name>",
		Short: "Change fields of a profile (only the flags you pass are changed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			p, err := store.Find(args[0])
			if err != nil {
				return err
			}
			edited := *p
			if err := pf.apply(cmd.Flags(), &edited); err != nil {
				return err
			}
			if edited.Server != p.Server || edited.Port != p.Port {
				edited.HostKey = "" // a different server has a different host key
				if cmd.Flags().Changed("host-key") {
					edited.HostKey = pf.p.HostKey
				}
			}
			if err := edited.Validate(); err != nil {
				return err
			}
			*p = edited
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Printf("✅ Updated %s (%s)\n", p.Name, p.ID)
			return nil
		},
	}
	pf.register(cmd.Flags())
	return cmd
}

func newProfileRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <id|name>",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a profile",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			if err := store.Remove(args[0]); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Println("✅ Removed")
			return nil
		},
	}
}

func newProfileUseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use <id|name>",
		Short: "Select the profile `mkconnect` connects with",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			p, err := store.Find(args[0])
			if err != nil {
				return err
			}
			store.Active = p.ID
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Printf("✅ Active profile: %s (%s)\n", p.Name, p.ID)
			return nil
		},
	}
}

func newProfileImportCmd() *cobra.Command {
	var file, subURL, legacy, group string
	cmd := &cobra.Command{
		Use:   "import [link...]",
		Short: "Import share links, a subscription, or a v1 config.json",
		Example: `  mkconnect profile import 'vmess://...' 'vless://...'
  mkconnect profile import --file links.txt
  mkconnect profile import --url https://example.com/sub
  mkconnect profile import --legacy config.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			var text strings.Builder
			for _, a := range args {
				text.WriteString(a + "\n")
			}
			if file != "" {
				data, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				text.Write(data)
				text.WriteString("\n")
			}
			if subURL != "" {
				g := store.AddGroup(group, subURL)
				if err := updateGroup(store, g); err != nil {
					return err
				}
				if text.Len() == 0 && legacy == "" {
					return store.Save()
				}
			}
			groupID := ""
			if group != "" && subURL == "" {
				g, err := store.FindGroup(group)
				if err != nil {
					g = store.AddGroup(group, "")
				}
				groupID = g.ID
			}

			var added int
			if legacy != "" {
				p, socksPort, err := profile.ImportLegacy(legacy)
				if err != nil {
					return err
				}
				if _, err := store.Add(p); err != nil {
					return err
				}
				if socksPort > 0 {
					store.Settings.ListenPort = socksPort
				}
				added++
			}

			profiles, errs := profile.ParseLinks(text.String())
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "⚠️  skipped: %v\n", e)
			}
			for _, p := range profiles {
				p.Group = groupID
				if _, err := store.Add(p); err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  skipped %s: %v\n", p.Name, err)
					continue
				}
				added++
			}
			if added == 0 && subURL == "" {
				return fmt.Errorf("nothing imported")
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Printf("✅ Imported %d profile(s)\n", added)
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "file with one link per line (or base64 subscription)")
	cmd.Flags().StringVar(&subURL, "url", "", "subscription URL (creates a group that can be refreshed with `sub update`)")
	cmd.Flags().StringVar(&group, "group", "", "put the imported accounts in this group (created if missing)")
	cmd.Flags().StringVar(&legacy, "legacy", "", "MKConnect v1 config.json to migrate")
	return cmd
}

func printIf(label, v string) {
	if v != "" {
		fmt.Printf("%-10s %s\n", label+":", v)
	}
}

func mask(s string) string {
	if len(s) <= 4 {
		if s == "" {
			return ""
		}
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func orDash(s string) string {
	if s == "" {
		return "tcp"
	}
	return s
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

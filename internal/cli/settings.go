package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// settingKeys maps `settings set` keys to setters.
var settingKeys = map[string]func(s *profile.Settings, v string) error{
	"core":          func(s *profile.Settings, v string) error { s.Core = v; return nil },
	"mode":          func(s *profile.Settings, v string) error { s.Mode = v; return nil },
	"external-path": func(s *profile.Settings, v string) error { s.ExternalPath = v; return nil },
	"external-kind": func(s *profile.Settings, v string) error { s.ExternalKind = v; return nil },
	"port": func(s *profile.Settings, v string) error {
		n, err := strconv.Atoi(v)
		s.ListenPort = n
		return err
	},
	"lan": func(s *profile.Settings, v string) error {
		b, err := strconv.ParseBool(v)
		s.AllowLAN = b
		return err
	},
	"proxy-user": func(s *profile.Settings, v string) error { s.ProxyUser = v; return nil },
	"proxy-pass": func(s *profile.Settings, v string) error { s.ProxyPass = v; return nil },
	"remote-dns": func(s *profile.Settings, v string) error { s.RemoteDNS = v; return nil },
	"log-level":  func(s *profile.Settings, v string) error { s.LogLevel = v; return nil },
}

func newSettingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Show or change core, mode and proxy sharing settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			s := store.Settings
			fmt.Printf("config file:   %s\n", store.Path())
			fmt.Printf("core:          %s\n", s.Core)
			fmt.Printf("mode:          %s\n", s.Mode)
			if s.Core == profile.CoreExternal {
				fmt.Printf("external-path: %s\nexternal-kind: %s\n", s.ExternalPath, s.ExternalKind)
			}
			fmt.Printf("port:          %d\n", s.ListenPort)
			fmt.Printf("lan:           %t\n", s.AllowLAN)
			fmt.Printf("proxy-user:    %s\n", s.ProxyUser)
			fmt.Printf("proxy-pass:    %s\n", mask(s.ProxyPass))
			fmt.Printf("remote-dns:    %s\n", s.RemoteDNS)
			fmt.Printf("log-level:     %s\n", s.LogLevel)
			return nil
		},
	}
	set := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Change a setting (core, mode, external-path, external-kind, port, lan, proxy-user, proxy-pass, remote-dns, log-level)",
		Example: `  mkconnect settings set core xray
  mkconnect settings set mode tun
  mkconnect settings set lan true
  mkconnect settings set proxy-user me && mkconnect settings set proxy-pass secret`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			setter, ok := settingKeys[args[0]]
			if !ok {
				return fmt.Errorf("unknown setting %q", args[0])
			}
			store, err := loadStore()
			if err != nil {
				return err
			}
			if err := setter(&store.Settings, args[1]); err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			if err := store.Settings.Validate(); err != nil {
				return err
			}
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Printf("✅ %s = %s\n", args[0], args[1])
			return nil
		},
	}
	cmd.AddCommand(set)
	return cmd
}

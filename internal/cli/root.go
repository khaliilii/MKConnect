// Package cli implements the mkconnect command line.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/khaliilii/MKConnect/internal/gateway"
	"github.com/khaliilii/MKConnect/internal/profile"
	"github.com/khaliilii/MKConnect/internal/recovery"
	"github.com/khaliilii/MKConnect/internal/version"
)

var storePath string

// NewRoot builds the root command. Running it without a subcommand connects the active profile.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "mkconnect",
		Short:         "SSH / VMess / VLESS / Trojan / Shadowsocks client with proxy, LAN sharing and TUN modes",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&storePath, "config", "", "profiles file (default: <user config dir>/mkconnect/profiles.json)")

	run := newRunCmd()
	root.RunE = run.RunE
	root.Flags().AddFlagSet(run.Flags())

	root.AddCommand(run, newProfileCmd(), newSubCmd(), newSettingsCmd(), newCoresCmd(), newTestCmd(), newInterfacesCmd(), newCleanupCmd())
	return root
}

func loadStore() (*profile.Store, error) {
	path := storePath
	if path == "" {
		var err error
		if path, err = profile.DefaultPath(); err != nil {
			return nil, err
		}
	}
	return profile.Load(path)
}

func newCoresCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cores",
		Short: "List the cores available in this build",
		Run: func(cmd *cobra.Command, args []string) {
			for _, c := range availableCores() {
				fmt.Println(c)
			}
		},
	}
}

// readSecret prompts for a value without echoing it when stdin is a terminal.
func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	var s string
	_, err := fmt.Scanln(&s)
	return s, err
}

func newInterfacesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "interfaces",
		Short: "List network interfaces that can share the tunnel (for --share)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ifaces, err := gateway.Interfaces()
			if err != nil {
				return err
			}
			for _, ifc := range ifaces {
				fmt.Println(ifc)
			}
			return nil
		},
	}
}

func newCleanupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cleanup",
		Short: "Undo network changes left by a crashed TUN connection (run as root/Administrator)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cleaned, err := recovery.Recover()
			for _, c := range cleaned {
				fmt.Println("🧹 removed:", c)
			}
			if err != nil {
				return err
			}
			if len(cleaned) == 0 {
				fmt.Println("✅ nothing to clean up")
			}
			return nil
		},
	}
}

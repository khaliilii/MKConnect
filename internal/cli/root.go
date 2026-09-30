// Package cli implements the mkconnect command line.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// Version is set at build time with -ldflags "-X github.com/khaliilii/MKConnect/internal/cli.Version=..."
var Version = "dev"

var storePath string

// NewRoot builds the root command. Running it without a subcommand connects the active profile.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "mkconnect",
		Short:         "SSH / VMess / VLESS / Trojan / Shadowsocks client with proxy, LAN sharing and TUN modes",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&storePath, "config", "", "profiles file (default: <user config dir>/mkconnect/profiles.json)")

	run := newRunCmd()
	root.RunE = run.RunE
	root.Flags().AddFlagSet(run.Flags())

	root.AddCommand(run, newProfileCmd(), newSettingsCmd(), newCoresCmd())
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

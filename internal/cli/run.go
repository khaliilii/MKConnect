package cli

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/common-nighthawk/go-figure"
	"github.com/spf13/cobra"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

func availableCores() []string { return engine.Available() }

func newRunCmd() *cobra.Command {
	var (
		core, mode, proxyUser, proxyPass string
		shareIfaces                      []string
		port                             int
		lan                              bool
	)
	cmd := &cobra.Command{
		Use:   "run [profile]",
		Short: "Connect using a profile (default: the active one)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			var p *profile.Profile
			if len(args) == 1 {
				p, err = store.Find(args[0])
			} else {
				p, err = store.ActiveProfile()
			}
			if err != nil {
				return err
			}

			// Flags override the saved settings for this run only.
			s := store.Settings
			f := cmd.Flags()
			if f.Changed("core") {
				s.Core = core
			}
			if f.Changed("mode") {
				s.Mode = mode
			}
			if f.Changed("port") {
				s.ListenPort = port
			}
			if f.Changed("lan") {
				s.AllowLAN = lan
			}
			if f.Changed("proxy-user") {
				s.ProxyUser = proxyUser
			}
			if f.Changed("proxy-pass") {
				s.ProxyPass = proxyPass
			}
			if f.Changed("share") {
				s.ShareInterfaces = shareIfaces
			}

			figure.NewFigure("MKConnect", "small", true).Print()

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			id := p.ID
			return engine.Run(ctx, *p, s, engine.Hooks{
				OnHostKey: func(key string) {
					saved, err := store.Find(id)
					if err != nil {
						return
					}
					saved.HostKey = key
					if err := store.Save(); err != nil {
						log.Printf("⚠️  could not save host key: %v", err)
					}
				},
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&core, "core", "", "core to use: singbox, xray, external")
	f.StringVar(&mode, "mode", "", "proxy or tun")
	f.IntVar(&port, "port", 0, "local proxy port")
	f.BoolVar(&lan, "lan", false, "share the proxy with other devices on the network")
	f.StringVar(&proxyUser, "proxy-user", "", "username required to use the local proxy")
	f.StringVar(&proxyPass, "proxy-pass", "", "password required to use the local proxy")
	f.StringSliceVar(&shareIfaces, "share", nil, "TUN mode: route devices on these network interfaces through the tunnel (gateway), e.g. --share eth1,wlan1")
	return cmd
}

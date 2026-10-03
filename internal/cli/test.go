package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

func newTestCmd() *cobra.Command {
	var (
		group    string
		speed    bool
		parallel int
		sortBy   string
	)
	cmd := &cobra.Command{
		Use:   "test [account...]",
		Short: "Measure latency, quality and speed of accounts (default: all)",
		Long: `Starts each account on a private local port and measures it through the proxy:
latency (average of 3 HTTPS requests, each on a new connection), how many of
them succeeded, and with --speed the download speed. Results are saved and
shown by "profile list" and the app.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			var idx []int
			if len(args) > 0 {
				for _, ref := range args {
					p, err := store.Find(ref)
					if err != nil {
						return err
					}
					for i := range store.Profiles {
						if store.Profiles[i].ID == p.ID {
							idx = append(idx, i)
						}
					}
				}
			} else {
				gid := ""
				if group != "" {
					g, err := store.FindGroup(group)
					if err != nil {
						return err
					}
					gid = g.ID
				}
				for i, p := range store.Profiles {
					if gid == "" || p.Group == gid {
						idx = append(idx, i)
					}
				}
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()

			results := engine.TestMany(ctx, store.Profiles, idx, store.Settings, engine.TestOptions{Speed: speed}, parallel,
				func(i int, r *profile.TestResult) {
					fmt.Fprintf(os.Stderr, "%-40s %s\n", store.Profiles[i].Name, describe(r))
				})
			for i, r := range results {
				store.Profiles[i].Test = r
			}
			if err := store.Save(); err != nil {
				return err
			}
			if sortBy == "" {
				sortBy = profile.SortLatency
				if speed {
					sortBy = profile.SortSpeed
				}
			}
			profile.SortProfiles(store.Profiles, idx, sortBy)
			fmt.Println()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tACCOUNT\tLATENCY\tOK\tJITTER\tSPEED\tID")
			for n, i := range idx {
				p := &store.Profiles[i]
				r := p.Test
				if !r.OK() {
					fmt.Fprintf(w, "%d\t%s\t-\t0/%d\t\t\t%s\t%s\n", n+1, p.Name, r.Sent, p.ID, r.Error)
					continue
				}
				sp := "-"
				if r.Speed > 0 {
					sp = profile.FormatBytes(r.Speed) + "/s"
				}
				fmt.Fprintf(w, "%d\t%s\t%d ms\t%d/%d\t%d ms\t%s\t%s\n", n+1, p.Name, r.Latency, r.Received, r.Sent, r.Jitter, sp, p.ID)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "only test this group")
	cmd.Flags().BoolVar(&speed, "speed", false, "also measure download speed (uses some traffic)")
	cmd.Flags().IntVar(&parallel, "parallel", 8, "accounts tested at the same time")
	cmd.Flags().StringVar(&sortBy, "sort", "", "sort the table: latency or speed")
	return cmd
}

func describe(r *profile.TestResult) string {
	if r.OK() {
		return r.Summary()
	}
	return "failed: " + r.Error
}

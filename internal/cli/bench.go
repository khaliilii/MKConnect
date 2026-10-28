package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/khaliilii/MKConnect/internal/engine"
	"github.com/khaliilii/MKConnect/internal/profile"
)

func newBenchCmd() *cobra.Command {
	var (
		group    string
		parallel int
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "bench [account...]",
		Short: "Benchmark accounts the way browsing uses them (default: the active one)",
		Long: `Starts each account on a private local port and measures what using it feels
like: new connections one by one (the time to the first answer, and how many
fail), a page-like burst of new connections to different sites, and download
speed with one and with four streams. Accounts are ranked by a score that
weighs failures heavily. Uses some traffic (about 5 s of download per stream
test and account).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			var picked []profile.Profile
			switch {
			case len(args) > 0:
				for _, ref := range args {
					p, err := store.Find(ref)
					if err != nil {
						return err
					}
					picked = append(picked, *p)
				}
			case group != "":
				g, err := store.FindGroup(group)
				if err != nil {
					return err
				}
				for _, p := range store.Profiles {
					if p.Group == g.ID && !p.IsInfo() {
						picked = append(picked, p)
					}
				}
			default:
				p, err := store.ActiveProfile()
				if err != nil {
					return err
				}
				picked = append(picked, *p)
			}

			// The cores write their own log to stdout; keep it for results only.
			out := os.Stdout
			os.Stdout = os.Stderr
			defer func() { os.Stdout = out }()

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			results := make([]*engine.BenchResult, len(picked))
			sem := make(chan struct{}, max(parallel, 1))
			var wg sync.WaitGroup
			for i, p := range picked {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					results[i] = engine.Benchmark(ctx, p, store.Settings, engine.BenchOptions{})
					results[i].Name = p.Name
					if !asJSON {
						fmt.Fprintf(os.Stderr, "%-40s %s\n", p.Name, results[i])
					}
				}()
			}
			wg.Wait()
			slices.SortStableFunc(results, func(a, b *engine.BenchResult) int {
				switch sa, sb := a.Score(), b.Score(); {
				case sa > sb:
					return -1
				case sa < sb:
					return 1
				}
				return 0
			})
			if asJSON {
				type row struct {
					*engine.BenchResult
					Score float64 `json:"score"`
				}
				var rows []row
				for _, r := range results {
					rows = append(rows, row{r, r.Score()})
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			fmt.Fprintln(out)
			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tACCOUNT\tCORE\tNEW CONN\tFAILED\tPAGE\tFAILED\tSPEED\tSPEED x4\tSCORE")
			for n, r := range results {
				if r.Error != "" {
					fmt.Fprintf(w, "%d\t%s\t%s\t-\t\t-\t\t-\t-\t0  %s\n", n+1, r.Name, r.Core, r.Error)
					continue
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%d ms\t%d/%d\t%d ms\t%d/%d\t%s/s\t%s/s\t%.0f\n", n+1, r.Name, r.Core,
					r.ConnectMedian.Milliseconds(), r.ConnectFailed, r.Connects, r.Page.Milliseconds(), r.PageFailed, r.PageParts,
					profile.FormatBytes(r.Download), profile.FormatBytes(r.DownloadMany), r.Score())
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "benchmark every account of this group")
	cmd.Flags().IntVar(&parallel, "parallel", 1, "accounts measured at the same time (more is faster but skews speeds)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the results as JSON")
	return cmd
}

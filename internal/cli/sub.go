package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/khaliilii/MKConnect/internal/profile"
)

func newSubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sub",
		Aliases: []string{"subscription", "subs"},
		Short:   "Manage subscriptions (groups of accounts fetched from a URL)",
	}

	var name string
	add := &cobra.Command{
		Use:   "add <url>",
		Short: "Add a subscription and fetch its accounts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			g := store.AddGroup(name, args[0])
			if err := updateGroup(store, g); err != nil {
				return err
			}
			return store.Save()
		},
	}
	add.Flags().StringVar(&name, "name", "", "group name (default: the provider's title)")

	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List subscriptions with their data usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tACCOUNTS\tUSED\tEXPIRES\tUPDATED")
			for _, g := range store.Groups {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n", g.ID, g.Name, store.GroupSize(g.ID),
					usageText(g.Usage), expiryText(g.Usage), updatedText(&g))
			}
			return w.Flush()
		},
	}

	var all bool
	update := &cobra.Command{
		Use:   "update [id|name]",
		Short: "Refresh a subscription (or all with --all)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			var targets []string
			if all || len(args) == 0 {
				for _, g := range store.Groups {
					if g.IsSubscription() {
						targets = append(targets, g.ID)
					}
				}
			} else {
				g, err := store.FindGroup(args[0])
				if err != nil {
					return err
				}
				targets = []string{g.ID}
			}
			var failed int
			for _, id := range targets {
				g, _ := store.FindGroup(id)
				if err := updateGroup(store, g); err != nil {
					fmt.Fprintf(os.Stderr, "❌ %s: %v\n", g.Name, err)
					failed++
				}
			}
			if err := store.Save(); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d subscription(s) failed to update", failed)
			}
			return nil
		},
	}
	update.Flags().BoolVar(&all, "all", false, "update every subscription")

	remove := &cobra.Command{
		Use:     "remove <id|name>",
		Aliases: []string{"rm"},
		Short:   "Remove a group and all of its accounts",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore()
			if err != nil {
				return err
			}
			g, err := store.FindGroup(args[0])
			if err != nil {
				return err
			}
			n := store.GroupSize(g.ID)
			store.RemoveGroup(g.ID)
			if err := store.Save(); err != nil {
				return err
			}
			fmt.Printf("✅ Removed group and %d account(s)\n", n)
			return nil
		},
	}

	cmd.AddCommand(add, list, update, remove)
	return cmd
}

func updateGroup(store *profile.Store, g *profile.Group) error {
	data, err := profile.FetchSubscription(g.URL)
	if err != nil {
		return err
	}
	n, errs := store.ApplySubscription(g, data, time.Now())
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "⚠️  skipped: %v\n", e)
	}
	if n == 0 {
		return fmt.Errorf("no usable accounts")
	}
	fmt.Printf("✅ %s: %d account(s), %s used, expires %s\n", g.Name, n, usageText(g.Usage), expiryText(g.Usage))
	return nil
}

func usageText(u *profile.Usage) string {
	if u == nil {
		return "-"
	}
	if u.Total == 0 {
		return profile.FormatBytes(u.Used()) + " / ∞"
	}
	return profile.FormatBytes(u.Used()) + " / " + profile.FormatBytes(u.Total)
}

func expiryText(u *profile.Usage) string {
	if u == nil || u.Expire.IsZero() {
		return "never"
	}
	return u.Expire.Format("2006-01-02")
}

func updatedText(g *profile.Group) string {
	if !g.IsSubscription() {
		return "local"
	}
	if g.UpdatedAt.IsZero() {
		return "never"
	}
	return g.UpdatedAt.Format("2006-01-02 15:04")
}

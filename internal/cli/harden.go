package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/harden"
)

var dryRun bool

var hardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Apply security hardening preset",
	Long:  "Review and apply recommended security hardening actions. Use --dry-run to preview changes.",
	RunE: func(cmd *cobra.Command, args []string) error {
		actions, err := harden.Plan()
		if err != nil {
			return fmt.Errorf("failed to create hardening plan: %w", err)
		}

		var needsChange []harden.Action
		for _, a := range actions {
			if a.CurrentState != a.DesiredState {
				needsChange = append(needsChange, a)
			}
		}

		if jsonFlag {
			result := jsonHardenResult{
				DryRun:  dryRun,
				Actions: actions,
			}

			if dryRun || len(needsChange) == 0 {
				result.Applied = 0
				return printJSON(result)
			}

			// Apply changes and record per-action results.
			var results []jsonHardenApplied
			for _, a := range needsChange {
				r := jsonHardenApplied{Name: a.Name, Status: "applied"}
				if err := a.Apply(); err != nil {
					r.Status = "failed"
					r.Error = err.Error()
				}
				results = append(results, r)
			}
			result.Applied = len(results)
			result.Results = results
			return printJSON(result)
		}

		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ACTION\tCURRENT\tDESIRED\tCHANGE\n")
		fmt.Fprintf(w, "------\t-------\t-------\t------\n")

		for _, a := range actions {
			change := green("OK")
			if a.CurrentState != a.DesiredState {
				change = yellow("CHANGE")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.Name, a.CurrentState, a.DesiredState, change)
		}
		w.Flush()
		fmt.Println()

		if len(needsChange) == 0 {
			fmt.Println(green("System is already hardened. No changes needed."))
			return nil
		}

		if dryRun {
			fmt.Printf("%d change(s) would be applied. Run without --dry-run to apply.\n", len(needsChange))
			return nil
		}

		fmt.Printf("Applying %d change(s)...\n", len(needsChange))
		if err := harden.Apply(needsChange); err != nil {
			return err
		}

		fmt.Println(green("Hardening complete."))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(hardenCmd)
	hardenCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview changes without applying them")
}

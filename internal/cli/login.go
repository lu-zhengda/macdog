package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/login"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "List login items and launch agents",
	Long:  "Display all login items, including osascript login items and LaunchAgents.",
	RunE: func(cmd *cobra.Command, args []string) error {
		items, err := login.ListItems()
		if err != nil {
			return fmt.Errorf("failed to list login items: %w", err)
		}

		if jsonFlag {
			return printJSON(items)
		}

		if len(items) == 0 {
			fmt.Println("No login items found.")
			return nil
		}

		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "NAME\tKIND\tPATH\n")
		fmt.Fprintf(w, "----\t----\t----\n")
		for _, item := range items {
			path := item.Path
			if path == "" {
				path = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", item.Name, item.Kind, path)
		}
		w.Flush()
		fmt.Println()

		return nil
	},
}

var loginRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a login item",
	Long:  "Remove a login item or disable a launch agent by name.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := login.RemoveItem(name); err != nil {
			return err
		}
		if jsonFlag {
			return printJSON(jsonAction{OK: true, Action: "remove", Target: name})
		}
		fmt.Printf("Removed login item %q.\n", name)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.AddCommand(loginRemoveCmd)
}

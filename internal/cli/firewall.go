package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/firewall"
)

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "Show firewall status and rules",
	Long:  "Display the current firewall status, stealth mode, block-all state, and application rules.",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := firewall.GetStatus()
		if err != nil {
			return fmt.Errorf("failed to get firewall status: %w", err)
		}

		if jsonFlag {
			return printJSON(status)
		}

		fmt.Println()
		fmt.Printf("Firewall:     %s\n", colorBool(status.Enabled, "on", "off"))
		fmt.Printf("Stealth Mode: %s\n", colorBool(status.StealthMode, "on", "off"))
		fmt.Printf("Block All:    %s\n", colorBool(status.BlockAll, "on", "off"))
		fmt.Println()

		if len(status.Rules) == 0 {
			fmt.Println("No application rules configured.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "APP\tPATH\tSTATUS\n")
		fmt.Fprintf(w, "---\t----\t------\n")
		for _, r := range status.Rules {
			status := red("blocked")
			if r.Allowed {
				status = green("allowed")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, r.Path, status)
		}
		w.Flush()
		fmt.Println()

		return nil
	},
}

var firewallEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable the firewall",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewall.Enable(); err != nil {
			return err
		}
		if jsonFlag {
			return printJSON(jsonAction{OK: true, Action: "enable", Target: "firewall"})
		}
		fmt.Println(green("Firewall enabled."))
		return nil
	},
}

var firewallDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable the firewall",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewall.Disable(); err != nil {
			return err
		}
		if jsonFlag {
			return printJSON(jsonAction{OK: true, Action: "disable", Target: "firewall"})
		}
		fmt.Println(red("Firewall disabled."))
		return nil
	},
}

var firewallAllowCmd = &cobra.Command{
	Use:   "allow <app-path>",
	Short: "Allow an application through the firewall",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewall.AllowApp(args[0]); err != nil {
			return err
		}
		if jsonFlag {
			return printJSON(jsonAction{OK: true, Action: "allow", Target: args[0]})
		}
		fmt.Printf("%s is now %s through the firewall.\n", args[0], green("allowed"))
		return nil
	},
}

var firewallBlockCmd = &cobra.Command{
	Use:   "block <app-path>",
	Short: "Block an application in the firewall",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewall.BlockApp(args[0]); err != nil {
			return err
		}
		if jsonFlag {
			return printJSON(jsonAction{OK: true, Action: "block", Target: args[0]})
		}
		fmt.Printf("%s is now %s in the firewall.\n", args[0], red("blocked"))
		return nil
	},
}

var firewallExportCmd = &cobra.Command{
	Use:   "export [file]",
	Short: "Export firewall rules to a JSON file",
	Long:  "Export the current firewall status and rules to a JSON file. If no file is specified, output to stdout.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var path string
		if len(args) == 1 {
			path = args[0]
		}

		data, err := firewall.ExportRules(path)
		if err != nil {
			return fmt.Errorf("failed to export firewall rules: %w", err)
		}

		if data != nil {
			// No file specified — write to stdout.
			os.Stdout.Write(data)
			return nil
		}

		fmt.Printf("Firewall rules exported to %s\n", green(path))
		return nil
	},
}

var firewallImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import firewall rules from a JSON file",
	Long:  "Import firewall status and rules from a JSON file. Requires sudo.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := firewall.ImportRules(args[0]); err != nil {
			return fmt.Errorf("failed to import firewall rules: %w", err)
		}
		if jsonFlag {
			return printJSON(jsonAction{OK: true, Action: "import", Target: args[0]})
		}
		fmt.Printf("Firewall rules imported from %s\n", green(args[0]))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(firewallCmd)
	firewallCmd.AddCommand(firewallEnableCmd)
	firewallCmd.AddCommand(firewallDisableCmd)
	firewallCmd.AddCommand(firewallAllowCmd)
	firewallCmd.AddCommand(firewallBlockCmd)
	firewallCmd.AddCommand(firewallExportCmd)
	firewallCmd.AddCommand(firewallImportCmd)
}

// colorBool formats a boolean as a colored on/off string.
func colorBool(b bool, onStr, offStr string) string {
	if b {
		return green(onStr)
	}
	return red(offStr)
}

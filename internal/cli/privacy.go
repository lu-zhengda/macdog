package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/privacy"
)

var privacyCmd = &cobra.Command{
	Use:   "privacy",
	Short: "List TCC privacy permissions",
	Long:  "Display applications that have been granted or denied privacy permissions (Camera, Microphone, etc.).",
	RunE: func(cmd *cobra.Command, args []string) error {
		perms, err := privacy.ListPermissions()
		if err != nil {
			return fmt.Errorf("failed to list permissions: %w", err)
		}

		if jsonFlag {
			return printJSON(perms)
		}

		if len(perms) == 0 {
			fmt.Println("No TCC permissions found.")
			return nil
		}

		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "SERVICE\tAPP\tBUNDLE ID\tSTATUS\n")
		fmt.Fprintf(w, "-------\t---\t---------\t------\n")
		for _, p := range perms {
			status := red("denied")
			if p.Allowed {
				status = green("allowed")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Service, p.App, p.BundleID, status)
		}
		w.Flush()
		fmt.Println()

		return nil
	},
}

var privacyRevokeCmd = &cobra.Command{
	Use:   "revoke <service> <bundle-id>",
	Short: "Revoke a TCC permission",
	Long:  "Revoke a privacy permission for a specific service and application bundle ID.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		service := args[0]
		bundleID := args[1]

		if err := privacy.RevokePermission(service, bundleID); err != nil {
			return err
		}
		fmt.Printf("Revoked %s permission for %s.\n", service, bundleID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(privacyCmd)
	privacyCmd.AddCommand(privacyRevokeCmd)
}

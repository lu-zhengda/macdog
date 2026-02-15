package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/audit"
)

type auditResult struct {
	audit.Report
	Score int    `json:"score"`
	Grade string `json:"grade"`
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full security audit",
	Long:  "Audit your macOS security posture and get a letter grade (A-F).",
	RunE: func(cmd *cobra.Command, args []string) error {
		report, err := audit.Full()
		if err != nil {
			return fmt.Errorf("failed to run audit: %w", err)
		}

		if jsonFlag {
			return printJSON(auditResult{
				Report: *report,
				Score:  report.Score(),
				Grade:  report.Grade(),
			})
		}

		grade := report.Grade()
		score := report.Score()

		fmt.Printf("\nSecurity Grade: %s (%d/100)\n\n", colorGrade(grade), score)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "CHECK\tSTATUS\n")
		fmt.Fprintf(w, "-----\t------\n")
		fmt.Fprintf(w, "System Integrity Protection\t%s\n", colorStatus(report.SIP, "enabled"))
		fmt.Fprintf(w, "Firewall\t%s\n", colorStatus(report.Firewall, "on"))
		fmt.Fprintf(w, "FileVault\t%s\n", colorStatus(report.FileVault, "on"))
		fmt.Fprintf(w, "Gatekeeper\t%s\n", colorStatus(report.Gatekeeper, "enabled"))
		fmt.Fprintf(w, "Remote Login\t%s\n", colorStatusInverse(report.RemoteLogin, "off"))
		w.Flush()

		fmt.Println()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}

// colorGrade returns a color-coded grade string.
func colorGrade(grade string) string {
	switch grade {
	case "A":
		return green(grade)
	case "B":
		return green(grade)
	case "C":
		return yellow(grade)
	case "D":
		return red(grade)
	case "F":
		return red(grade)
	default:
		return grade
	}
}

// colorStatus colors a status value green if it matches the secure value, red otherwise.
func colorStatus(value, secureValue string) string {
	if value == secureValue {
		return green(value)
	}
	return red(value)
}

// colorStatusInverse colors a status value green if it matches (for values where the "good" state
// is the given value, e.g., Remote Login = "off" is good).
func colorStatusInverse(value, secureValue string) string {
	if value == secureValue {
		return green(value)
	}
	return red(value)
}

// ANSI color helpers.
func green(s string) string { return "\033[32m" + s + "\033[0m" }
func red(s string) string   { return "\033[31m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }

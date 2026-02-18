package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/status"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Overall security status summary",
	Long: `Show a concise security status summary across all macdog domains.

Aggregates key signals from audit, firewall, login items, and privacy without
running slow operations (e.g., event log scanning).  All checks are fast and
read-only.

Exit codes:
  0  overall status is ok
  1  overall status is warning
  2  overall status is critical`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStatus()
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus() error {
	report, err := status.Collect()
	if err != nil {
		return fmt.Errorf("failed to collect status: %w", err)
	}

	if jsonFlag {
		if err := printJSON(report); err != nil {
			return err
		}
		return exitCodeForOverall(report.Overall)
	}

	printStatusHuman(report)
	return exitCodeForOverall(report.Overall)
}

// printStatusHuman renders the status report in a concise human-readable table.
func printStatusHuman(r *status.Report) {
	// ── Header ───────────────────────────────────────────────────────────
	fmt.Printf("\nSecurity Status: %s   Grade %s (%d/100)\n\n",
		colorOverall(r.Overall), colorGrade(r.Grade), r.Score)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "DOMAIN\tSTATUS\tDETAIL\n")
	fmt.Fprintf(w, "------\t------\t------\n")

	// ── Audit checks ─────────────────────────────────────────────────────
	fmt.Fprintf(w, "SIP\t%s\t%s\n",
		colorStatus(r.Audit.SIP, "enabled"),
		r.Audit.SIP)
	fmt.Fprintf(w, "Firewall\t%s\t%s\n",
		colorStatus(r.Audit.Firewall, "on"),
		firewallDetail(r))
	fmt.Fprintf(w, "FileVault\t%s\t%s\n",
		colorStatus(r.Audit.FileVault, "on"),
		r.Audit.FileVault)
	fmt.Fprintf(w, "Gatekeeper\t%s\t%s\n",
		colorStatus(r.Audit.Gatekeeper, "enabled"),
		r.Audit.Gatekeeper)
	fmt.Fprintf(w, "Remote Login\t%s\t%s\n",
		colorStatusInverse(r.Audit.RemoteLogin, "off"),
		r.Audit.RemoteLogin)

	// ── Login items ───────────────────────────────────────────────────────
	if r.LoginItems.Error != "" {
		fmt.Fprintf(w, "Login Items\t%s\t%s\n", yellow("?"), r.LoginItems.Error)
	} else {
		fmt.Fprintf(w, "Login Items\t%s\t%d items\n",
			colorOverall(status.OverallOK), r.LoginItems.Count)
	}

	// ── Privacy ───────────────────────────────────────────────────────────
	if r.Privacy.Error != "" {
		fmt.Fprintf(w, "Privacy\t%s\t%s\n", yellow("?"), "Full Disk Access required")
	} else {
		fmt.Fprintf(w, "Privacy\t%s\t%d granted, %d denied (%d total)\n",
			colorOverall(status.OverallOK),
			r.Privacy.Granted, r.Privacy.Denied, r.Privacy.Total)
	}

	w.Flush()
	fmt.Printf("\nGenerated: %s\n\n", r.GeneratedAt)
}

// firewallDetail returns a detail string for the firewall row.
func firewallDetail(r *status.Report) string {
	if r.Firewall.Error != "" {
		return r.Firewall.Error
	}
	state := r.Audit.Firewall
	if r.Firewall.StealthMode {
		state += ", stealth on"
	}
	if r.Firewall.BlockAll {
		state += ", block-all on"
	}
	if r.Firewall.RuleCount > 0 {
		state += fmt.Sprintf(", %d rules", r.Firewall.RuleCount)
	}
	return state
}

// colorOverall returns a colored overall status string.
func colorOverall(overall string) string {
	switch overall {
	case status.OverallOK:
		return green("OK")
	case status.OverallWarning:
		return yellow("WARNING")
	case status.OverallCritical:
		return red("CRITICAL")
	default:
		return overall
	}
}

// exitCodeForOverall converts overall status to a meaningful exit code.
//
//	ok       → 0
//	warning  → 1
//	critical → 2
func exitCodeForOverall(overall string) error {
	switch overall {
	case status.OverallWarning:
		return exitCode(1)
	case status.OverallCritical:
		return exitCode(2)
	default:
		return nil
	}
}

// ExitCoder is implemented by errors that carry a specific OS exit code.
// main.go uses this to call os.Exit with the right code without printing
// an error message.
type ExitCoder interface {
	error
	ExitCode() int
}

// exitCode is a sentinel error type that carries a numeric exit code.
type exitCode int

func (e exitCode) Error() string    { return fmt.Sprintf("exit code %d", int(e)) }
func (e exitCode) ExitCode() int    { return int(e) }

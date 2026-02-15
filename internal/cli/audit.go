package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/audit"
)

type auditResult struct {
	audit.Report
	Score int    `json:"score"`
	Grade string `json:"grade"`
}

var (
	fixFlag      bool
	watchFlag    bool
	intervalFlag int
	minScoreFlag int
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full security audit",
	Long:  "Audit your macOS security posture and get a letter grade (A-F).",
	RunE: func(cmd *cobra.Command, args []string) error {
		if fixFlag {
			return runAuditFix()
		}
		if watchFlag {
			return runAuditWatch()
		}
		return runAudit()
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().BoolVar(&fixFlag, "fix", false, "Auto-apply recommended fixes for failing checks")
	auditCmd.Flags().BoolVar(&watchFlag, "watch", false, "Poll security score and alert on drops")
	auditCmd.Flags().IntVar(&intervalFlag, "interval", 60, "Polling interval in seconds (used with --watch)")
	auditCmd.Flags().IntVar(&minScoreFlag, "min-score", 70, "Minimum acceptable score (used with --watch)")
}

func runAudit() error {
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
}

func runAuditFix() error {
	fixReport, err := audit.Fix()
	if err != nil {
		return fmt.Errorf("failed to run audit fix: %w", err)
	}

	if jsonFlag {
		return printJSON(fixReport)
	}

	if len(fixReport.Results) == 0 {
		fmt.Println(green("\nAll checks are passing. Nothing to fix."))
		return nil
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "CHECK\tSTATUS\tDETAIL\n")
	fmt.Fprintf(w, "-----\t------\t------\n")
	for _, r := range fixReport.Results {
		var detail string
		switch r.Status {
		case "fixed":
			detail = fmt.Sprintf("%s -> %s", r.Before, r.After)
		case "skipped":
			detail = r.Reason
		case "failed":
			detail = r.Reason
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Check, colorFixStatus(r.Status), detail)
	}
	w.Flush()

	after := &fixReport.After
	fmt.Printf("\nScore: %s (%d/100)\n\n", colorGrade(after.Grade()), after.Score())
	return nil
}

type watchAlert struct {
	Score    int    `json:"score"`
	Grade   string `json:"grade"`
	MinScore int   `json:"min_score"`
	Message string `json:"message"`
	audit.Report
}

func runAuditWatch() error {
	interval := time.Duration(intervalFlag) * time.Second
	if intervalFlag < 1 {
		interval = 60 * time.Second
	}

	fmt.Printf("Watching security score (interval=%ds, min-score=%d)...\n", intervalFlag, minScoreFlag)

	for {
		report, err := audit.Full()
		if err != nil {
			return fmt.Errorf("failed to run audit: %w", err)
		}

		score := report.Score()
		grade := report.Grade()
		ts := time.Now().Format("15:04:05")

		if score < minScoreFlag {
			if jsonFlag {
				return printJSON(watchAlert{
					Score:    score,
					Grade:    grade,
					MinScore: minScoreFlag,
					Message:  fmt.Sprintf("security score %d is below minimum %d", score, minScoreFlag),
					Report:   *report,
				})
			}
			fmt.Printf("[%s] %s Security score %d (%s) is below minimum %d\n",
				ts, red("ALERT:"), score, colorGrade(grade), minScoreFlag)
			os.Exit(1)
		}

		if !jsonFlag {
			fmt.Printf("[%s] Score: %d (%s) - OK\n", ts, score, colorGrade(grade))
		}

		time.Sleep(interval)
	}
}

// colorFixStatus colors fix status strings.
func colorFixStatus(status string) string {
	switch status {
	case "fixed":
		return green(status)
	case "skipped":
		return yellow(status)
	case "failed":
		return red(status)
	default:
		return status
	}
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
func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }

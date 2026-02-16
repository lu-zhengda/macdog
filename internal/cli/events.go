package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/lu-zhengda/macdog/internal/events"
)

var (
	eventsLastFlag     string
	eventsTypeFlag     string
	eventsSeverityFlag string
)

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Show security events from system log",
	Long: `Parse the macOS unified system log for security-relevant events.

Event types: auth, tcc, firewall, gatekeeper, install

Examples:
  macdog events                    # show events from last 24h
  macdog events --last 1h          # show events from last hour
  macdog events --last 7d          # show events from last 7 days
  macdog events --type auth        # show only authentication events
  macdog events --type tcc --json  # TCC events as JSON
  macdog events --severity warning # skip info-level noise`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEvents()
	},
}

func init() {
	rootCmd.AddCommand(eventsCmd)
	eventsCmd.Flags().StringVar(&eventsLastFlag, "last", "24h", "Time window for events (e.g., 1h, 24h, 7d)")
	eventsCmd.Flags().StringVar(&eventsTypeFlag, "type", "", "Filter by event type (auth, tcc, firewall, gatekeeper, install)")
	eventsCmd.Flags().StringVar(&eventsSeverityFlag, "severity", "", "Minimum severity level (info, warning, critical)")
}

func runEvents() error {
	if eventsTypeFlag != "" {
		validTypes := events.ValidEventTypes()
		valid := false
		for _, vt := range validTypes {
			if eventsTypeFlag == vt {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid event type %q (valid types: %s)",
				eventsTypeFlag, strings.Join(events.ValidEventTypes(), ", "))
		}
	}

	if eventsSeverityFlag != "" {
		validSeverities := []string{"info", "warning", "critical"}
		valid := false
		for _, vs := range validSeverities {
			if eventsSeverityFlag == vs {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid severity %q (valid values: info, warning, critical)",
				eventsSeverityFlag)
		}
	}

	var secEvents []events.SecurityEvent
	var err error

	if eventsTypeFlag != "" {
		secEvents, err = events.FetchEvents(eventsTypeFlag, eventsLastFlag)
	} else {
		secEvents, err = events.FetchAllEvents(eventsLastFlag)
	}
	if err != nil {
		return fmt.Errorf("failed to fetch events: %w", err)
	}

	// Filter by minimum severity level.
	secEvents = events.FilterBySeverity(secEvents, eventsSeverityFlag)

	// Deduplicate consecutive same-type same-severity events within 30s.
	secEvents = events.DeduplicateEvents(secEvents, 30*time.Second)

	if jsonFlag {
		return printJSON(secEvents)
	}

	if len(secEvents) == 0 {
		fmt.Println("No security events found.")
		return nil
	}

	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "TIMESTAMP\tTYPE\tSEVERITY\tPROCESS\tMESSAGE\n")
	fmt.Fprintf(w, "---------\t----\t--------\t-------\t-------\n")
	for _, e := range secEvents {
		severity := colorSeverity(e.Severity)
		msg := e.Message
		if e.Count > 1 {
			msg = fmt.Sprintf("(%dx) %s", e.Count, e.Message)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp, e.Type, severity, e.Process, msg)
	}
	w.Flush()
	fmt.Printf("\nTotal: %d events\n\n", len(secEvents))

	return nil
}

// colorSeverity returns a color-coded severity string.
func colorSeverity(severity string) string {
	switch severity {
	case "critical":
		return red(severity)
	case "warning":
		return yellow(severity)
	case "info":
		return green(severity)
	default:
		return severity
	}
}

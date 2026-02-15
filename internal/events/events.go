package events

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SecurityEvent represents a single security-relevant event parsed from system logs.
type SecurityEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`     // auth, tcc, firewall, gatekeeper, install
	Severity  string `json:"severity"` // info, warning, critical
	Process   string `json:"process"`
	Message   string `json:"message"`
}

// eventTypeDef defines a log source and its parsing rules.
type eventTypeDef struct {
	Name      string
	Predicate string // for `log show --predicate`
}

// eventTypes maps event type names to their log source definitions.
var eventTypes = map[string]eventTypeDef{
	"auth": {
		Name:      "auth",
		Predicate: `subsystem == "com.apple.Authorization"`,
	},
	"tcc": {
		Name:      "tcc",
		Predicate: `subsystem == "com.apple.TCC"`,
	},
	"firewall": {
		Name:      "firewall",
		Predicate: `subsystem == "com.apple.alf"`,
	},
	"gatekeeper": {
		Name:      "gatekeeper",
		Predicate: `subsystem == "com.apple.syspolicy"`,
	},
}

// ValidEventTypes returns the list of valid event type names.
func ValidEventTypes() []string {
	return []string{"auth", "tcc", "firewall", "gatekeeper", "install"}
}

// compactLogRe matches the compact log format from `log show --style compact`.
// Example line: 2024-01-15 10:30:45.123 Df loginwindow[123:1a2b] [com.apple.Authorization:authd] User authenticated successfully
var compactLogRe = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{4})?)\s+` + // timestamp (timezone optional)
		`\w{1,3}\s+` + // log type code (Df, E, I, D, etc.)
		`(\w+)\[` + // process name (capture group 2)
		`[^\]]+\]\s+` + // [PID:TID]
		`\[[^\]]+\]\s+` + // [subsystem:category]
		`(.+)$`, // message (capture group 3)
)

// installLogRe matches install.log format.
// Example: 2024-01-15 10:30:45-0800 processName[123]: message
var installLogRe = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[+-]\d{4})\s+` + // timestamp
		`(\S+?)(?:\[\d+\])?:\s+` + // process name (optionally with PID)
		`(.+)$`, // message
)

// ParseLogEvents parses `log show` compact output into SecurityEvent slices.
func ParseLogEvents(output string, eventType string) []SecurityEvent {
	var events []SecurityEvent

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		matches := compactLogRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		ts := normalizeTimestamp(matches[1])
		process := matches[2]
		message := matches[3]

		severity := assignSeverity(eventType, message)

		events = append(events, SecurityEvent{
			Timestamp: ts,
			Type:      eventType,
			Severity:  severity,
			Process:   process,
			Message:   truncateMessage(message, 200),
		})
	}

	return events
}

// ParseInstallLog parses /var/log/install.log entries into SecurityEvent slices.
func ParseInstallLog(output string) []SecurityEvent {
	var events []SecurityEvent

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		matches := installLogRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		ts := normalizeTimestamp(matches[1])
		process := matches[2]
		message := matches[3]

		severity := assignSeverity("install", message)

		events = append(events, SecurityEvent{
			Timestamp: ts,
			Type:      "install",
			Severity:  severity,
			Process:   process,
			Message:   truncateMessage(message, 200),
		})
	}

	return events
}

// CommandRunner abstracts command execution for testing.
type CommandRunner func(name string, args ...string) ([]byte, error)

// defaultRunner runs commands via os/exec.
func defaultRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// FetchEvents runs `log show` with appropriate predicates and returns parsed events.
func FetchEvents(eventType string, duration string) ([]SecurityEvent, error) {
	return fetchEventsWithRunner(eventType, duration, defaultRunner)
}

func fetchEventsWithRunner(eventType string, duration string, runner CommandRunner) ([]SecurityEvent, error) {
	if eventType == "install" {
		return fetchInstallEventsWithRunner(duration, runner)
	}

	def, ok := eventTypes[eventType]
	if !ok {
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}

	logDuration, err := convertDuration(duration)
	if err != nil {
		return nil, fmt.Errorf("invalid duration %q: %w", duration, err)
	}

	out, err := runner("log", "show",
		"--predicate", def.Predicate,
		"--style", "compact",
		"--last", logDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to run log show for %s: %w", eventType, err)
	}

	return ParseLogEvents(string(out), eventType), nil
}

// fetchInstallEventsWithRunner reads /var/log/install.log and filters by duration.
func fetchInstallEventsWithRunner(duration string, runner CommandRunner) ([]SecurityEvent, error) {
	out, err := runner("cat", "/var/log/install.log")
	if err != nil {
		return nil, fmt.Errorf("failed to read install.log: %w", err)
	}

	events := ParseInstallLog(string(out))

	cutoff, err := durationCutoff(duration)
	if err != nil {
		return nil, fmt.Errorf("invalid duration %q: %w", duration, err)
	}

	var filtered []SecurityEvent
	for _, e := range events {
		t, parseErr := time.Parse("2006-01-02 15:04:05", e.Timestamp)
		if parseErr != nil {
			// If we can't parse the timestamp, include the event anyway.
			filtered = append(filtered, e)
			continue
		}
		if t.After(cutoff) {
			filtered = append(filtered, e)
		}
	}

	return filtered, nil
}

// FetchAllEvents fetches all event types and merges them, sorted by timestamp.
func FetchAllEvents(duration string) ([]SecurityEvent, error) {
	return fetchAllEventsWithRunner(duration, defaultRunner)
}

func fetchAllEventsWithRunner(duration string, runner CommandRunner) ([]SecurityEvent, error) {
	var allEvents []SecurityEvent

	for _, et := range ValidEventTypes() {
		events, err := fetchEventsWithRunner(et, duration, runner)
		if err != nil {
			// Log source may not be available; skip silently.
			continue
		}
		allEvents = append(allEvents, events...)
	}

	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp < allEvents[j].Timestamp
	})

	return allEvents, nil
}

// assignSeverity determines the severity of an event based on its type and message content.
func assignSeverity(eventType, message string) string {
	lower := strings.ToLower(message)

	switch eventType {
	case "auth":
		switch {
		case strings.Contains(lower, "failed") || strings.Contains(lower, "failure") || strings.Contains(lower, "denied"):
			return "critical"
		case strings.Contains(lower, "sudo"):
			return "warning"
		case strings.Contains(lower, "authenticated") || strings.Contains(lower, "succeeded") || strings.Contains(lower, "success"):
			return "info"
		default:
			return "info"
		}

	case "tcc":
		switch {
		case strings.Contains(lower, "denied"):
			return "critical"
		case strings.Contains(lower, "prompted"):
			return "warning"
		case strings.Contains(lower, "allowed"):
			return "info"
		default:
			return "info"
		}

	case "firewall":
		switch {
		case strings.Contains(lower, "deny") || strings.Contains(lower, "block"):
			return "critical"
		case strings.Contains(lower, "stealth"):
			return "warning"
		case strings.Contains(lower, "allow"):
			return "info"
		default:
			return "info"
		}

	case "gatekeeper":
		switch {
		case strings.Contains(lower, "blocked") || strings.Contains(lower, "rejected"):
			return "critical"
		case strings.Contains(lower, "quarantine") || strings.Contains(lower, "prompted"):
			return "warning"
		case strings.Contains(lower, "notarized") || strings.Contains(lower, "allowed"):
			return "info"
		default:
			return "info"
		}

	case "install":
		switch {
		case strings.Contains(lower, "failed") || strings.Contains(lower, "error"):
			return "critical"
		case strings.Contains(lower, "installing") || strings.Contains(lower, "packagekit"):
			return "warning"
		case strings.Contains(lower, "successfully installed") || strings.Contains(lower, "completed"):
			return "info"
		default:
			return "info"
		}

	default:
		return "info"
	}
}

// convertDuration converts a human-friendly duration string (1h, 24h, 7d) to the
// format expected by `log show --last` (e.g., "1h", "24h", "168h").
func convertDuration(duration string) (string, error) {
	if duration == "" {
		return "24h", nil
	}

	duration = strings.TrimSpace(duration)

	// Handle day suffix: convert to hours.
	if strings.HasSuffix(duration, "d") {
		numStr := strings.TrimSuffix(duration, "d")
		var days int
		if _, err := fmt.Sscanf(numStr, "%d", &days); err != nil {
			return "", fmt.Errorf("invalid day duration: %s", duration)
		}
		if days <= 0 {
			return "", fmt.Errorf("duration must be positive: %s", duration)
		}
		return fmt.Sprintf("%dh", days*24), nil
	}

	// Handle hours and minutes natively.
	if strings.HasSuffix(duration, "h") || strings.HasSuffix(duration, "m") {
		suffix := duration[len(duration)-1:]
		numStr := duration[:len(duration)-1]
		var val int
		if _, err := fmt.Sscanf(numStr, "%d", &val); err != nil {
			return "", fmt.Errorf("invalid duration: %s", duration)
		}
		if val <= 0 {
			return "", fmt.Errorf("duration must be positive: %s", duration)
		}
		return fmt.Sprintf("%d%s", val, suffix), nil
	}

	return "", fmt.Errorf("unsupported duration format: %s (use e.g., 1h, 24h, 7d)", duration)
}

// durationCutoff returns the time cutoff for filtering events by duration.
func durationCutoff(duration string) (time.Time, error) {
	if duration == "" {
		duration = "24h"
	}

	duration = strings.TrimSpace(duration)

	// Handle day suffix.
	if strings.HasSuffix(duration, "d") {
		numStr := strings.TrimSuffix(duration, "d")
		var days int
		if _, err := fmt.Sscanf(numStr, "%d", &days); err != nil {
			return time.Time{}, fmt.Errorf("invalid day duration: %s", duration)
		}
		return time.Now().Add(-time.Duration(days) * 24 * time.Hour), nil
	}

	// Handle hours.
	if strings.HasSuffix(duration, "h") {
		numStr := strings.TrimSuffix(duration, "h")
		var hours int
		if _, err := fmt.Sscanf(numStr, "%d", &hours); err != nil {
			return time.Time{}, fmt.Errorf("invalid hour duration: %s", duration)
		}
		return time.Now().Add(-time.Duration(hours) * time.Hour), nil
	}

	// Handle minutes.
	if strings.HasSuffix(duration, "m") {
		numStr := strings.TrimSuffix(duration, "m")
		var mins int
		if _, err := fmt.Sscanf(numStr, "%d", &mins); err != nil {
			return time.Time{}, fmt.Errorf("invalid minute duration: %s", duration)
		}
		return time.Now().Add(-time.Duration(mins) * time.Minute), nil
	}

	return time.Time{}, fmt.Errorf("unsupported duration format: %s", duration)
}

// normalizeTimestamp converts various log timestamp formats to a consistent format.
func normalizeTimestamp(raw string) string {
	layouts := []string{
		"2006-01-02 15:04:05.000000-0700",
		"2006-01-02 15:04:05-0700",
		"2006-01-02 15:04:05.000000+0000",
		"2006-01-02 15:04:05.000000",
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, strings.TrimSpace(raw))
		if err == nil {
			return t.Local().Format("2006-01-02 15:04:05")
		}
	}

	// If nothing matches, return as-is trimmed.
	return strings.TrimSpace(raw)
}

// truncateMessage truncates a message to maxLen characters.
func truncateMessage(msg string, maxLen int) string {
	if len(msg) <= maxLen {
		return msg
	}
	return msg[:maxLen-3] + "..."
}

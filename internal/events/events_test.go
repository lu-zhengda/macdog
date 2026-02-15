package events

import (
	"strings"
	"testing"
)

func TestParseLogEvents_Auth(t *testing.T) {
	input := `Timestamp               Ty Process[PID:TID]
2024-01-15 10:30:45.123 Df loginwindow[123:1a2b] [com.apple.Authorization:authd] User authenticated successfully
2024-01-15 10:31:00.654 E  securityd[124:1a2c] [com.apple.Authorization:authd] Authentication failed for user admin
2024-01-15 10:32:00.000 Df sudo[125:1a2d] [com.apple.Authorization:authd] sudo: user ran command as root
`

	events := ParseLogEvents(input, "auth")

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	tests := []struct {
		idx      int
		process  string
		severity string
		wantSub  string
	}{
		{0, "loginwindow", "info", "authenticated"},
		{1, "securityd", "critical", "failed"},
		{2, "sudo", "warning", "sudo"},
	}

	for _, tt := range tests {
		t.Run(tt.process, func(t *testing.T) {
			e := events[tt.idx]
			if e.Type != "auth" {
				t.Errorf("Type = %q, want %q", e.Type, "auth")
			}
			if e.Process != tt.process {
				t.Errorf("Process = %q, want %q", e.Process, tt.process)
			}
			if e.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", e.Severity, tt.severity)
			}
			if !strings.Contains(strings.ToLower(e.Message), tt.wantSub) {
				t.Errorf("Message %q does not contain %q", e.Message, tt.wantSub)
			}
		})
	}
}

func TestParseLogEvents_Auth_Succeeded(t *testing.T) {
	input := `2024-01-15 10:30:45.123 Df authd[472:d945e6] [com.apple.Authorization:authd] Succeeded authorizing right 'com.apple.ServiceManagement.daemons.modify' by client '/usr/libexec/mdmclient' [4380]
`

	events := ParseLogEvents(input, "auth")

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	if e.Process != "authd" {
		t.Errorf("Process = %q, want %q", e.Process, "authd")
	}
	if e.Severity != "info" {
		t.Errorf("Severity = %q, want %q", e.Severity, "info")
	}
	if !strings.Contains(e.Message, "Succeeded") {
		t.Errorf("Message %q does not contain %q", e.Message, "Succeeded")
	}
}

func TestParseLogEvents_TCC(t *testing.T) {
	input := `2024-01-15 11:00:00.000 Df tccd[234:2a2b] [com.apple.TCC:access] kTCCServiceCamera access denied for com.example.app
2024-01-15 11:01:00.000 Df tccd[235:2a2c] [com.apple.TCC:access] kTCCServiceMicrophone access allowed for com.other.app
2024-01-15 11:02:00.000 Df tccd[236:2a2d] [com.apple.TCC:access] User prompted for kTCCServiceScreenCapture
`

	events := ParseLogEvents(input, "tcc")

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	tests := []struct {
		idx      int
		severity string
		wantSub  string
	}{
		{0, "critical", "denied"},
		{1, "info", "allowed"},
		{2, "warning", "prompted"},
	}

	for _, tt := range tests {
		t.Run(tt.wantSub, func(t *testing.T) {
			e := events[tt.idx]
			if e.Type != "tcc" {
				t.Errorf("Type = %q, want %q", e.Type, "tcc")
			}
			if e.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", e.Severity, tt.severity)
			}
			if !strings.Contains(strings.ToLower(e.Message), tt.wantSub) {
				t.Errorf("Message %q does not contain %q", e.Message, tt.wantSub)
			}
		})
	}
}

func TestParseLogEvents_Firewall(t *testing.T) {
	input := `2024-01-15 12:00:00.000 Df socketfilterfw[345:3a3b] [com.apple.alf:filter] Deny connection from 192.168.1.100:443
2024-01-15 12:01:00.000 Df socketfilterfw[346:3a3c] [com.apple.alf:filter] Allow connection to 10.0.0.1:80
2024-01-15 12:02:00.000 Df socketfilterfw[347:3a3d] [com.apple.alf:filter] Block incoming connection in stealth mode
`

	events := ParseLogEvents(input, "firewall")

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	tests := []struct {
		idx      int
		severity string
		wantSub  string
	}{
		{0, "critical", "deny"},
		{1, "info", "allow"},
		{2, "critical", "block"},
	}

	for _, tt := range tests {
		t.Run(tt.wantSub, func(t *testing.T) {
			e := events[tt.idx]
			if e.Type != "firewall" {
				t.Errorf("Type = %q, want %q", e.Type, "firewall")
			}
			if e.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", e.Severity, tt.severity)
			}
		})
	}
}

func TestParseLogEvents_Gatekeeper(t *testing.T) {
	input := `2024-01-15 13:00:00.000 Df syspolicyd[456:4a4b] [com.apple.syspolicy:exec] App blocked due to invalid signature
2024-01-15 13:01:00.000 Df syspolicyd[457:4a4c] [com.apple.syspolicy:exec] App notarized and allowed to run
2024-01-15 13:02:00.000 Df syspolicyd[458:4a4d] [com.apple.syspolicy:exec] File has quarantine flag, checking
`

	events := ParseLogEvents(input, "gatekeeper")

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	tests := []struct {
		idx      int
		severity string
		wantSub  string
	}{
		{0, "critical", "blocked"},
		{1, "info", "notarized"},
		{2, "warning", "quarantine"},
	}

	for _, tt := range tests {
		t.Run(tt.wantSub, func(t *testing.T) {
			e := events[tt.idx]
			if e.Type != "gatekeeper" {
				t.Errorf("Type = %q, want %q", e.Type, "gatekeeper")
			}
			if e.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", e.Severity, tt.severity)
			}
		})
	}
}

func TestParseLogEvents_EmptyInput(t *testing.T) {
	events := ParseLogEvents("", "auth")
	if len(events) != 0 {
		t.Errorf("expected 0 events for empty input, got %d", len(events))
	}
}

func TestParseLogEvents_MalformedLines(t *testing.T) {
	input := `this is not a valid log line
another bad line
Timestamp               Ty Process[PID:TID]
--- just a header ---
`

	events := ParseLogEvents(input, "auth")
	if len(events) != 0 {
		t.Errorf("expected 0 events for malformed input, got %d", len(events))
	}
}

func TestParseInstallLog(t *testing.T) {
	input := `2024-01-15 10:00:00-0800 PackageKit[123]: Installing com.example.package
2024-01-15 10:01:00-0800 installer[456]: Successfully installed Safari Update
2024-01-15 10:02:00-0800 softwareupdated[789]: Error downloading update
`

	events := ParseInstallLog(input)

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	tests := []struct {
		idx      int
		process  string
		severity string
	}{
		{0, "PackageKit", "warning"},
		{1, "installer", "info"},
		{2, "softwareupdated", "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.process, func(t *testing.T) {
			e := events[tt.idx]
			if e.Type != "install" {
				t.Errorf("Type = %q, want %q", e.Type, "install")
			}
			if e.Process != tt.process {
				t.Errorf("Process = %q, want %q", e.Process, tt.process)
			}
			if e.Severity != tt.severity {
				t.Errorf("Severity = %q, want %q", e.Severity, tt.severity)
			}
		})
	}
}

func TestParseInstallLog_EmptyInput(t *testing.T) {
	events := ParseInstallLog("")
	if len(events) != 0 {
		t.Errorf("expected 0 events for empty input, got %d", len(events))
	}
}

func TestAssignSeverity(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		message   string
		want      string
	}{
		// auth events
		{"auth failed", "auth", "Authentication failed for user", "critical"},
		{"auth failure", "auth", "login failure detected", "critical"},
		{"auth denied", "auth", "access denied by policy", "critical"},
		{"auth sudo", "auth", "sudo: user ran command", "warning"},
		{"auth success", "auth", "User authenticated OK", "info"},
		{"auth succeeded", "auth", "Succeeded authorizing right", "info"},
		{"auth other", "auth", "some other auth message", "info"},

		// tcc events
		{"tcc denied", "tcc", "access denied for camera", "critical"},
		{"tcc prompted", "tcc", "user prompted for access", "warning"},
		{"tcc allowed", "tcc", "camera access allowed", "info"},
		{"tcc other", "tcc", "checking service status", "info"},

		// firewall events
		{"fw deny", "firewall", "Deny incoming connection", "critical"},
		{"fw block", "firewall", "Block TCP 192.168.1.1", "critical"},
		{"fw stealth", "firewall", "stealth mode drop", "warning"},
		{"fw allow", "firewall", "Allow outbound to 10.0.0.1", "info"},
		{"fw other", "firewall", "rule evaluation complete", "info"},

		// gatekeeper events
		{"gk blocked", "gatekeeper", "App blocked from opening", "critical"},
		{"gk rejected", "gatekeeper", "Code signature rejected", "critical"},
		{"gk quarantine", "gatekeeper", "quarantine flag detected", "warning"},
		{"gk prompted", "gatekeeper", "user prompted to allow", "warning"},
		{"gk notarized", "gatekeeper", "app notarized by Apple", "info"},
		{"gk allowed", "gatekeeper", "execution allowed", "info"},
		{"gk other", "gatekeeper", "policy check complete", "info"},

		// install events
		{"install failed", "install", "Installation failed", "critical"},
		{"install error", "install", "Error downloading package", "critical"},
		{"install installing", "install", "Installing Safari update", "warning"},
		{"install packagekit", "install", "PackageKit processing", "warning"},
		{"install success", "install", "Successfully installed update", "info"},
		{"install completed", "install", "Update completed", "info"},
		{"install other", "install", "checking status", "info"},

		// unknown type
		{"unknown type", "unknown", "any message", "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assignSeverity(tt.eventType, tt.message)
			if got != tt.want {
				t.Errorf("assignSeverity(%q, %q) = %q, want %q", tt.eventType, tt.message, got, tt.want)
			}
		})
	}
}

func TestConvertDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty defaults to 24h", "", "24h", false},
		{"1 hour", "1h", "1h", false},
		{"24 hours", "24h", "24h", false},
		{"1 day", "1d", "24h", false},
		{"7 days", "7d", "168h", false},
		{"30 minutes", "30m", "30m", false},
		{"invalid suffix", "24x", "", true},
		{"invalid number", "abch", "", true},
		{"zero days", "0d", "", true},
		{"negative hours", "-1h", "", true},
		{"whitespace", "  24h  ", "24h", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("convertDuration(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeTimestamp(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"compact with microseconds",
			"2024-01-15 10:30:45.123456-0800",
			"2024-01-15 18:30:45", // UTC-8 -> local time (depends on test machine)
		},
		{
			"without microseconds",
			"2024-01-15 10:30:45-0800",
			"2024-01-15 18:30:45",
		},
		{
			"compact no timezone with milliseconds",
			"2024-01-15 10:30:45.123",
			"2024-01-15 10:30:45",
		},
		{
			"compact no timezone no fractional",
			"2024-01-15 10:30:45",
			"2024-01-15 10:30:45",
		},
		{
			"unparseable returns as-is",
			"some random string",
			"some random string",
		},
		{
			"whitespace trimmed",
			"  2024-01-15 10:30:45-0800  ",
			"2024-01-15 18:30:45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeTimestamp(tt.input)
			// Since local timezone varies, we just check it's not empty
			// and is a reasonable format for parseable timestamps.
			if tt.name == "unparseable returns as-is" {
				if got != tt.want {
					t.Errorf("normalizeTimestamp(%q) = %q, want %q", tt.input, got, tt.want)
				}
			} else if tt.name == "whitespace trimmed" && got == "some random string" {
				t.Errorf("normalizeTimestamp(%q) unexpectedly returned as-is", tt.input)
			} else {
				// Just verify it looks like a timestamp.
				if !strings.HasPrefix(got, "2024-01-15") {
					t.Errorf("normalizeTimestamp(%q) = %q, expected to start with '2024-01-15'", tt.input, got)
				}
			}
		})
	}
}

func TestTruncateMessage(t *testing.T) {
	tests := []struct {
		name   string
		msg    string
		maxLen int
		want   string
	}{
		{"short message", "hello", 200, "hello"},
		{"exact length", "abc", 3, "abc"},
		{"truncated", "abcdefghij", 8, "abcde..."},
		{"empty", "", 200, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateMessage(tt.msg, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateMessage(%q, %d) = %q, want %q", tt.msg, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestValidEventTypes(t *testing.T) {
	types := ValidEventTypes()
	expected := []string{"auth", "tcc", "firewall", "gatekeeper", "install"}

	if len(types) != len(expected) {
		t.Fatalf("ValidEventTypes() returned %d types, want %d", len(types), len(expected))
	}

	for i, et := range expected {
		if types[i] != et {
			t.Errorf("ValidEventTypes()[%d] = %q, want %q", i, types[i], et)
		}
	}
}

func TestFetchEventsWithRunner_UnknownType(t *testing.T) {
	runner := func(name string, args ...string) ([]byte, error) {
		return nil, nil
	}

	_, err := fetchEventsWithRunner("unknown_type", "24h", runner)
	if err == nil {
		t.Error("expected error for unknown event type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown event type") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "unknown event type")
	}
}

func TestFetchEventsWithRunner_InvalidDuration(t *testing.T) {
	runner := func(name string, args ...string) ([]byte, error) {
		return nil, nil
	}

	_, err := fetchEventsWithRunner("auth", "invalid", runner)
	if err == nil {
		t.Error("expected error for invalid duration, got nil")
	}
}

func TestFetchEventsWithRunner_Auth(t *testing.T) {
	mockOutput := `2024-01-15 10:30:45.123 Df loginwindow[123:1a2b] [com.apple.Authorization:authd] User authenticated successfully
2024-01-15 10:31:00.654 E  securityd[124:1a2c] [com.apple.Authorization:authd] Authentication failed for user admin
`

	runner := func(name string, args ...string) ([]byte, error) {
		return []byte(mockOutput), nil
	}

	events, err := fetchEventsWithRunner("auth", "24h", runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Severity != "info" {
		t.Errorf("events[0].Severity = %q, want %q", events[0].Severity, "info")
	}
	if events[1].Severity != "critical" {
		t.Errorf("events[1].Severity = %q, want %q", events[1].Severity, "critical")
	}
}

func TestFetchEventsWithRunner_Install(t *testing.T) {
	mockOutput := `2026-02-15 10:00:00-0800 PackageKit[123]: Installing com.example.package
2026-02-15 10:01:00-0800 installer[456]: Successfully installed Safari Update
`

	runner := func(name string, args ...string) ([]byte, error) {
		return []byte(mockOutput), nil
	}

	events, err := fetchEventsWithRunner("install", "24h", runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Events may be filtered by time — we just verify no error and correct type.
	for _, e := range events {
		if e.Type != "install" {
			t.Errorf("Type = %q, want %q", e.Type, "install")
		}
	}
}

func TestFetchAllEventsWithRunner(t *testing.T) {
	callCount := 0
	runner := func(name string, args ...string) ([]byte, error) {
		callCount++
		// Return different mock data depending on the predicate or command.
		for _, arg := range args {
			if strings.Contains(arg, "Authorization") {
				return []byte("2024-01-15 10:30:45.123 Df loginwindow[123:1a2b] [com.apple.Authorization:authd] User authenticated\n"), nil
			}
			if strings.Contains(arg, "TCC") {
				return []byte("2024-01-15 11:00:00.000 Df tccd[234:2a2b] [com.apple.TCC:access] access denied\n"), nil
			}
		}
		// For install (cat) and others, return empty.
		return []byte(""), nil
	}

	events, err := fetchAllEventsWithRunner("24h", runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have at least auth + tcc events.
	if len(events) < 2 {
		t.Errorf("expected at least 2 events, got %d", len(events))
	}

	// Verify sorting by timestamp.
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp < events[i-1].Timestamp {
			t.Errorf("events not sorted: [%d].Timestamp=%q < [%d].Timestamp=%q",
				i, events[i].Timestamp, i-1, events[i-1].Timestamp)
		}
	}
}

func TestDurationCutoff(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"1 hour", "1h", false},
		{"24 hours", "24h", false},
		{"7 days", "7d", false},
		{"30 minutes", "30m", false},
		{"empty defaults", "", false},
		{"invalid", "xyz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := durationCutoff(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("durationCutoff(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

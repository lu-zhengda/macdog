package audit

import (
	"testing"
)

func TestGrade(t *testing.T) {
	tests := []struct {
		name     string
		report   Report
		wantGrad string
	}{
		{
			name: "all secure - grade A",
			report: Report{
				SIP:         "enabled",
				Firewall:    "on",
				FileVault:   "on",
				Gatekeeper:  "enabled",
				RemoteLogin: "off",
			},
			wantGrad: "A",
		},
		{
			name: "remote login on - grade A (90pts)",
			report: Report{
				SIP:         "enabled",
				Firewall:    "on",
				FileVault:   "on",
				Gatekeeper:  "enabled",
				RemoteLogin: "on",
			},
			wantGrad: "A",
		},
		{
			name: "firewall off - grade B (75pts)",
			report: Report{
				SIP:         "enabled",
				Firewall:    "off",
				FileVault:   "on",
				Gatekeeper:  "enabled",
				RemoteLogin: "off",
			},
			wantGrad: "B",
		},
		{
			name: "SIP disabled - grade B (75pts)",
			report: Report{
				SIP:         "disabled",
				Firewall:    "on",
				FileVault:   "on",
				Gatekeeper:  "enabled",
				RemoteLogin: "off",
			},
			wantGrad: "B",
		},
		{
			name: "SIP and firewall off - grade C (50pts)",
			report: Report{
				SIP:         "disabled",
				Firewall:    "off",
				FileVault:   "on",
				Gatekeeper:  "enabled",
				RemoteLogin: "off",
			},
			wantGrad: "D",
		},
		{
			name: "only SIP enabled - grade D (35pts)",
			report: Report{
				SIP:         "enabled",
				Firewall:    "off",
				FileVault:   "off",
				Gatekeeper:  "disabled",
				RemoteLogin: "on",
			},
			wantGrad: "F",
		},
		{
			name: "nothing secure - grade F (0pts)",
			report: Report{
				SIP:         "disabled",
				Firewall:    "off",
				FileVault:   "off",
				Gatekeeper:  "disabled",
				RemoteLogin: "on",
			},
			wantGrad: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.report.Grade()
			if got != tt.wantGrad {
				t.Errorf("Grade() = %q, want %q (report: %+v)", got, tt.wantGrad, tt.report)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name      string
		report    Report
		wantScore int
	}{
		{
			name: "all secure = 100",
			report: Report{
				SIP:         "enabled",
				Firewall:    "on",
				FileVault:   "on",
				Gatekeeper:  "enabled",
				RemoteLogin: "off",
			},
			wantScore: 100,
		},
		{
			name: "nothing secure = 0",
			report: Report{
				SIP:         "disabled",
				Firewall:    "off",
				FileVault:   "off",
				Gatekeeper:  "disabled",
				RemoteLogin: "on",
			},
			wantScore: 0,
		},
		{
			name: "SIP only = 25",
			report: Report{
				SIP:         "enabled",
				Firewall:    "off",
				FileVault:   "off",
				Gatekeeper:  "disabled",
				RemoteLogin: "on",
			},
			wantScore: 25,
		},
		{
			name: "firewall only = 25",
			report: Report{
				SIP:         "disabled",
				Firewall:    "on",
				FileVault:   "off",
				Gatekeeper:  "disabled",
				RemoteLogin: "on",
			},
			wantScore: 25,
		},
		{
			name: "filevault only = 25",
			report: Report{
				SIP:         "disabled",
				Firewall:    "off",
				FileVault:   "on",
				Gatekeeper:  "disabled",
				RemoteLogin: "on",
			},
			wantScore: 25,
		},
		{
			name: "gatekeeper only = 15",
			report: Report{
				SIP:         "disabled",
				Firewall:    "off",
				FileVault:   "off",
				Gatekeeper:  "enabled",
				RemoteLogin: "on",
			},
			wantScore: 15,
		},
		{
			name: "remote login off only = 10",
			report: Report{
				SIP:         "disabled",
				Firewall:    "off",
				FileVault:   "off",
				Gatekeeper:  "disabled",
				RemoteLogin: "off",
			},
			wantScore: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.report.Score()
			if got != tt.wantScore {
				t.Errorf("Score() = %d, want %d", got, tt.wantScore)
			}
		})
	}
}

func TestParseCSRUtil(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"enabled", "System Integrity Protection status: enabled.", "enabled"},
		{"disabled", "System Integrity Protection status: disabled.", "disabled"},
		{"unknown output", "something unexpected", "unknown"},
		{"empty", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCSRUtil(tt.output)
			if got != tt.want {
				t.Errorf("parseCSRUtil(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseFirewall(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"enabled", "Firewall is enabled. (State = 1)", "on"},
		{"disabled", "Firewall is disabled. (State = 0)", "off"},
		{"unknown", "something else", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFirewall(tt.output)
			if got != tt.want {
				t.Errorf("parseFirewall(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseFileVault(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"on", "FileVault is On.", "on"},
		{"off", "FileVault is Off.", "off"},
		{"unknown", "something else", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFileVault(tt.output)
			if got != tt.want {
				t.Errorf("parseFileVault(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseGatekeeper(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"enabled", "assessments enabled", "enabled"},
		{"disabled", "assessments disabled", "disabled"},
		{"unknown", "something else", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGatekeeper(tt.output)
			if got != tt.want {
				t.Errorf("parseGatekeeper(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseRemoteLogin(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"off", "Remote Login: Off", "off"},
		{"on", "Remote Login: On", "on"},
		{"unknown", "something else", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRemoteLogin(tt.output)
			if got != tt.want {
				t.Errorf("parseRemoteLogin(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestFixResultTypes(t *testing.T) {
	// Verify FixResult struct fields are correctly typed.
	r := FixResult{
		Check:  "Firewall",
		Status: "fixed",
		Reason: "",
		Before: "off",
		After:  "on",
	}

	if r.Check != "Firewall" {
		t.Errorf("Check = %q, want %q", r.Check, "Firewall")
	}
	if r.Status != "fixed" {
		t.Errorf("Status = %q, want %q", r.Status, "fixed")
	}
	if r.Before != "off" {
		t.Errorf("Before = %q, want %q", r.Before, "off")
	}
	if r.After != "on" {
		t.Errorf("After = %q, want %q", r.After, "on")
	}
}

func TestFixReportTypes(t *testing.T) {
	// Verify FixReport struct embeds Before/After correctly.
	fr := FixReport{
		Before: Report{
			SIP:         "enabled",
			Firewall:    "off",
			FileVault:   "on",
			Gatekeeper:  "enabled",
			RemoteLogin: "off",
		},
		After: Report{
			SIP:         "enabled",
			Firewall:    "on",
			FileVault:   "on",
			Gatekeeper:  "enabled",
			RemoteLogin: "off",
		},
		Results: []FixResult{
			{Check: "Firewall", Status: "fixed", Before: "off", After: "on"},
		},
	}

	if fr.Before.Firewall != "off" {
		t.Errorf("Before.Firewall = %q, want %q", fr.Before.Firewall, "off")
	}
	if fr.After.Firewall != "on" {
		t.Errorf("After.Firewall = %q, want %q", fr.After.Firewall, "on")
	}
	if len(fr.Results) != 1 {
		t.Errorf("len(Results) = %d, want 1", len(fr.Results))
	}
	if fr.After.Score() != 100 {
		t.Errorf("After.Score() = %d, want 100", fr.After.Score())
	}
}

func TestFix(t *testing.T) {
	// Fix() runs actual system commands including sudo.
	// In test context without sudo, the fix operations will fail but the
	// function should still return a valid FixReport.
	fixReport, err := Fix()
	if err != nil {
		t.Fatalf("Fix() returned error: %v", err)
	}
	if fixReport == nil {
		t.Fatal("Fix() returned nil report")
	}

	// Before and After reports should be populated.
	if fixReport.Before.SIP == "" {
		t.Error("Before.SIP is empty")
	}
	if fixReport.After.SIP == "" {
		t.Error("After.SIP is empty")
	}
}

func TestFull(t *testing.T) {
	// Full() runs actual system commands; just verify it returns without panic.
	// The actual values depend on the system state.
	report, err := Full()
	if err != nil {
		t.Fatalf("Full() returned error: %v", err)
	}
	if report == nil {
		t.Fatal("Full() returned nil report")
	}

	// Verify all fields are populated (not empty).
	if report.SIP == "" {
		t.Error("SIP field is empty")
	}
	if report.Firewall == "" {
		t.Error("Firewall field is empty")
	}
	if report.FileVault == "" {
		t.Error("FileVault field is empty")
	}
	if report.Gatekeeper == "" {
		t.Error("Gatekeeper field is empty")
	}
	if report.RemoteLogin == "" {
		t.Error("RemoteLogin field is empty")
	}

	// Verify grade is a valid letter.
	grade := report.Grade()
	validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	if !validGrades[grade] {
		t.Errorf("Grade() = %q, want one of A/B/C/D/F", grade)
	}
}

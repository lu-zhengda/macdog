package status

import (
	"testing"
)

func TestComputeOverall(t *testing.T) {
	tests := []struct {
		name  string
		score int
		want  string
	}{
		{"perfect score", 100, OverallOK},
		{"grade A boundary", 90, OverallOK},
		{"grade B high", 89, OverallWarning},
		{"grade B boundary", 75, OverallWarning},
		{"grade C high", 74, OverallWarning},
		{"grade C boundary", 60, OverallWarning},
		{"grade D high", 59, OverallCritical},
		{"grade D boundary", 40, OverallCritical},
		{"grade F", 0, OverallCritical},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Score: tc.score}
			got := computeOverall(r)
			if got != tc.want {
				t.Errorf("score %d: got %q, want %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestReportFields(t *testing.T) {
	r := &Report{
		Overall: OverallWarning,
		Score:   75,
		Grade:   "B",
		Audit: AuditInfo{
			SIP:         "enabled",
			Firewall:    "off",
			FileVault:   "on",
			Gatekeeper:  "enabled",
			RemoteLogin: "off",
			Score:       75,
			Grade:       "B",
		},
		Firewall: FirewallInfo{
			Enabled:     false,
			StealthMode: false,
			BlockAll:    false,
			RuleCount:   3,
		},
		LoginItems: LoginInfo{Count: 5},
		Privacy:    PrivacyInfo{Granted: 12, Denied: 2, Total: 14},
	}

	if r.Overall != OverallWarning {
		t.Errorf("Overall: got %q, want %q", r.Overall, OverallWarning)
	}
	if r.Score != 75 {
		t.Errorf("Score: got %d, want 75", r.Score)
	}
	if r.Audit.SIP != "enabled" {
		t.Errorf("Audit.SIP: got %q, want %q", r.Audit.SIP, "enabled")
	}
	if r.Firewall.RuleCount != 3 {
		t.Errorf("Firewall.RuleCount: got %d, want 3", r.Firewall.RuleCount)
	}
	if r.LoginItems.Count != 5 {
		t.Errorf("LoginItems.Count: got %d, want 5", r.LoginItems.Count)
	}
	if r.Privacy.Total != 14 {
		t.Errorf("Privacy.Total: got %d, want 14", r.Privacy.Total)
	}
}

func TestPrivacyErrorField(t *testing.T) {
	r := &Report{
		Privacy: PrivacyInfo{Error: "cannot read TCC database (Full Disk Access required)"},
	}
	if r.Privacy.Error == "" {
		t.Error("expected Privacy.Error to be non-empty")
	}
	if r.Privacy.Total != 0 {
		t.Errorf("expected Privacy.Total 0 on error, got %d", r.Privacy.Total)
	}
}

func TestConstants(t *testing.T) {
	if OverallOK != "ok" {
		t.Errorf("OverallOK = %q, want %q", OverallOK, "ok")
	}
	if OverallWarning != "warning" {
		t.Errorf("OverallWarning = %q, want %q", OverallWarning, "warning")
	}
	if OverallCritical != "critical" {
		t.Errorf("OverallCritical = %q, want %q", OverallCritical, "critical")
	}
}

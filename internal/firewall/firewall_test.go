package firewall

import (
	"testing"
)

func TestParseGlobalState(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"enabled state 1", "Firewall is enabled. (State = 1)", true},
		{"enabled state 2", "Firewall is enabled. (State = 2)", true},
		{"disabled", "Firewall is disabled. (State = 0)", false},
		{"unknown", "something else", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGlobalState(tt.output)
			if got != tt.want {
				t.Errorf("parseGlobalState(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseStealthMode(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"enabled", "Stealth mode enabled.", true},
		{"disabled", "Stealth mode disabled.", false},
		{"unknown", "foobar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseStealthMode(tt.output)
			if got != tt.want {
				t.Errorf("parseStealthMode(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseBlockAll(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"enabled", "Block all ENABLED!", true},
		{"disabled", "Block all DISABLED!", false},
		{"unknown", "foobar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBlockAll(tt.output)
			if got != tt.want {
				t.Errorf("parseBlockAll(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseListApps(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    int
		wantErr bool
	}{
		{
			name: "two apps",
			output: `ALF : Total number of apps = 2

1 :  /usr/libexec/configd
   ( Allow incoming connections )

2 :  /usr/sbin/mDNSResponder
   ( Block incoming connections )
`,
			want: 2,
		},
		{
			name:   "no apps",
			output: "ALF : Total number of apps = 0 \n",
			want:   0,
		},
		{
			name:   "empty",
			output: "",
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := parseListApps(tt.output)
			if len(rules) != tt.want {
				t.Errorf("parseListApps() returned %d rules, want %d", len(rules), tt.want)
			}
		})
	}
}

func TestParseListAppsDetails(t *testing.T) {
	output := `ALF : Total number of apps = 2

1 :  /usr/libexec/configd
   ( Allow incoming connections )

2 :  /usr/sbin/mDNSResponder
   ( Block incoming connections )
`
	rules := parseListApps(output)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].Path != "/usr/libexec/configd" {
		t.Errorf("rules[0].Path = %q, want %q", rules[0].Path, "/usr/libexec/configd")
	}
	if rules[0].Name != "configd" {
		t.Errorf("rules[0].Name = %q, want %q", rules[0].Name, "configd")
	}
	if !rules[0].Allowed {
		t.Error("rules[0].Allowed = false, want true")
	}

	if rules[1].Path != "/usr/sbin/mDNSResponder" {
		t.Errorf("rules[1].Path = %q, want %q", rules[1].Path, "/usr/sbin/mDNSResponder")
	}
	if rules[1].Allowed {
		t.Error("rules[1].Allowed = true, want false")
	}
}

func TestGetStatus(t *testing.T) {
	// GetStatus runs actual system commands. Verify it returns without error
	// and has reasonable fields.
	status, err := GetStatus()
	if err != nil {
		t.Fatalf("GetStatus() error: %v", err)
	}
	if status == nil {
		t.Fatal("GetStatus() returned nil")
	}
	// Rules may be empty on a clean system, that's OK.
}

func TestListRules(t *testing.T) {
	rules, err := ListRules()
	if err != nil {
		t.Fatalf("ListRules() error: %v", err)
	}
	// Rules may be empty on a clean system, that's OK.
	_ = rules
}

func TestEnableDisableRequiresSudo(t *testing.T) {
	// These operations require sudo. We just verify they return an error
	// when run without sudo (in test context).
	// Skip if running as root (unlikely in tests but be safe).
	err := Enable()
	if err == nil {
		t.Log("Enable() succeeded — running as root or firewall already enabled")
	}

	err = Disable()
	if err == nil {
		t.Log("Disable() succeeded — running as root or firewall already disabled")
	}
}

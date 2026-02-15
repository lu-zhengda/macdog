package harden

import (
	"testing"
)

func TestPlan(t *testing.T) {
	actions, err := Plan()
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	if len(actions) == 0 {
		t.Fatal("Plan() returned no actions")
	}

	// Verify we have the expected action names.
	expectedNames := map[string]bool{
		"Enable Firewall":                   false,
		"Enable Stealth Mode":               false,
		"Disable Remote Login":              false,
		"Disable Remote Apple Events":       false,
		"Require Password After Sleep (5s)": false,
	}

	for _, a := range actions {
		if _, ok := expectedNames[a.Name]; ok {
			expectedNames[a.Name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected action %q not found in Plan()", name)
		}
	}
}

func TestPlanActionFields(t *testing.T) {
	actions, err := Plan()
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	for _, a := range actions {
		if a.Name == "" {
			t.Error("action has empty Name")
		}
		if a.Description == "" {
			t.Errorf("action %q has empty Description", a.Name)
		}
		if a.DesiredState == "" {
			t.Errorf("action %q has empty DesiredState", a.Name)
		}
		if a.Apply == nil {
			t.Errorf("action %q has nil Apply func", a.Name)
		}
	}
}

func TestPlanCurrentStates(t *testing.T) {
	actions, err := Plan()
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	for _, a := range actions {
		// CurrentState should be set (not empty) since we probe the system.
		if a.CurrentState == "" {
			t.Errorf("action %q has empty CurrentState", a.Name)
		}
	}
}

func TestApplyDryRun(t *testing.T) {
	// Test that Apply with an empty action list returns no error.
	err := Apply(nil)
	if err != nil {
		t.Errorf("Apply(nil) error: %v", err)
	}

	err = Apply([]Action{})
	if err != nil {
		t.Errorf("Apply(empty) error: %v", err)
	}
}

func TestParseRemoteAppleEvents(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"off", "Remote Apple Events: Off", "off"},
		{"on", "Remote Apple Events: On", "on"},
		{"unknown", "something else", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRemoteAppleEvents(tt.output)
			if got != tt.want {
				t.Errorf("parseRemoteAppleEvents(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestParseScreenSaverPassword(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"required immediately", "askForPassword = 1;\naskForPasswordDelay = 0;", "on (0s)"},
		{"required 5s", "askForPassword = 1;\naskForPasswordDelay = 5;", "on (5s)"},
		{"not required", "askForPassword = 0;", "off"},
		{"unknown", "something else", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseScreenSaverPassword(tt.output)
			if got != tt.want {
				t.Errorf("parseScreenSaverPassword(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

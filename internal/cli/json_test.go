package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lu-zhengda/macdog/internal/harden"
)

func TestJSONAction_RoundTrip(t *testing.T) {
	actions := []struct {
		action string
		target string
	}{
		{"enable", "firewall"},
		{"disable", "firewall"},
		{"allow", "/Applications/Safari.app"},
		{"block", "/Applications/Suspicious.app"},
		{"import", "/tmp/firewall-rules.json"},
		{"remove", "com.example.agent"},
		{"revoke", "Camera/com.example.app"},
	}

	for _, tc := range actions {
		t.Run(tc.action, func(t *testing.T) {
			input := jsonAction{OK: true, Action: tc.action, Target: tc.target}

			var buf bytes.Buffer
			if err := fprintJSON(&buf, input); err != nil {
				t.Fatalf("fprintJSON() error = %v", err)
			}

			var got jsonAction
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}
			if !got.OK {
				t.Error("got ok=false, want true")
			}
			if got.Action != tc.action {
				t.Errorf("got action %q, want %q", got.Action, tc.action)
			}
			if got.Target != tc.target {
				t.Errorf("got target %q, want %q", got.Target, tc.target)
			}
		})
	}
}

func TestJSONHardenResult_DryRun(t *testing.T) {
	input := jsonHardenResult{
		DryRun: true,
		Actions: []harden.Action{
			{
				Name:         "Enable Firewall",
				Description:  "Turn on the firewall",
				CurrentState: "off",
				DesiredState: "on",
			},
			{
				Name:         "Enable Stealth Mode",
				Description:  "Turn on stealth mode",
				CurrentState: "on",
				DesiredState: "on",
			},
		},
		Applied: 0,
	}

	var buf bytes.Buffer
	if err := fprintJSON(&buf, input); err != nil {
		t.Fatalf("fprintJSON() error = %v", err)
	}

	var got jsonHardenResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if !got.DryRun {
		t.Error("got dry_run=false, want true")
	}
	if len(got.Actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(got.Actions))
	}
	if got.Actions[0].Name != "Enable Firewall" {
		t.Errorf("got action name %q, want %q", got.Actions[0].Name, "Enable Firewall")
	}
	if got.Applied != 0 {
		t.Errorf("got applied %d, want 0", got.Applied)
	}
}

func TestJSONHardenResult_WithResults(t *testing.T) {
	input := jsonHardenResult{
		DryRun: false,
		Actions: []harden.Action{
			{
				Name:         "Enable Firewall",
				Description:  "Turn on the firewall",
				CurrentState: "off",
				DesiredState: "on",
			},
		},
		Applied: 1,
		Results: []jsonHardenApplied{
			{Name: "Enable Firewall", Status: "applied"},
		},
	}

	var buf bytes.Buffer
	if err := fprintJSON(&buf, input); err != nil {
		t.Fatalf("fprintJSON() error = %v", err)
	}

	var got jsonHardenResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if got.DryRun {
		t.Error("got dry_run=true, want false")
	}
	if got.Applied != 1 {
		t.Errorf("got applied %d, want 1", got.Applied)
	}
	if len(got.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(got.Results))
	}
	if got.Results[0].Status != "applied" {
		t.Errorf("got status %q, want %q", got.Results[0].Status, "applied")
	}
}

func TestJSONHardenApplied_WithError(t *testing.T) {
	input := jsonHardenApplied{
		Name:   "Enable Firewall",
		Status: "failed",
		Error:  "permission denied",
	}

	var buf bytes.Buffer
	if err := fprintJSON(&buf, input); err != nil {
		t.Fatalf("fprintJSON() error = %v", err)
	}

	var got jsonHardenApplied
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if got.Status != "failed" {
		t.Errorf("got status %q, want %q", got.Status, "failed")
	}
	if got.Error != "permission denied" {
		t.Errorf("got error %q, want %q", got.Error, "permission denied")
	}
}

func TestJSONHardenApplied_OmitsEmptyError(t *testing.T) {
	input := jsonHardenApplied{
		Name:   "Enable Firewall",
		Status: "applied",
	}

	var buf bytes.Buffer
	if err := fprintJSON(&buf, input); err != nil {
		t.Fatalf("fprintJSON() error = %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if _, ok := raw["error"]; ok {
		t.Errorf("error field should be omitted when empty, got %s", string(raw["error"]))
	}
}

func TestJSONHardenResult_OmitsEmptyResults(t *testing.T) {
	input := jsonHardenResult{
		DryRun:  true,
		Actions: []harden.Action{},
		Applied: 0,
	}

	var buf bytes.Buffer
	if err := fprintJSON(&buf, input); err != nil {
		t.Fatalf("fprintJSON() error = %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if _, ok := raw["results"]; ok {
		t.Errorf("results field should be omitted when empty, got %s", string(raw["results"]))
	}
}

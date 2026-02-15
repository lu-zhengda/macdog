package login

import (
	"testing"
)

func TestParseOsascriptOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
	}{
		{
			name:   "two items",
			output: "iTerm2, Docker",
			want:   2,
		},
		{
			name:   "single item",
			output: "iTerm2",
			want:   1,
		},
		{
			name:   "empty",
			output: "",
			want:   0,
		},
		{
			name:   "whitespace only",
			output: "  \n  ",
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := parseOsascriptLoginItems(tt.output)
			if len(items) != tt.want {
				t.Errorf("parseOsascriptLoginItems(%q) returned %d items, want %d", tt.output, len(items), tt.want)
			}
		})
	}
}

func TestParseOsascriptDetails(t *testing.T) {
	output := "iTerm2, Docker"
	items := parseOsascriptLoginItems(output)
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Name != "iTerm2" {
		t.Errorf("items[0].Name = %q, want %q", items[0].Name, "iTerm2")
	}
	if items[0].Kind != "LoginItem" {
		t.Errorf("items[0].Kind = %q, want %q", items[0].Kind, "LoginItem")
	}
	if items[1].Name != "Docker" {
		t.Errorf("items[1].Name = %q, want %q", items[1].Name, "Docker")
	}
}

func TestParseLaunchAgents(t *testing.T) {
	// Create some test plist file names.
	names := []string{
		"com.example.agent.plist",
		"com.google.keystone.agent.plist",
	}

	items := parseLaunchAgentNames(names, "/Users/test/Library/LaunchAgents")
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	if items[0].Name != "com.example.agent" {
		t.Errorf("items[0].Name = %q, want %q", items[0].Name, "com.example.agent")
	}
	if items[0].Kind != "LaunchAgent" {
		t.Errorf("items[0].Kind = %q, want %q", items[0].Kind, "LaunchAgent")
	}
	if items[0].Path != "/Users/test/Library/LaunchAgents/com.example.agent.plist" {
		t.Errorf("items[0].Path = %q", items[0].Path)
	}
}

func TestParseLaunchAgentsFiltering(t *testing.T) {
	// Non-plist files should be ignored.
	names := []string{
		"com.example.agent.plist",
		".DS_Store",
		"README.txt",
	}

	items := parseLaunchAgentNames(names, "/tmp")
	if len(items) != 1 {
		t.Errorf("expected 1 item, got %d", len(items))
	}
}

func TestListItems(t *testing.T) {
	// ListItems runs actual system commands.
	items, err := ListItems()
	if err != nil {
		t.Fatalf("ListItems() error: %v", err)
	}
	// We should have at least some launch agents on any macOS system.
	if len(items) == 0 {
		t.Log("ListItems() returned empty — may be expected in sandboxed environment")
	}
}

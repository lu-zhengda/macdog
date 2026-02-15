package login

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LoginItem represents a startup/login item.
type LoginItem struct {
	Name string
	Path string
	Kind string // "LaunchAgent", "LoginItem", "App"
}

// ListItems returns all login items from multiple sources:
// - osascript login items
// - ~/Library/LaunchAgents/*.plist
// - /Library/LaunchAgents/*.plist
func ListItems() ([]LoginItem, error) {
	var items []LoginItem

	// 1. osascript login items.
	osItems := getOsascriptLoginItems()
	items = append(items, osItems...)

	// 2. User launch agents.
	home, err := os.UserHomeDir()
	if err == nil {
		userAgentDir := filepath.Join(home, "Library", "LaunchAgents")
		userAgents := getLaunchAgents(userAgentDir)
		items = append(items, userAgents...)
	}

	// 3. System launch agents.
	sysAgents := getLaunchAgents("/Library/LaunchAgents")
	items = append(items, sysAgents...)

	return items, nil
}

// RemoveItem removes a login item by name.
// For LaunchAgents, it uses launchctl to unload/disable.
// For LoginItems, it uses osascript.
func RemoveItem(name string) error {
	// Try to find the item first.
	items, err := ListItems()
	if err != nil {
		return fmt.Errorf("failed to list items: %w", err)
	}

	for _, item := range items {
		if item.Name != name {
			continue
		}

		switch item.Kind {
		case "LaunchAgent":
			return removeLaunchAgent(item.Path)
		case "LoginItem":
			return removeLoginItem(item.Name)
		default:
			return removeLoginItem(item.Name)
		}
	}

	return fmt.Errorf("login item %q not found", name)
}

// getOsascriptLoginItems retrieves login items via osascript.
func getOsascriptLoginItems() []LoginItem {
	script := `tell application "System Events" to get the name of every login item`
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return nil
	}
	return parseOsascriptLoginItems(string(out))
}

// parseOsascriptLoginItems parses comma-separated osascript output.
func parseOsascriptLoginItems(output string) []LoginItem {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var items []LoginItem
	for _, name := range strings.Split(output, ", ") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		items = append(items, LoginItem{
			Name: name,
			Kind: "LoginItem",
		})
	}
	return items
}

// getLaunchAgents scans a directory for plist files.
func getLaunchAgents(dir string) []LoginItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return parseLaunchAgentNames(names, dir)
}

// parseLaunchAgentNames converts plist file names to LoginItem slices.
func parseLaunchAgentNames(names []string, dir string) []LoginItem {
	var items []LoginItem
	for _, name := range names {
		if !strings.HasSuffix(name, ".plist") {
			continue
		}
		items = append(items, LoginItem{
			Name: strings.TrimSuffix(name, ".plist"),
			Path: filepath.Join(dir, name),
			Kind: "LaunchAgent",
		})
	}
	return items
}

// removeLaunchAgent unloads and disables a launch agent.
func removeLaunchAgent(path string) error {
	// Try bootout first (modern launchctl).
	out, err := exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), path).CombinedOutput()
	if err != nil {
		// Fall back to legacy unload.
		out, err = exec.Command("launchctl", "unload", "-w", path).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to unload launch agent: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// removeLoginItem removes a login item via osascript.
func removeLoginItem(name string) error {
	script := fmt.Sprintf(`tell application "System Events" to delete login item "%s"`, name)
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove login item %q: %s: %w", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

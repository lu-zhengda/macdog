package firewall

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

const socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// Status represents the current firewall state.
type Status struct {
	Enabled     bool   `json:"enabled"`
	StealthMode bool   `json:"stealth_mode"`
	BlockAll    bool   `json:"block_all"`
	Rules       []Rule `json:"rules"`
}

// Rule represents a firewall application rule.
type Rule struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Allowed bool   `json:"allowed"`
}

// GetStatus returns the current firewall status.
func GetStatus() (*Status, error) {
	s := &Status{}

	out, err := exec.Command(socketFilterFW, "--getglobalstate").CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("failed to get firewall state: %w", err)
	}
	s.Enabled = parseGlobalState(string(out))

	out, err = exec.Command(socketFilterFW, "--getstealthmode").CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("failed to get stealth mode: %w", err)
	}
	s.StealthMode = parseStealthMode(string(out))

	out, err = exec.Command(socketFilterFW, "--getblockall").CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("failed to get block-all state: %w", err)
	}
	s.BlockAll = parseBlockAll(string(out))

	rules, err := ListRules()
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}
	s.Rules = rules

	return s, nil
}

// Enable turns the firewall on. Requires sudo.
func Enable() error {
	out, err := exec.Command("sudo", socketFilterFW, "--setglobalstate", "on").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable firewall (requires sudo): %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Disable turns the firewall off. Requires sudo.
func Disable() error {
	out, err := exec.Command("sudo", socketFilterFW, "--setglobalstate", "off").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable firewall (requires sudo): %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// AllowApp adds a firewall rule to allow an application.
func AllowApp(path string) error {
	out, err := exec.Command("sudo", socketFilterFW, "--add", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to allow app %q (requires sudo): %s: %w", path, strings.TrimSpace(string(out)), err)
	}
	out, err = exec.Command("sudo", socketFilterFW, "--unblockapp", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unblock app %q (requires sudo): %s: %w", path, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// BlockApp adds a firewall rule to block an application.
func BlockApp(path string) error {
	out, err := exec.Command("sudo", socketFilterFW, "--add", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add app %q (requires sudo): %s: %w", path, strings.TrimSpace(string(out)), err)
	}
	out, err = exec.Command("sudo", socketFilterFW, "--blockapp", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to block app %q (requires sudo): %s: %w", path, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ListRules returns the list of application firewall rules.
func ListRules() ([]Rule, error) {
	out, err := exec.Command(socketFilterFW, "--listapps").CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("failed to list firewall rules: %w", err)
	}
	return parseListApps(string(out)), nil
}

// parseGlobalState parses the output of --getglobalstate.
func parseGlobalState(output string) bool {
	return strings.Contains(output, "enabled")
}

// parseStealthMode parses the output of --getstealthmode.
func parseStealthMode(output string) bool {
	return strings.Contains(output, "enabled")
}

// parseBlockAll parses the output of --getblockall.
func parseBlockAll(output string) bool {
	return strings.Contains(output, "ENABLED")
}

// parseListApps parses the output of --listapps into Rule slices.
// Format:
//
//	ALF : Total number of apps = N
//
//	1 :  /path/to/app
//	   ( Allow incoming connections )
func parseListApps(output string) []Rule {
	var rules []Rule
	lines := strings.Split(output, "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Look for lines matching "N :  /path/to/app"
		if !strings.Contains(line, " :  /") {
			continue
		}

		parts := strings.SplitN(line, " :  ", 2)
		if len(parts) != 2 {
			continue
		}

		path := strings.TrimSpace(parts[1])
		name := filepath.Base(path)
		allowed := true

		// Next non-empty line should contain Allow/Block.
		for j := i + 1; j < len(lines); j++ {
			next := strings.TrimSpace(lines[j])
			if next == "" {
				continue
			}
			if strings.Contains(next, "Block") {
				allowed = false
			}
			break
		}

		rules = append(rules, Rule{
			Name:    name,
			Path:    path,
			Allowed: allowed,
		})
	}

	return rules
}

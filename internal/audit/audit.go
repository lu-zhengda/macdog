package audit

import (
	"fmt"
	"os/exec"
	"strings"
)

// Report holds the results of a security audit.
type Report struct {
	SIP         string `json:"sip"`          // "enabled" or "disabled"
	Firewall    string `json:"firewall"`     // "on" or "off"
	FileVault   string `json:"file_vault"`   // "on" or "off"
	Gatekeeper  string `json:"gatekeeper"`   // "enabled" or "disabled"
	RemoteLogin string `json:"remote_login"` // "on" or "off"
}

// Full runs a full security audit and returns a Report.
func Full() (*Report, error) {
	r := &Report{}

	r.SIP = runAndParse("csrutil", []string{"status"}, parseCSRUtil)
	r.Firewall = runAndParse("/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getglobalstate"}, parseFirewall)
	r.FileVault = runAndParse("fdesetup", []string{"status"}, parseFileVault)
	r.Gatekeeper = runAndParse(spctlBin, []string{"--status"}, parseGatekeeper)
	r.RemoteLogin = runAndParse(systemsetupBin, []string{"-getremotelogin"}, parseRemoteLogin)
	// Fallback: if systemsetup requires admin, check via launchctl.
	if r.RemoteLogin == "unknown" {
		r.RemoteLogin = probeRemoteLoginFallback()
	}

	return r, nil
}

// Score computes a numeric security score (0-100).
func (r *Report) Score() int {
	score := 0
	if r.SIP == "enabled" {
		score += 25
	}
	if r.Firewall == "on" {
		score += 25
	}
	if r.FileVault == "on" {
		score += 25
	}
	if r.Gatekeeper == "enabled" {
		score += 15
	}
	if r.RemoteLogin == "off" {
		score += 10
	}
	return score
}

// Grade returns a letter grade (A-F) based on the security posture.
//
// Scoring: SIP enabled=25, Firewall on=25, FileVault on=25,
// Gatekeeper enabled=15, Remote Login off=10.
// A: >=90, B: >=75, C: >=60, D: >=40, F: <40.
func (r *Report) Grade() string {
	score := r.Score()
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// runAndParse executes a command and parses its output.
func runAndParse(name string, args []string, parse func(string) string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		// Some commands (like spctl) exit non-zero but still produce useful output.
		if len(out) > 0 {
			return parse(string(out))
		}
		return "unknown"
	}
	return parse(string(out))
}

// parseCSRUtil parses the output of `csrutil status`.
func parseCSRUtil(output string) string {
	s := strings.TrimSpace(output)
	switch {
	case strings.Contains(s, "enabled"):
		return "enabled"
	case strings.Contains(s, "disabled"):
		return "disabled"
	default:
		return "unknown"
	}
}

// parseFirewall parses the output of socketfilterfw --getglobalstate.
func parseFirewall(output string) string {
	s := strings.TrimSpace(output)
	switch {
	case strings.Contains(s, "enabled"):
		return "on"
	case strings.Contains(s, "disabled"):
		return "off"
	default:
		return "unknown"
	}
}

// parseFileVault parses the output of `fdesetup status`.
func parseFileVault(output string) string {
	s := strings.TrimSpace(output)
	switch {
	case strings.Contains(s, "On"):
		return "on"
	case strings.Contains(s, "Off"):
		return "off"
	default:
		return "unknown"
	}
}

// parseGatekeeper parses the output of `spctl --status`.
func parseGatekeeper(output string) string {
	s := strings.TrimSpace(output)
	switch {
	case strings.Contains(s, "assessments enabled"):
		return "enabled"
	case strings.Contains(s, "assessments disabled"):
		return "disabled"
	default:
		return "unknown"
	}
}

// parseRemoteLogin parses the output of `systemsetup -getremotelogin`.
func parseRemoteLogin(output string) string {
	s := strings.TrimSpace(output)
	switch {
	case strings.Contains(s, "Off"):
		return "off"
	case strings.Contains(s, "On"):
		return "on"
	default:
		return "unknown"
	}
}

// FixResult describes a single fix that was applied (or skipped).
type FixResult struct {
	Check  string `json:"check"`
	Status string `json:"status"` // "fixed", "skipped", "failed"
	Reason string `json:"reason"` // why it was skipped or error message
	Before string `json:"before"` // value before fix
	After  string `json:"after"`  // value after fix (empty if skipped/failed)
}

// FixReport holds the results of an auto-fix run.
type FixReport struct {
	Results []FixResult `json:"results"`
	Before  Report      `json:"before"`
	After   Report      `json:"after"`
}

const (
	socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	spctlBin       = "/usr/sbin/spctl"
	systemsetupBin = "/usr/sbin/systemsetup"
	launchctlBin   = "/bin/launchctl"
	sudoBin        = "/usr/bin/sudo"
)

// Fix runs a full audit, then auto-fixes checks that are safe to fix
// programmatically. It re-runs the audit after applying fixes and returns
// a FixReport describing what was changed.
func Fix() (*FixReport, error) {
	before, err := Full()
	if err != nil {
		return nil, fmt.Errorf("failed to run initial audit: %w", err)
	}

	fr := &FixReport{Before: *before}

	// SIP: cannot be changed programmatically (requires Recovery Mode).
	if before.SIP != "enabled" {
		fr.Results = append(fr.Results, FixResult{
			Check:  "System Integrity Protection",
			Status: "skipped",
			Reason: "requires reboot into Recovery Mode",
			Before: before.SIP,
		})
	}

	// Firewall: safe to enable via socketfilterfw.
	if before.Firewall != "on" {
		out, fErr := exec.Command(sudoBin, socketFilterFW, "--setglobalstate", "on").CombinedOutput()
		if fErr != nil {
			fr.Results = append(fr.Results, FixResult{
				Check:  "Firewall",
				Status: "failed",
				Reason: fmt.Sprintf("requires sudo: %s", strings.TrimSpace(string(out))),
				Before: before.Firewall,
			})
		} else {
			fr.Results = append(fr.Results, FixResult{
				Check:  "Firewall",
				Status: "fixed",
				Before: before.Firewall,
				After:  "on",
			})
		}
	}

	// FileVault: cannot be enabled non-interactively (requires password/recovery key setup).
	if before.FileVault != "on" {
		fr.Results = append(fr.Results, FixResult{
			Check:  "FileVault",
			Status: "skipped",
			Reason: "requires interactive setup with recovery key",
			Before: before.FileVault,
		})
	}

	// Gatekeeper: safe to enable via spctl.
	if before.Gatekeeper != "enabled" {
		out, gErr := exec.Command(sudoBin, spctlBin, "--master-enable").CombinedOutput()
		if gErr != nil {
			fr.Results = append(fr.Results, FixResult{
				Check:  "Gatekeeper",
				Status: "failed",
				Reason: fmt.Sprintf("requires sudo: %s", strings.TrimSpace(string(out))),
				Before: before.Gatekeeper,
			})
		} else {
			fr.Results = append(fr.Results, FixResult{
				Check:  "Gatekeeper",
				Status: "fixed",
				Before: before.Gatekeeper,
				After:  "enabled",
			})
		}
	}

	// Remote Login: safe to disable via systemsetup.
	if before.RemoteLogin != "off" {
		out, rErr := exec.Command(sudoBin, systemsetupBin, "-setremotelogin", "off").CombinedOutput()
		if rErr != nil {
			fr.Results = append(fr.Results, FixResult{
				Check:  "Remote Login",
				Status: "failed",
				Reason: fmt.Sprintf("requires sudo: %s", strings.TrimSpace(string(out))),
				Before: before.RemoteLogin,
			})
		} else {
			fr.Results = append(fr.Results, FixResult{
				Check:  "Remote Login",
				Status: "fixed",
				Before: before.RemoteLogin,
				After:  "off",
			})
		}
	}

	// Re-audit after fixes.
	after, err := Full()
	if err != nil {
		return nil, fmt.Errorf("failed to run post-fix audit: %w", err)
	}
	fr.After = *after

	return fr, nil
}

// probeRemoteLoginFallback checks remote login state by looking for sshd via launchctl.
func probeRemoteLoginFallback() string {
	out, err := exec.Command(launchctlBin, "list").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	if strings.Contains(string(out), "com.openssh.sshd") {
		return "on"
	}
	return "off"
}

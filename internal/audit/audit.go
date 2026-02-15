package audit

import (
	"os/exec"
	"strings"
)

// Report holds the results of a security audit.
type Report struct {
	SIP         string // "enabled" or "disabled"
	Firewall    string // "on" or "off"
	FileVault   string // "on" or "off"
	Gatekeeper  string // "enabled" or "disabled"
	RemoteLogin string // "on" or "off"
}

// Full runs a full security audit and returns a Report.
func Full() (*Report, error) {
	r := &Report{}

	r.SIP = runAndParse("csrutil", []string{"status"}, parseCSRUtil)
	r.Firewall = runAndParse("/usr/libexec/ApplicationFirewall/socketfilterfw", []string{"--getglobalstate"}, parseFirewall)
	r.FileVault = runAndParse("fdesetup", []string{"status"}, parseFileVault)
	r.Gatekeeper = runAndParse("spctl", []string{"--status"}, parseGatekeeper)
	r.RemoteLogin = runAndParse("systemsetup", []string{"-getremotelogin"}, parseRemoteLogin)

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

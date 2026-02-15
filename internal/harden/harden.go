package harden

import (
	"fmt"
	"os/exec"
	"strings"
)

const socketFilterFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// Action represents a single hardening action.
type Action struct {
	Name         string
	Description  string
	CurrentState string
	DesiredState string
	Apply        func() error
}

// Plan returns a list of hardening actions showing current vs. desired state.
func Plan() ([]Action, error) {
	actions := []Action{
		{
			Name:         "Enable Firewall",
			Description:  "Turn on the application-level firewall to control incoming connections",
			CurrentState: probeFirewall(),
			DesiredState: "on",
			Apply: func() error {
				return sudoRun(socketFilterFW, "--setglobalstate", "on")
			},
		},
		{
			Name:         "Enable Stealth Mode",
			Description:  "Enable stealth mode so the system does not respond to probing requests (ping, etc.)",
			CurrentState: probeStealthMode(),
			DesiredState: "on",
			Apply: func() error {
				return sudoRun(socketFilterFW, "--setstealthmode", "on")
			},
		},
		{
			Name:         "Disable Remote Login",
			Description:  "Disable SSH remote login to prevent unauthorized remote access",
			CurrentState: probeRemoteLogin(),
			DesiredState: "off",
			Apply: func() error {
				return sudoRun("systemsetup", "-setremotelogin", "off")
			},
		},
		{
			Name:         "Disable Remote Apple Events",
			Description:  "Disable remote Apple events to prevent remote AppleScript execution",
			CurrentState: probeRemoteAppleEvents(),
			DesiredState: "off",
			Apply: func() error {
				return sudoRun("systemsetup", "-setremoteappleevents", "off")
			},
		},
		{
			Name:         "Require Password After Sleep (5s)",
			Description:  "Require password within 5 seconds after sleep or screen saver begins",
			CurrentState: probeScreenSaverPassword(),
			DesiredState: "on (5s)",
			Apply: func() error {
				// Set askForPassword = 1 and askForPasswordDelay = 5.
				err := exec.Command("defaults", "write", "com.apple.screensaver", "askForPassword", "-int", "1").Run()
				if err != nil {
					return fmt.Errorf("failed to set askForPassword: %w", err)
				}
				err = exec.Command("defaults", "write", "com.apple.screensaver", "askForPasswordDelay", "-int", "5").Run()
				if err != nil {
					return fmt.Errorf("failed to set askForPasswordDelay: %w", err)
				}
				return nil
			},
		},
	}

	return actions, nil
}

// Apply executes the given hardening actions.
func Apply(actions []Action) error {
	for _, a := range actions {
		if a.CurrentState == a.DesiredState {
			continue
		}
		if err := a.Apply(); err != nil {
			return fmt.Errorf("failed to apply %q: %w", a.Name, err)
		}
	}
	return nil
}

// sudoRun executes a command with sudo.
func sudoRun(name string, args ...string) error {
	cmdArgs := append([]string{name}, args...)
	out, err := exec.Command("sudo", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s (requires sudo): %s: %w", name, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// probeFirewall checks the current firewall state.
func probeFirewall() string {
	out, err := exec.Command(socketFilterFW, "--getglobalstate").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	if strings.Contains(string(out), "enabled") {
		return "on"
	}
	if strings.Contains(string(out), "disabled") {
		return "off"
	}
	return "unknown"
}

// probeStealthMode checks stealth mode state.
func probeStealthMode() string {
	out, err := exec.Command(socketFilterFW, "--getstealthmode").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	if strings.Contains(string(out), "enabled") {
		return "on"
	}
	if strings.Contains(string(out), "disabled") {
		return "off"
	}
	return "unknown"
}

// probeRemoteLogin checks remote login state.
func probeRemoteLogin() string {
	out, err := exec.Command("systemsetup", "-getremotelogin").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	s := string(out)
	if strings.Contains(s, "Off") {
		return "off"
	}
	if strings.Contains(s, "On") {
		return "on"
	}
	return "unknown"
}

// probeRemoteAppleEvents checks remote Apple events state.
func probeRemoteAppleEvents() string {
	out, err := exec.Command("systemsetup", "-getremoteappleevents").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	return parseRemoteAppleEvents(string(out))
}

// parseRemoteAppleEvents parses systemsetup -getremoteappleevents output.
func parseRemoteAppleEvents(output string) string {
	s := strings.TrimSpace(output)
	if strings.Contains(s, "Off") {
		return "off"
	}
	if strings.Contains(s, "On") {
		return "on"
	}
	return "unknown"
}

// probeScreenSaverPassword checks the screen saver password setting.
func probeScreenSaverPassword() string {
	out, err := exec.Command("defaults", "read", "com.apple.screensaver").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	return parseScreenSaverPassword(string(out))
}

// parseScreenSaverPassword parses defaults read com.apple.screensaver output.
func parseScreenSaverPassword(output string) string {
	s := strings.TrimSpace(output)
	if strings.Contains(s, "askForPassword = 1") {
		// Extract delay.
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "askForPasswordDelay") {
				// Parse "askForPasswordDelay = N;"
				line = strings.TrimSuffix(line, ";")
				parts := strings.Split(line, "= ")
				if len(parts) == 2 {
					return fmt.Sprintf("on (%ss)", strings.TrimSpace(parts[1]))
				}
			}
		}
		return "on (0s)"
	}
	if strings.Contains(s, "askForPassword = 0") {
		return "off"
	}
	return "unknown"
}

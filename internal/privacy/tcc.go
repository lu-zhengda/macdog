package privacy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Permission represents a TCC privacy permission entry.
type Permission struct {
	Service      string
	App          string
	BundleID     string
	Allowed      bool
	LastModified string
}

// tccServiceMap maps TCC internal names to human-readable names.
var tccServiceMap = map[string]string{
	"kTCCServiceCamera":                "Camera",
	"kTCCServiceMicrophone":            "Microphone",
	"kTCCServiceAddressBook":           "Contacts",
	"kTCCServiceCalendar":              "Calendar",
	"kTCCServicePhotos":                "Photos",
	"kTCCServiceReminders":             "Reminders",
	"kTCCServiceAccessibility":         "Accessibility",
	"kTCCServiceScreenCapture":         "ScreenCapture",
	"kTCCServiceSystemPolicyAllFiles":  "FullDiskAccess",
	"kTCCServiceSystemPolicyDesktopFolder": "DesktopFolder",
	"kTCCServiceSystemPolicyDocumentsFolder": "DocumentsFolder",
	"kTCCServiceSystemPolicyDownloadsFolder": "DownloadsFolder",
	"kTCCServiceLocation":              "Location",
	"kTCCServiceMediaLibrary":          "MediaLibrary",
	"kTCCServiceAppleEvents":           "AppleEvents",
	"kTCCServiceListenEvent":           "InputMonitoring",
	"kTCCServicePostEvent":             "Automation",
}

// ListPermissions reads the user TCC.db and returns all permission entries.
func ListPermissions() ([]Permission, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	dbPath := filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("TCC database not found at %s", dbPath)
	}

	query := "SELECT service, client, auth_value, last_modified FROM access"
	out, err := exec.Command("sqlite3", "-separator", "|", dbPath, query).CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "unable to open database") || strings.Contains(outStr, "Error") {
			return nil, fmt.Errorf("cannot read TCC database (Full Disk Access required): %s", outStr)
		}
		return nil, fmt.Errorf("failed to query TCC database: %s: %w", outStr, err)
	}

	return parseTCCOutput(string(out)), nil
}

// RevokePermission revokes a TCC permission for a specific service and bundle ID.
func RevokePermission(service, bundleID string) error {
	out, err := exec.Command("tccutil", "reset", service, bundleID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to revoke %s permission for %s: %s: %w",
			service, bundleID, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ListServices returns a list of known TCC service names.
func ListServices() []string {
	return []string{
		"Camera",
		"Microphone",
		"Location",
		"Contacts",
		"Calendar",
		"Reminders",
		"Photos",
		"MediaLibrary",
		"Accessibility",
		"ScreenCapture",
		"FullDiskAccess",
		"DesktopFolder",
		"DocumentsFolder",
		"DownloadsFolder",
		"InputMonitoring",
		"Automation",
		"AppleEvents",
	}
}

// parseTCCOutput parses sqlite3 output into Permission slices.
// Expected format per line: service|client|auth_value|last_modified
func parseTCCOutput(output string) []Permission {
	var perms []Permission
	output = strings.TrimSpace(output)
	if output == "" {
		return perms
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 3 {
			continue
		}

		service := serviceNameFromTCC(parts[0])
		bundleID := parts[1]
		authValue := parts[2]
		lastMod := ""
		if len(parts) >= 4 {
			lastMod = parts[3]
		}

		perms = append(perms, Permission{
			Service:      service,
			App:          appNameFromBundleID(bundleID),
			BundleID:     bundleID,
			Allowed:      authValue == "2", // 2 = allowed, 0 = denied
			LastModified: lastMod,
		})
	}

	return perms
}

// serviceNameFromTCC converts a TCC service constant to a human-readable name.
func serviceNameFromTCC(tccName string) string {
	if name, ok := tccServiceMap[tccName]; ok {
		return name
	}
	// Strip "kTCCService" prefix as fallback.
	return strings.TrimPrefix(tccName, "kTCCService")
}

// appNameFromBundleID extracts a short app name from a bundle identifier.
func appNameFromBundleID(bundleID string) string {
	parts := strings.Split(bundleID, ".")
	if len(parts) == 0 {
		return bundleID
	}
	return parts[len(parts)-1]
}

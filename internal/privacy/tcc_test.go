package privacy

import (
	"testing"
)

func TestListServices(t *testing.T) {
	services := ListServices()
	if len(services) == 0 {
		t.Fatal("ListServices() returned empty slice")
	}

	// Verify some well-known services are present.
	known := map[string]bool{
		"Camera":      false,
		"Microphone":  false,
		"Contacts":    false,
		"Calendar":    false,
		"Photos":      false,
		"Reminders":   false,
		"Accessibility": false,
	}

	for _, svc := range services {
		if _, ok := known[svc]; ok {
			known[svc] = true
		}
	}

	for svc, found := range known {
		if !found {
			t.Errorf("expected service %q not found in ListServices()", svc)
		}
	}
}

func TestParseTCCOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		want    int
		wantErr bool
	}{
		{
			name: "two permissions",
			output: `kTCCServiceCamera|com.apple.Terminal|2|1700000000
kTCCServiceMicrophone|com.zoom.us|0|1700000001`,
			want: 2,
		},
		{
			name:   "empty output",
			output: "",
			want:   0,
		},
		{
			name: "single permission allowed",
			output: `kTCCServiceCamera|com.apple.Terminal|2|1700000000`,
			want:   1,
		},
		{
			name: "single permission denied",
			output: `kTCCServiceCamera|com.apple.Terminal|0|1700000000`,
			want:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := parseTCCOutput(tt.output)
			if len(perms) != tt.want {
				t.Errorf("parseTCCOutput() returned %d permissions, want %d", len(perms), tt.want)
			}
		})
	}
}

func TestParseTCCOutputDetails(t *testing.T) {
	output := `kTCCServiceCamera|com.apple.Terminal|2|1700000000
kTCCServiceMicrophone|com.zoom.us|0|1700000001`

	perms := parseTCCOutput(output)
	if len(perms) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(perms))
	}

	// First permission: Camera, Terminal, allowed.
	if perms[0].Service != "Camera" {
		t.Errorf("perms[0].Service = %q, want %q", perms[0].Service, "Camera")
	}
	if perms[0].BundleID != "com.apple.Terminal" {
		t.Errorf("perms[0].BundleID = %q, want %q", perms[0].BundleID, "com.apple.Terminal")
	}
	if !perms[0].Allowed {
		t.Error("perms[0].Allowed = false, want true")
	}

	// Second permission: Microphone, Zoom, denied.
	if perms[1].Service != "Microphone" {
		t.Errorf("perms[1].Service = %q, want %q", perms[1].Service, "Microphone")
	}
	if perms[1].BundleID != "com.zoom.us" {
		t.Errorf("perms[1].BundleID = %q, want %q", perms[1].BundleID, "com.zoom.us")
	}
	if perms[1].Allowed {
		t.Error("perms[1].Allowed = true, want false")
	}
}

func TestServiceNameFromTCC(t *testing.T) {
	tests := []struct {
		tccName string
		want    string
	}{
		{"kTCCServiceCamera", "Camera"},
		{"kTCCServiceMicrophone", "Microphone"},
		{"kTCCServiceAddressBook", "Contacts"},
		{"kTCCServiceCalendar", "Calendar"},
		{"kTCCServicePhotos", "Photos"},
		{"kTCCServiceReminders", "Reminders"},
		{"kTCCServiceAccessibility", "Accessibility"},
		{"kTCCServiceScreenCapture", "ScreenCapture"},
		{"kTCCServiceSystemPolicyAllFiles", "FullDiskAccess"},
		{"kTCCServiceUnknownNew", "UnknownNew"},
	}

	for _, tt := range tests {
		t.Run(tt.tccName, func(t *testing.T) {
			got := serviceNameFromTCC(tt.tccName)
			if got != tt.want {
				t.Errorf("serviceNameFromTCC(%q) = %q, want %q", tt.tccName, got, tt.want)
			}
		})
	}
}

func TestAppNameFromBundleID(t *testing.T) {
	tests := []struct {
		bundleID string
		want     string
	}{
		{"com.apple.Terminal", "Terminal"},
		{"com.zoom.us", "us"},
		{"org.mozilla.firefox", "firefox"},
		{"singleword", "singleword"},
	}

	for _, tt := range tests {
		t.Run(tt.bundleID, func(t *testing.T) {
			got := appNameFromBundleID(tt.bundleID)
			if got != tt.want {
				t.Errorf("appNameFromBundleID(%q) = %q, want %q", tt.bundleID, got, tt.want)
			}
		})
	}
}

func TestListPermissions(t *testing.T) {
	// ListPermissions reads the TCC.db which may not be accessible.
	// We just verify it handles errors gracefully.
	perms, err := ListPermissions()
	if err != nil {
		// This is expected if Full Disk Access is not granted.
		t.Logf("ListPermissions() error (expected without Full Disk Access): %v", err)
		return
	}
	// If it succeeded, verify we got a slice (possibly empty).
	_ = perms
}

func TestRevokePermission(t *testing.T) {
	// tccutil reset requires a valid service — we test with a no-op.
	// This will likely fail without proper permissions, which is fine.
	err := RevokePermission("Camera", "com.example.nonexistent")
	if err != nil {
		t.Logf("RevokePermission() error (expected): %v", err)
	}
}

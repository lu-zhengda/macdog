// Package status aggregates key security signals from multiple macdog domains
// into a single concise health report.  It is intentionally lightweight: it
// calls only fast, non-blocking operations (a handful of subprocess calls and
// filesystem reads) and never touches event logs by default.
package status

import (
	"time"

	"github.com/lu-zhengda/macdog/internal/audit"
	"github.com/lu-zhengda/macdog/internal/firewall"
	"github.com/lu-zhengda/macdog/internal/login"
	"github.com/lu-zhengda/macdog/internal/privacy"
)

// loginTimeout is the maximum time to wait for osascript-based login item listing.
// osascript can block indefinitely in headless / automation environments.
const loginTimeout = 5 * time.Second

// Overall status levels returned by Report.Overall.
const (
	OverallOK       = "ok"
	OverallWarning  = "warning"
	OverallCritical = "critical"
)

// Report is a concise snapshot of the system's security posture.
type Report struct {
	Overall     string      `json:"overall"`
	Score       int         `json:"score"`
	Grade       string      `json:"grade"`
	GeneratedAt string      `json:"generated_at"`
	Audit       AuditInfo   `json:"audit"`
	Firewall    FirewallInfo `json:"firewall"`
	LoginItems  LoginInfo   `json:"login_items"`
	Privacy     PrivacyInfo `json:"privacy"`
}

// AuditInfo mirrors the key fields from the audit report.
type AuditInfo struct {
	SIP         string `json:"sip"`
	Firewall    string `json:"firewall"`
	FileVault   string `json:"file_vault"`
	Gatekeeper  string `json:"gatekeeper"`
	RemoteLogin string `json:"remote_login"`
	Score       int    `json:"score"`
	Grade       string `json:"grade"`
}

// FirewallInfo contains the current firewall state (excluding per-app rules).
type FirewallInfo struct {
	Enabled     bool   `json:"enabled"`
	StealthMode bool   `json:"stealth_mode"`
	BlockAll    bool   `json:"block_all"`
	RuleCount   int    `json:"rule_count"`
	Error       string `json:"error,omitempty"`
}

// LoginInfo summarises login items and launch agents.
type LoginInfo struct {
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

// PrivacyInfo summarises TCC permission grants.
// If the TCC database is not readable (Full Disk Access required), Error is set.
type PrivacyInfo struct {
	Granted int    `json:"granted"`
	Denied  int    `json:"denied"`
	Total   int    `json:"total"`
	Error   string `json:"error,omitempty"`
}

// Collect runs all fast sub-checks and returns a consolidated Report.
// Errors in individual sub-checks are recorded inside the relevant field
// (rather than aborting the whole report) so that partial results are
// always returned.
func Collect() (*Report, error) {
	r := &Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// ── Audit (5 quick subprocess calls) ────────────────────────────────
	auditReport, err := audit.Full()
	if err != nil {
		return nil, err // audit is mandatory; abort if it fails
	}
	r.Score = auditReport.Score()
	r.Grade = auditReport.Grade()
	r.Audit = AuditInfo{
		SIP:         auditReport.SIP,
		Firewall:    auditReport.Firewall,
		FileVault:   auditReport.FileVault,
		Gatekeeper:  auditReport.Gatekeeper,
		RemoteLogin: auditReport.RemoteLogin,
		Score:       r.Score,
		Grade:       r.Grade,
	}

	// ── Firewall state (3 subprocess calls) ─────────────────────────────
	fwStatus, fwErr := firewall.GetStatus()
	if fwErr != nil {
		r.Firewall = FirewallInfo{Error: fwErr.Error()}
	} else {
		r.Firewall = FirewallInfo{
			Enabled:     fwStatus.Enabled,
			StealthMode: fwStatus.StealthMode,
			BlockAll:    fwStatus.BlockAll,
			RuleCount:   len(fwStatus.Rules),
		}
	}

	// ── Login items (filesystem scan + osascript) ────────────────────────
	// osascript can hang in headless/automation environments, so we run it
	// in a goroutine with a bounded timeout.
	type loginResult struct {
		items []login.LoginItem
		err   error
	}
	loginCh := make(chan loginResult, 1)
	go func() {
		items, err := login.ListItems()
		loginCh <- loginResult{items, err}
	}()
	select {
	case lr := <-loginCh:
		if lr.err != nil {
			r.LoginItems = LoginInfo{Error: lr.err.Error()}
		} else {
			r.LoginItems = LoginInfo{Count: len(lr.items)}
		}
	case <-time.After(loginTimeout):
		r.LoginItems = LoginInfo{Error: "timed out (osascript unavailable in this environment)"}
	}

	// ── Privacy / TCC (best-effort — requires Full Disk Access) ──────────
	perms, privErr := privacy.ListPermissions()
	if privErr != nil {
		r.Privacy = PrivacyInfo{Error: privErr.Error()}
	} else {
		var granted, denied int
		for _, p := range perms {
			if p.Allowed {
				granted++
			} else {
				denied++
			}
		}
		r.Privacy = PrivacyInfo{
			Granted: granted,
			Denied:  denied,
			Total:   len(perms),
		}
	}

	// ── Overall ──────────────────────────────────────────────────────────
	r.Overall = computeOverall(r)

	return r, nil
}

// computeOverall derives an overall status string from the audit score.
//
// Thresholds align with the audit grade boundaries:
//
//	ok       → A grade (score ≥ 90)  — all or nearly all checks pass
//	warning  → B/C grade (60–89)     — one or more checks failing
//	critical → D/F grade (score < 60) — multiple critical checks failing
func computeOverall(r *Report) string {
	switch {
	case r.Score >= 90:
		return OverallOK
	case r.Score >= 60:
		return OverallWarning
	default:
		return OverallCritical
	}
}

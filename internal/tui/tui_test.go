package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zhengda-lu/macdog/internal/audit"
	"github.com/zhengda-lu/macdog/internal/harden"
)

func TestNew(t *testing.T) {
	m := New("1.0.0")
	if m.version != "1.0.0" {
		t.Errorf("version = %q, want %q", m.version, "1.0.0")
	}
	if m.tab != tabAudit {
		t.Errorf("tab = %d, want %d (tabAudit)", m.tab, tabAudit)
	}
	if !m.loading {
		t.Error("loading = false, want true")
	}
}

func TestInit(t *testing.T) {
	m := New("dev")
	cmd := m.Init()
	if cmd == nil {
		t.Error("Init() returned nil cmd, want batch cmd")
	}
}

func TestUpdateQuit(t *testing.T) {
	m := New("dev")
	m.loading = false

	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("pressing q should return a quit cmd")
	}
	_ = newModel
}

func TestUpdateTabSwitch(t *testing.T) {
	m := New("dev")
	m.loading = false

	// Tab forward.
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newModel.(Model)
	if m.tab != tabFirewall {
		t.Errorf("after tab press, tab = %d, want %d (tabFirewall)", m.tab, tabFirewall)
	}

	// Tab forward again.
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newModel.(Model)
	if m.tab != tabPrivacy {
		t.Errorf("after second tab press, tab = %d, want %d (tabPrivacy)", m.tab, tabPrivacy)
	}

	// Shift+tab backward.
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	m = newModel.(Model)
	if m.tab != tabFirewall {
		t.Errorf("after shift+tab, tab = %d, want %d (tabFirewall)", m.tab, tabFirewall)
	}
}

func TestUpdateNavigation(t *testing.T) {
	m := New("dev")
	m.loading = false
	m.tab = tabHarden
	m.hardenActions = []harden.Action{
		{Name: "Action 1"},
		{Name: "Action 2"},
		{Name: "Action 3"},
	}

	// Move down.
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m = newModel.(Model)
	if m.cursor != 1 {
		t.Errorf("after j, cursor = %d, want 1", m.cursor)
	}

	// Move up.
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m = newModel.(Model)
	if m.cursor != 0 {
		t.Errorf("after k, cursor = %d, want 0", m.cursor)
	}

	// Can't go above 0.
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m = newModel.(Model)
	if m.cursor != 0 {
		t.Errorf("after k at 0, cursor = %d, want 0", m.cursor)
	}
}

func TestViewLoading(t *testing.T) {
	m := New("dev")
	view := m.View()
	if view == "" {
		t.Error("View() returned empty string while loading")
	}
}

func TestViewAudit(t *testing.T) {
	m := New("dev")
	m.loading = false
	m.auditReport = &audit.Report{
		SIP:         "enabled",
		Firewall:    "on",
		FileVault:   "on",
		Gatekeeper:  "enabled",
		RemoteLogin: "off",
	}

	view := m.View()
	if view == "" {
		t.Error("View() returned empty string")
	}
}

func TestRenderTabs(t *testing.T) {
	m := New("dev")
	tabs := m.renderTabs()
	if tabs == "" {
		t.Error("renderTabs() returned empty string")
	}
}

func TestAuditDoneMsg(t *testing.T) {
	m := New("dev")
	report := &audit.Report{
		SIP:         "enabled",
		Firewall:    "on",
		FileVault:   "on",
		Gatekeeper:  "enabled",
		RemoteLogin: "off",
	}

	newModel, _ := m.Update(auditDoneMsg{report: report})
	m = newModel.(Model)

	if m.auditReport == nil {
		t.Error("auditReport is nil after auditDoneMsg")
	}
	if m.loading {
		t.Error("still loading after auditDoneMsg")
	}
}

func TestWindowSizeMsg(t *testing.T) {
	m := New("dev")
	newModel, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = newModel.(Model)
	if m.width != 120 {
		t.Errorf("width = %d, want 120", m.width)
	}
	if m.height != 40 {
		t.Errorf("height = %d, want 40", m.height)
	}
}

func TestBoolToStr(t *testing.T) {
	if got := boolToStr(true, "on", "off"); got != "on" {
		t.Errorf("boolToStr(true) = %q, want %q", got, "on")
	}
	if got := boolToStr(false, "on", "off"); got != "off" {
		t.Errorf("boolToStr(false) = %q, want %q", got, "off")
	}
}

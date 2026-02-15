package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zhengda-lu/macdog/internal/audit"
	"github.com/zhengda-lu/macdog/internal/firewall"
	"github.com/zhengda-lu/macdog/internal/harden"
	"github.com/zhengda-lu/macdog/internal/login"
	"github.com/zhengda-lu/macdog/internal/privacy"
)

// Tab indices.
const (
	tabAudit = iota
	tabFirewall
	tabPrivacy
	tabLoginItems
	tabHarden
	tabCount
)

var tabNames = []string{"Audit", "Firewall", "Privacy", "Login Items", "Harden"}

// Styles.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250")).
				Background(lipgloss.Color("236")).
				Padding(0, 1)

	gradeStyleA = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("46"))

	gradeStyleB = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("46"))

	gradeStyleC = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("226"))

	gradeStyleDF = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("196"))

	secureStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("46"))

	insecureStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("242"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15"))

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("237")).
			Foreground(lipgloss.Color("15"))
)

// Model is the main TUI model.
type Model struct {
	version string
	tab     int
	cursor  int
	width   int
	height  int
	loading bool
	err     error

	// Data.
	auditReport    *audit.Report
	fwStatus       *firewall.Status
	permissions    []privacy.Permission
	privacyErr     error
	loginItems     []login.LoginItem
	hardenActions  []harden.Action
}

// Messages.
type auditDoneMsg struct {
	report *audit.Report
	err    error
}

type firewallDoneMsg struct {
	status *firewall.Status
	err    error
}

type privacyDoneMsg struct {
	perms []privacy.Permission
	err   error
}

type loginDoneMsg struct {
	items []login.LoginItem
	err   error
}

type hardenDoneMsg struct {
	actions []harden.Action
	err     error
}

// New creates a new TUI model.
func New(version string) Model {
	return Model{
		version: version,
		tab:     tabAudit,
		loading: true,
	}
}

// Init initializes the model and kicks off data loading.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		loadAudit,
		loadFirewall,
		loadPrivacy,
		loadLogin,
		loadHarden,
	)
}

func loadAudit() tea.Msg {
	report, err := audit.Full()
	return auditDoneMsg{report: report, err: err}
}

func loadFirewall() tea.Msg {
	status, err := firewall.GetStatus()
	return firewallDoneMsg{status: status, err: err}
}

func loadPrivacy() tea.Msg {
	perms, err := privacy.ListPermissions()
	return privacyDoneMsg{perms: perms, err: err}
}

func loadLogin() tea.Msg {
	items, err := login.ListItems()
	return loginDoneMsg{items: items, err: err}
}

func loadHarden() tea.Msg {
	actions, err := harden.Plan()
	return hardenDoneMsg{actions: actions, err: err}
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "l":
			m.tab = (m.tab + 1) % tabCount
			m.cursor = 0
		case "shift+tab", "h":
			m.tab = (m.tab - 1 + tabCount) % tabCount
			m.cursor = 0
		case "j", "down":
			m.cursor++
			m.cursor = m.clampCursor()
		case "k", "up":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = 0
			}
		case "enter":
			return m, m.handleEnter()
		}

	case auditDoneMsg:
		m.auditReport = msg.report
		if msg.err != nil {
			m.err = msg.err
		}
		m.checkLoading()

	case firewallDoneMsg:
		m.fwStatus = msg.status
		if msg.err != nil && m.err == nil {
			m.err = msg.err
		}
		m.checkLoading()

	case privacyDoneMsg:
		m.permissions = msg.perms
		m.privacyErr = msg.err
		m.checkLoading()

	case loginDoneMsg:
		m.loginItems = msg.items
		if msg.err != nil && m.err == nil {
			m.err = msg.err
		}
		m.checkLoading()

	case hardenDoneMsg:
		m.hardenActions = msg.actions
		if msg.err != nil && m.err == nil {
			m.err = msg.err
		}
		m.checkLoading()
	}

	return m, nil
}

func (m *Model) checkLoading() {
	// Loading is done when audit report is available.
	if m.auditReport != nil {
		m.loading = false
	}
}

func (m Model) clampCursor() int {
	max := 0
	switch m.tab {
	case tabFirewall:
		if m.fwStatus != nil {
			max = len(m.fwStatus.Rules) - 1
		}
	case tabPrivacy:
		max = len(m.permissions) - 1
	case tabLoginItems:
		max = len(m.loginItems) - 1
	case tabHarden:
		max = len(m.hardenActions) - 1
	}
	if m.cursor > max {
		return max
	}
	if m.cursor < 0 {
		return 0
	}
	return m.cursor
}

func (m Model) handleEnter() tea.Cmd {
	// Harden tab: apply the selected action.
	if m.tab == tabHarden && m.cursor >= 0 && m.cursor < len(m.hardenActions) {
		action := m.hardenActions[m.cursor]
		if action.CurrentState != action.DesiredState {
			return func() tea.Msg {
				_ = action.Apply()
				// Reload harden actions.
				actions, err := harden.Plan()
				return hardenDoneMsg{actions: actions, err: err}
			}
		}
	}
	return nil
}

// View renders the TUI.
func (m Model) View() string {
	if m.loading {
		return "\n  Loading security data...\n"
	}

	var b strings.Builder

	// Header.
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("macdog"))
	b.WriteString(dimStyle.Render(fmt.Sprintf(" v%s", m.version)))
	b.WriteString("\n\n")

	// Tab bar.
	b.WriteString(m.renderTabs())
	b.WriteString("\n\n")

	// Content.
	switch m.tab {
	case tabAudit:
		b.WriteString(m.renderAudit())
	case tabFirewall:
		b.WriteString(m.renderFirewall())
	case tabPrivacy:
		b.WriteString(m.renderPrivacy())
	case tabLoginItems:
		b.WriteString(m.renderLoginItems())
	case tabHarden:
		b.WriteString(m.renderHarden())
	}

	// Footer.
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  Tab/h/l: switch tabs  j/k: navigate  Enter: act  q: quit"))
	b.WriteString("\n")

	return b.String()
}

func (m Model) renderTabs() string {
	var tabs []string
	for i, name := range tabNames {
		if i == m.tab {
			tabs = append(tabs, activeTabStyle.Render(name))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(name))
		}
	}
	return "  " + strings.Join(tabs, " ")
}

func (m Model) renderAudit() string {
	if m.auditReport == nil {
		return "  No audit data available.\n"
	}

	r := m.auditReport
	grade := r.Grade()
	score := r.Score()

	var b strings.Builder

	// Big grade display.
	gradeStyle := gradeStyleDF
	switch grade {
	case "A":
		gradeStyle = gradeStyleA
	case "B":
		gradeStyle = gradeStyleB
	case "C":
		gradeStyle = gradeStyleC
	}

	bigGrade := fmt.Sprintf(`
    ██████╗
    ██╔══██╗
    ██████╔╝
    ██╔══██╗
    ██████╔╝
    ╚═════╝ `)

	switch grade {
	case "A":
		bigGrade = `
     █████╗
    ██╔══██╗
    ███████║
    ██╔══██║
    ██║  ██║
    ╚═╝  ╚═╝`
	case "B":
		bigGrade = `
    ██████╗
    ██╔══██╗
    ██████╔╝
    ██╔══██╗
    ██████╔╝
    ╚═════╝ `
	case "C":
		bigGrade = `
     ██████╗
    ██╔════╝
    ██║
    ██║
    ╚██████╗
     ╚═════╝`
	case "D":
		bigGrade = `
    ██████╗
    ██╔══██╗
    ██║  ██║
    ██║  ██║
    ██████╔╝
    ╚═════╝ `
	case "F":
		bigGrade = `
    ███████╗
    ██╔════╝
    █████╗
    ██╔══╝
    ██║
    ╚═╝     `
	}

	b.WriteString(gradeStyle.Render(bigGrade))
	b.WriteString(fmt.Sprintf("\n    %s\n\n", dimStyle.Render(fmt.Sprintf("Score: %d/100", score))))

	// Check details.
	b.WriteString(renderCheck("System Integrity Protection", r.SIP, "enabled"))
	b.WriteString(renderCheck("Firewall", r.Firewall, "on"))
	b.WriteString(renderCheck("FileVault", r.FileVault, "on"))
	b.WriteString(renderCheck("Gatekeeper", r.Gatekeeper, "enabled"))
	b.WriteString(renderCheck("Remote Login", r.RemoteLogin, "off"))

	return b.String()
}

func renderCheck(name, value, secureValue string) string {
	icon := insecureStyle.Render("  ✗ ")
	val := insecureStyle.Render(value)
	if value == secureValue {
		icon = secureStyle.Render("  ✓ ")
		val = secureStyle.Render(value)
	}
	return fmt.Sprintf("%s%-35s %s\n", icon, name, val)
}

func (m Model) renderFirewall() string {
	if m.fwStatus == nil {
		return "  No firewall data available.\n"
	}

	var b strings.Builder

	b.WriteString(renderCheck("Firewall", boolToStr(m.fwStatus.Enabled, "on", "off"), "on"))
	b.WriteString(renderCheck("Stealth Mode", boolToStr(m.fwStatus.StealthMode, "on", "off"), "on"))
	b.WriteString(renderCheck("Block All", boolToStr(m.fwStatus.BlockAll, "on", "off"), "on"))
	b.WriteString("\n")

	if len(m.fwStatus.Rules) == 0 {
		b.WriteString(dimStyle.Render("  No application rules configured.\n"))
		return b.String()
	}

	b.WriteString(headerStyle.Render("  Application Rules:"))
	b.WriteString("\n\n")

	for i, r := range m.fwStatus.Rules {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			prefix = "▸ "
			style = selectedStyle
		}

		status := insecureStyle.Render("blocked")
		if r.Allowed {
			status = secureStyle.Render("allowed")
		}

		line := fmt.Sprintf("%s%-30s %s", prefix, r.Name, status)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderPrivacy() string {
	if m.privacyErr != nil {
		return fmt.Sprintf("  %s\n  %s\n",
			insecureStyle.Render("Cannot read TCC database."),
			dimStyle.Render("Grant Full Disk Access to Terminal to view privacy permissions."))
	}

	if len(m.permissions) == 0 {
		return dimStyle.Render("  No TCC permissions found.\n")
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render("  Privacy Permissions:"))
	b.WriteString("\n\n")

	for i, p := range m.permissions {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			prefix = "▸ "
			style = selectedStyle
		}

		status := insecureStyle.Render("denied")
		if p.Allowed {
			status = secureStyle.Render("allowed")
		}

		line := fmt.Sprintf("%s%-15s %-25s %s", prefix, p.Service, p.BundleID, status)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderLoginItems() string {
	if len(m.loginItems) == 0 {
		return dimStyle.Render("  No login items found.\n")
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render("  Login Items & Launch Agents:"))
	b.WriteString("\n\n")

	for i, item := range m.loginItems {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			prefix = "▸ "
			style = selectedStyle
		}

		kind := dimStyle.Render(fmt.Sprintf("[%s]", item.Kind))
		line := fmt.Sprintf("%s%-40s %s", prefix, item.Name, kind)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderHarden() string {
	if len(m.hardenActions) == 0 {
		return dimStyle.Render("  No hardening actions available.\n")
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render("  Hardening Actions:"))
	b.WriteString(dimStyle.Render("  (Enter to apply selected action)"))
	b.WriteString("\n\n")

	for i, a := range m.hardenActions {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			prefix = "▸ "
			style = selectedStyle
		}

		status := secureStyle.Render("OK")
		change := ""
		if a.CurrentState != a.DesiredState {
			status = insecureStyle.Render("CHANGE")
			change = dimStyle.Render(fmt.Sprintf(" (%s → %s)", a.CurrentState, a.DesiredState))
		}

		line := fmt.Sprintf("%s%-45s %s%s", prefix, a.Name, status, change)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	return b.String()
}

func boolToStr(b bool, trueStr, falseStr string) string {
	if b {
		return trueStr
	}
	return falseStr
}

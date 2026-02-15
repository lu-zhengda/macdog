package tui

import tea "github.com/charmbracelet/bubbletea"

// Model is the main TUI model.
type Model struct {
	version string
}

// New creates a new TUI model.
func New(version string) Model {
	return Model{version: version}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the TUI.
func (m Model) View() string {
	return "macdog " + m.version + " — press q to quit\n"
}

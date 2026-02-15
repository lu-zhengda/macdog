package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/zhengda-lu/macdog/internal/tui"
)

var (
	// version is set via ldflags at build time.
	version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "macdog",
	Short: "macOS security and privacy suite",
	Long: `macdog is a macOS security and privacy suite — audit your security posture,
manage firewall rules, review privacy permissions, and harden your system
with a live TUI or handy CLI subcommands.
Launch without subcommands for interactive TUI mode.`,
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		p := tea.NewProgram(tui.New(version), tea.WithAltScreen())
		_, err := p.Run()
		return err
	},
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("macdog %s\n", version))
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

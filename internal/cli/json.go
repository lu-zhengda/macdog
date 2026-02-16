package cli

import "github.com/lu-zhengda/macdog/internal/harden"

// ---------------------------------------------------------------------------
// Action JSON type (firewall enable/disable/allow/block/import, login remove,
// privacy revoke)
// ---------------------------------------------------------------------------

// jsonAction represents the result of a mutating action command.
type jsonAction struct {
	OK     bool   `json:"ok"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// ---------------------------------------------------------------------------
// Harden result JSON type
// ---------------------------------------------------------------------------

// jsonHardenResult represents the outcome of a harden apply operation.
type jsonHardenResult struct {
	DryRun  bool                 `json:"dry_run"`
	Actions []harden.Action      `json:"actions"`
	Applied int                  `json:"applied"`
	Results []jsonHardenApplied  `json:"results,omitempty"`
}

// jsonHardenApplied represents a single applied hardening change.
type jsonHardenApplied struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

package cli

import (
	"encoding/json"
	"fmt"
	"os"
)

var jsonFlag bool

// printJSON marshals v as indented JSON and writes it to stdout.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

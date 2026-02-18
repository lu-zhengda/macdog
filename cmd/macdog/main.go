package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/lu-zhengda/macdog/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// ExitCoder: a command completed successfully but wants a specific
		// exit code (e.g., `macdog status` exits 1=warning, 2=critical).
		// Print nothing — the command already displayed its output.
		var ec cli.ExitCoder
		if errors.As(err, &ec) {
			os.Exit(ec.ExitCode())
		}
		// Real error: print and exit 1.
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/lu-zhengda/macdog/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// exitCoder lets commands communicate a specific exit code without
		// printing an error message (e.g., `macdog status` exits 1 on warning).
		var ec cli.ExitCoder
		if errors.As(err, &ec) {
			os.Exit(ec.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

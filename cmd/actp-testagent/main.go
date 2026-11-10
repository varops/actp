// Command actp-testagent is a scripted ACP agent used by actp's tests.
package main

import (
	"fmt"
	"os"

	"github.com/varops/actp/internal/testagent"
)

func main() {
	if err := testagent.Run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

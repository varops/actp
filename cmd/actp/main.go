// Command actp runs ACP agents on one machine and lets ACP clients use them from another.
//
//	actp serve                         run the server next to the agents
//	actp <agent>@<server> [options]    bridge: a local stdio ACP agent backed by a remote one
//	actp token create|list|revoke      manage client tokens
//	actp agents <server>               list the agents a server offers
//	actp doctor                        check agents and config
//	actp version
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/varops/actp/internal/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `actp – Agent Client Transport Protocol (ACP over HTTP)

Usage:
  actp serve [--config FILE] [--dashboard]
  actp tray [--config FILE] [--no-open]  server, dashboard and menu bar icon
  actp <agent>@<server> [options]        bridge to a remote agent (see "actp bridge -h")
  actp <agent>@<server> -p "text"        send one prompt and print the answer [--cwd actp://folder] [--yes|--no]
  actp bridge <agent>@<server> [options]
  actp token create --name NAME [--agents a,b] [--workspaces w,x] [--default-workspace w]
  actp token list
  actp token generate                    print a new token without saving it (for ACTP_TOKEN)
  actp token revoke NAME
  actp remote add NAME URL [--token-stdin | --token-env NAME | --token-file PATH]
  actp remote list
  actp remote remove NAME
  actp agents <server> [--token-env NAME | --token-file PATH]
  actp tunnel install                    download the pinned cloudflared into ~/.actp/bin
  actp doctor [--config FILE]
  actp container                         run in the Docker image (see "actp container -h")
  actp version
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, "actp:", err)
		os.Exit(1)
	}
}

type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func run(args []string) error {
	if len(args) == 0 {
		// Double-clicking actp.app starts the tray; the plain binary prints help.
		if inAppBundle() {
			_, err := os.Stat(config.DefaultPath())
			return runTray(context.Background(), "", os.IsNotExist(err))
		}
		fmt.Print(usage)
		return exitError(2)
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "serve":
		return cmdServe(rest)
	case "bridge":
		return cmdBridge(rest)
	case "tray":
		return cmdTray(rest)
	case "container":
		return cmdContainer(rest)
	case "token":
		return cmdToken(rest)
	case "agents":
		return cmdAgents(rest)
	case "remote":
		return cmdRemote(rest)
	case "tunnel":
		return cmdTunnel(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "version", "--version", "-v":
		fmt.Println("actp", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		if strings.Contains(cmd, "@") && !strings.HasPrefix(cmd, "-") {
			return cmdBridge(args)
		}
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// inAppBundle reports whether this binary runs from a macOS .app bundle.
func inAppBundle() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return strings.Contains(filepath.ToSlash(exe), ".app/Contents/MacOS/")
}

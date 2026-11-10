package main

import (
	"context"
	"flag"
	"os/exec"
	"runtime"
)

func cmdTray(args []string) error {
	fs := flag.NewFlagSet("tray", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file")
	noOpen := fs.Bool("no-open", false, "do not open the dashboard in the browser")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	return runTray(context.Background(), *cfgPath, !*noOpen)
}

// openBrowser opens a URL in the default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

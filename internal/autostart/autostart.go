// Package autostart starts `actp tray` when the user logs in: a LaunchAgent on
// macOS, an XDG autostart entry on Linux, the Run key on Windows.
package autostart

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Args are the arguments actp starts with at login.
var Args = []string{"tray", "--no-open"}

// Enabled reports whether actp starts at login.
func Enabled() bool { return enabled() }

// Enable makes the given actp executable start at login.
func Enable(exe string) error {
	abs, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	return enable(abs)
}

// Disable stops actp from starting at login.
func Disable() error { return disable() }

// filePath is where the login entry lives on macOS and Linux.
func filePath(goos, home, xdgConfig string) string {
	if goos == "darwin" {
		return filepath.Join(home, "Library", "LaunchAgents", "dev.actp.tray.plist")
	}
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	return filepath.Join(xdgConfig, "autostart", "actp.desktop")
}

// fileContents is the login entry for macOS (plist) or Linux (desktop file).
func fileContents(goos, exe string) string {
	if goos == "darwin" {
		var args strings.Builder
		for _, a := range append([]string{exe}, Args...) {
			fmt.Fprintf(&args, "\t\t<string>%s</string>\n", xmlEscape(a))
		}
		return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.actp.tray</string>
	<key>ProgramArguments</key>
	<array>
` + args.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`
	}
	return "[Desktop Entry]\nType=Application\nName=actp\nComment=Run ACP agents for remote clients\nExec=" +
		desktopQuote(exe) + " " + strings.Join(Args, " ") + "\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// desktopQuote quotes a path for an Exec= line in a desktop file.
func desktopQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\$`") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", "$", `\$`).Replace(s) + `"`
}

func fileTarget() string {
	home, _ := os.UserHomeDir()
	return filePath(runtime.GOOS, home, os.Getenv("XDG_CONFIG_HOME"))
}

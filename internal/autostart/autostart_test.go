package autostart

import (
	"runtime"
	"strings"
	"testing"
)

func TestEntries(t *testing.T) {
	if p := filePath("darwin", "/Users/me", ""); p != "/Users/me/Library/LaunchAgents/dev.actp.tray.plist" {
		t.Errorf("darwin path %s", p)
	}
	if p := filePath("linux", "/home/me", ""); p != "/home/me/.config/autostart/actp.desktop" {
		t.Errorf("linux path %s", p)
	}
	if p := filePath("linux", "/home/me", "/cfg"); p != "/cfg/autostart/actp.desktop" {
		t.Errorf("xdg path %s", p)
	}
	plist := fileContents("darwin", "/Applications/A & B/actp")
	if !strings.Contains(plist, "<string>/Applications/A &amp; B/actp</string>") || !strings.Contains(plist, "<string>--no-open</string>") {
		t.Errorf("plist:\n%s", plist)
	}
	desktop := fileContents("linux", "/opt/my apps/actp")
	if !strings.Contains(desktop, `Exec="/opt/my apps/actp" tray --no-open`) {
		t.Errorf("desktop:\n%s", desktop)
	}
}

func TestEnableDisable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("touches the real registry")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	if Enabled() {
		t.Fatal("enabled in a fresh home")
	}
	if err := Enable("/usr/local/bin/actp"); err != nil || !Enabled() {
		t.Fatalf("enable: %v", err)
	}
	if err := Disable(); err != nil || Enabled() {
		t.Fatalf("disable: %v", err)
	}
	if err := Disable(); err != nil {
		t.Fatalf("second disable: %v", err)
	}
}

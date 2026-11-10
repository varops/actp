// Package cliinstall puts an `actp` command on the user's PATH that points at
// the running binary, for app installs where the binary lives inside a bundle.
package cliinstall

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Status says where the actp command is and whether it points at exe.
type Status struct {
	Path    string `json:"path,omitempty"` // the actp found on PATH
	Current bool   `json:"current"`        // it is this binary
	Hint    string `json:"hint,omitempty"` // what to do if it cannot be installed
}

// Check looks for actp on a PATH (the login shell's, not the app's: apps
// started from Finder get a minimal one).
func Check(exe, path string) Status {
	for _, dir := range filepath.SplitList(path) {
		p := filepath.Join(dir, name())
		if _, err := os.Stat(p); err == nil {
			return Status{Path: p, Current: sameFile(p, exe)}
		}
	}
	return Status{}
}

func name() string {
	if runtime.GOOS == "windows" {
		return "actp.exe"
	}
	return "actp"
}

func sameFile(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// candidates are folders usually on PATH that a user can write without sudo.
func candidates(home string) []string {
	return []string{"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".local", "bin"), filepath.Join(home, "bin")}
}

// Install links actp into the first writable folder on PATH. It returns the
// link, or an error with the command to run by hand.
func Install(exe, path string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", errors.New("on Windows, add the folder that holds actp.exe to PATH")
	}
	home, _ := os.UserHomeDir()
	onPath := map[string]bool{}
	for _, dir := range filepath.SplitList(path) {
		onPath[filepath.Clean(dir)] = true
	}
	for _, dir := range candidates(home) {
		if !onPath[filepath.Clean(dir)] || !writable(dir) {
			continue
		}
		link := filepath.Join(dir, "actp")
		if info, err := os.Lstat(link); err == nil {
			if info.Mode()&os.ModeSymlink == 0 {
				return "", errors.New(link + " exists and is not a link; remove it first")
			}
			_ = os.Remove(link)
		}
		if err := os.Symlink(exe, link); err != nil {
			continue
		}
		return link, nil
	}
	return "", errors.New("no folder on your PATH is writable without an admin password. Run: sudo ln -sf " + quote(exe) + " /usr/local/bin/actp")
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".actp-check-*")
	if err != nil {
		return false
	}
	f.Close()
	_ = os.Remove(f.Name())
	return true
}

func quote(s string) string {
	if strings.ContainsAny(s, " '\"") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

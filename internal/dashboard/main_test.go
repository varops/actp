package dashboard

import (
	"os"
	"testing"
)

// TestMain gives the tests their own home folder, so a developer's real
// ~/.actp (tokens, remotes, config) never leaks into them.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "actp-test-home")
	if err != nil {
		panic(err)
	}
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA"} {
		os.Setenv(k, home)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/varops/actp/internal/config"
)

// A link that ends after Close must not write state: the folder may be gone.
func TestNoStateWritesAfterClose(t *testing.T) {
	dir := t.TempDir()
	sc := &config.Server{Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"), LogDir: filepath.Join(dir, "logs"), TokensFile: filepath.Join(dir, "tokens.yaml")}
	s, err := New(sc, Options{BaseEnv: os.Environ(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	s.recordPIDs()
	if _, err := os.Stat(s.statePath()); err != nil {
		t.Fatalf("state not written while running: %v", err)
	}
	s.Close(0)
	if _, err := os.Stat(s.statePath()); !os.IsNotExist(err) {
		t.Fatalf("state left after a clean stop: %v", err)
	}
	s.recordPIDs()
	if entries, _ := os.ReadDir(sc.StateDir); len(entries) != 0 {
		t.Fatalf("wrote state after Close: %v", entries)
	}
}

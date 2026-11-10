//go:build !windows

package autostart

import (
	"os"
	"path/filepath"
	"runtime"
)

func enabled() bool {
	_, err := os.Stat(fileTarget())
	return err == nil
}

func enable(exe string) error {
	path := fileTarget()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fileContents(runtime.GOOS, exe)), 0o644)
}

func disable() error {
	err := os.Remove(fileTarget())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

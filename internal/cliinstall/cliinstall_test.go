package cliinstall

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstallIntoAWritableFolderOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links are not used on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, ".local", "bin")
	_ = os.MkdirAll(bin, 0o755)
	t.Setenv("PATH", bin)
	exe := filepath.Join(t.TempDir(), "actp-real")
	_ = os.WriteFile(exe, []byte("x"), 0o755)

	if st := Check(exe, os.Getenv("PATH")); st.Path != "" {
		t.Fatalf("found before install: %+v", st)
	}
	link, err := Install(exe, os.Getenv("PATH"))
	if err != nil || link != filepath.Join(bin, "actp") {
		t.Fatalf("install: %s %v", link, err)
	}
	if st := Check(exe, os.Getenv("PATH")); !st.Current {
		t.Fatalf("after install: %+v", st)
	}
	if _, err := Install(exe, os.Getenv("PATH")); err != nil { // reinstall replaces the link
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir()+"/nothing")
	if _, err := Install(exe, os.Getenv("PATH")); err == nil {
		t.Fatal("installed with no writable folder on PATH")
	}
}

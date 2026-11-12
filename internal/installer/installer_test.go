package installer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeNPM puts an npm on PATH that logs its arguments and answers `ls`.
func fakeNPM(t *testing.T, fail bool) (*Installer, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake npm is a shell script")
	}
	dir := t.TempDir()
	logFile := filepath.Join(dir, "args.log")
	exit := "0"
	if fail {
		exit = "3"
	}
	script := "#!/bin/sh\necho \"$@\" >> " + logFile + "\n" +
		"if [ \"$1\" = ls ]; then echo '{\"dependencies\":{\"pi-acp\":{\"version\":\"0.0.34\"}}}'; exit 1; fi\n" +
		"echo working\nexit " + exit + "\n"
	if err := os.WriteFile(filepath.Join(dir, "npm"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	in := &Installer{Prefix: filepath.Join(dir, "prefix"), Env: func() []string { return []string{"PATH=" + dir + ":/bin:/usr/bin"} }}
	return in, logFile
}

func waitJob(t *testing.T, in *Installer) *JobView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if j := in.Job(0); j != nil && j.Done {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return nil
}

func TestInstallJob(t *testing.T) {
	in, logFile := fakeNPM(t, false)
	var done []string
	in.OnDone = func(preset, action string) { done = append(done, preset+" "+action) }
	if _, err := in.Start("pi", ActionInstall); err != nil {
		t.Fatal(err)
	}
	j := waitJob(t, in)
	if j.Error != "" || !strings.Contains(j.Output, "working") || !strings.HasSuffix(j.Output, "Done.\n") {
		t.Fatalf("job = %+v", j)
	}
	if len(done) != 1 || done[0] != "pi install" {
		t.Fatalf("OnDone calls = %v", done)
	}
	if rest := in.Job(j.Next); rest.Output != "" {
		t.Fatalf("output after the end = %q", rest.Output)
	}
	args, _ := os.ReadFile(logFile)
	want := "install -g --prefix " + in.Prefix + " --no-fund --no-audit --no-update-notifier pi-acp@latest @earendil-works/pi-coding-agent@latest"
	if !strings.Contains(string(args), want) {
		t.Fatalf("npm got %q, want %q", args, want)
	}
	if v := in.Installed(context.Background()); v["pi-acp"] != "0.0.34" {
		t.Fatalf("installed = %v", v)
	}
}

func TestFailedJobAndBusy(t *testing.T) {
	in, _ := fakeNPM(t, true)
	called := false
	in.OnDone = func(string, string) { called = true }
	if _, err := in.Start("codex", ActionRemove); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Start("pi", ActionInstall); err == nil {
		// The fake npm may already be done; only a running job must refuse.
		if j := in.Job(0); j != nil && !j.Done {
			t.Fatal("a second job started while one runs")
		}
	}
	j := waitJob(t, in)
	if j.Error == "" || called {
		t.Fatalf("failed job = %+v, OnDone called = %v", j, called)
	}
}

func TestRunAndUnknown(t *testing.T) {
	in, _ := fakeNPM(t, false)
	var out bytes.Buffer
	if err := in.Run(context.Background(), "droid", ActionInstall, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "@factory/cli@latest") {
		t.Fatalf("output %q", out.String())
	}
	if _, err := in.Start("grok", ActionInstall); err == nil {
		t.Fatal("installed a preset without a recipe")
	}
	if _, err := in.Start("pi", "explode"); err == nil {
		t.Fatal("accepted an unknown action")
	}
}

func TestNoNPM(t *testing.T) {
	in := &Installer{Env: func() []string { return []string{"PATH=" + t.TempDir()} }}
	if _, err := in.Start("pi", ActionInstall); err == nil || !strings.Contains(err.Error(), "npm") {
		t.Fatalf("err = %v", err)
	}
}

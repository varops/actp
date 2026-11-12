package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func TestSetServerListKeepsTheRestOfTheFile(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	_ = os.MkdirAll(a, 0o755)
	_ = os.MkdirAll(b, 0o755)
	path := filepath.Join(dir, "actp.yaml")
	src := "# my notes\nremotes_file: " + strconv.Quote(filepath.Join(dir, "r.yaml")) + "\nserver:\n  name: mac # comment kept\n  tokens_file: " + strconv.Quote(filepath.Join(dir, "t.yaml")) + "\n  workspaces:\n  - name: a\n    path: " + strconv.Quote(a) + "\n  agents:\n  - id: pi\n    preset: pi\n  - id: mine\n    command: my-agent\n    permissions: auto_deny\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetServerList(path, "workspaces", []Workspace{{Name: "a", Path: a}, {Name: "b", Path: b}}); err != nil {
		t.Fatal(err)
	}
	agents, err := ReadServerList(path, "agents")
	if err != nil || len(agents) != 2 {
		t.Fatalf("agents %v %v", agents, err)
	}
	agents = append(agents[1:], yaml.MapSlice{{Key: "id", Value: "droid"}, {Key: "preset", Value: "droid"}})
	if err := SetServerList(path, "agents", agents); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{"# my notes", "# comment kept", "permissions: auto_deny", "preset: droid"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %q in:\n%s", want, data)
		}
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Workspace("b") == nil || cfg.Server.Agent("pi") != nil || cfg.Server.Agent("droid") == nil || cfg.Server.Agent("mine") == nil {
		t.Fatalf("server %+v", cfg.Server)
	}
	// A change that breaks the config is refused and the file is left alone.
	before, _ := os.ReadFile(path)
	if err := SetServerList(path, "workspaces", []Workspace{{Name: "a", Path: "relative/path"}}); err == nil {
		t.Fatal("bad workspace accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("file changed after a refused edit")
	}
}

func TestSetPresetEnabledAddsMissingList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "actp.yaml")
	src := "version: 1\nserver:\n  # keep me\n  workspaces:\n  - name: w\n    path: " + filepath.ToSlash(dir) + "\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		preset  string
		on      bool
		changed bool
	}{{"pi", true, true}, {"pi", true, false}, {"codex", true, true}, {"pi", false, true}, {"pi", false, false}} {
		changed, err := SetPresetEnabled(path, step.preset, step.on)
		if err != nil || changed != step.changed {
			t.Fatalf("%s on=%v: changed=%v err=%v", step.preset, step.on, changed, err)
		}
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.Agents) != 1 || cfg.Server.Agents[0].ID != "codex" {
		t.Fatalf("agents = %+v", cfg.Server.Agents)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "# keep me") {
		t.Fatalf("comment lost:\n%s", b)
	}
}

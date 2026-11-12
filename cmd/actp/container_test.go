package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/varops/actp/internal/config"
)

func TestContainerConfig(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"Web Site", "api", ".hidden"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	ws := containerWorkspaces(root)
	if len(ws) != 2 || ws[0].Name != "web-site" || ws[1].Name != "api" { // ReadDir sorts by bytes: "W" < "a"
		t.Fatalf("workspaces = %+v", ws)
	}
	path := filepath.Join(t.TempDir(), "actp.yaml")
	if err := writeContainerConfig(path, "box", ws); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(root, "new"), 0o755)
	if err := addWorkspaces(path, containerWorkspaces(root)); err != nil {
		t.Fatal(err)
	}
	if err := addWorkspaces(path, containerWorkspaces(root)); err != nil { // nothing new: no change
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Name != "box" || len(cfg.Server.Workspaces) != 3 || cfg.Server.Workspaces[2].Name != "new" {
		t.Fatalf("server = %+v", cfg.Server)
	}
}

func TestSetEnvToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	if err := setEnvToken(path, "not-a-token"); err == nil {
		t.Fatal("accepted a malformed token")
	}
	a, _, _ := config.NewToken()
	b, _, _ := config.NewToken()
	for _, tok := range []string{a, a, b} {
		if err := setEnvToken(path, tok); err != nil {
			t.Fatal(err)
		}
	}
	tf, err := config.ReadTokensFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tf.Tokens) != 1 || tf.Tokens[0].Name != "env" || tf.Tokens[0].Hash != config.HashToken(b) {
		t.Fatalf("tokens = %+v", tf.Tokens)
	}
}

func TestContainerSmallParts(t *testing.T) {
	if got := localTarget("0.0.0.0:7860"); got != "127.0.0.1:7860" {
		t.Fatalf("localTarget = %s", got)
	}
	if got := localTarget("[::]:7860"); got != "127.0.0.1:7860" {
		t.Fatalf("localTarget = %s", got)
	}
	if got := localTarget("127.0.0.1:9"); got != "127.0.0.1:9" {
		t.Fatalf("localTarget = %s", got)
	}
	env := withoutActpVars([]string{"ACTP_TOKEN=x", "ANTHROPIC_API_KEY=k", "PATH=/bin"})
	if len(env) != 2 || env[0] != "ANTHROPIC_API_KEY=k" {
		t.Fatalf("env = %v", env)
	}
	if got := splitList(" pi, ,codex "); len(got) != 2 || got[1] != "codex" {
		t.Fatalf("splitList = %v", got)
	}
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/varops/actp/internal/config"
)

func TestResolveServer(t *testing.T) {
	cfg := &config.Config{Remotes: []config.Remote{{Name: "box", URL: "https://box.example.com"}}}
	cases := map[string]string{
		"box":                        "https://box.example.com",
		"agents.example.com":         "https://agents.example.com",
		"localhost:7860":             "http://localhost:7860",
		"127.0.0.1:7860":             "http://127.0.0.1:7860",
		"[::1]:7860":                 "http://[::1]:7860",
		"http://10.0.0.2:7860/actp":  "http://10.0.0.2:7860/actp",
		"https://agents.example.com": "https://agents.example.com",
	}
	for in, want := range cases {
		if got, _ := resolveServer(cfg, in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

func TestTokenCreateListRevoke(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "actp.yaml")
	ws := filepath.Join(dir, "site")
	_ = os.MkdirAll(ws, 0o755)
	data := "server:\n  tokens_file: " + filepath.Join(dir, "tokens.yaml") + "\n  workspaces:\n    - name: site\n      path: " + ws + "\n  agents:\n    - id: a\n      command: x\n"
	if err := os.WriteFile(cfgPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"token", "create", "--config", cfgPath, "--name", "bot", "--default-workspace", "site"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"token", "create", "--config", cfgPath, "--name", "bot"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate: %v", err)
	}
	if err := run([]string{"token", "create", "--config", cfgPath, "--name", "x", "--agents", "nope"}); err == nil {
		t.Fatal("unknown agent accepted")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.Tokens) != 1 || cfg.Server.Tokens[0].MCPServers != "remote" {
		t.Fatalf("tokens: %+v", cfg.Server.Tokens)
	}
	info, _ := os.Stat(filepath.Join(dir, "tokens.yaml"))
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("tokens file mode %v", info.Mode())
	}
	if err := run([]string{"token", "revoke", "--config", cfgPath, "bot"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(cfgPath)
	if len(cfg.Server.Tokens) != 0 {
		t.Fatal("token not revoked")
	}
}

func TestCheckListen(t *testing.T) {
	if checkListen(&config.Server{Listen: "127.0.0.1:1"}) != nil {
		t.Error("loopback refused")
	}
	if checkListen(&config.Server{Listen: "0.0.0.0:1"}) == nil {
		t.Error("public plain HTTP accepted")
	}
	if checkListen(&config.Server{Listen: "0.0.0.0:1", InsecureListen: true}) != nil {
		t.Error("insecure_listen ignored")
	}
}

func TestRemoteAddListRemove(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "actp.yaml")
	if err := os.WriteFile(cfgPath, []byte("remotes_file: "+filepath.Join(dir, "remotes.yaml")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"remote", "add", "box", "https://box.example.com/", "--config", cfgPath, "--token-env", "BOX_TOKEN"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"remote", "add", "box", "https://other", "--config", cfgPath}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := run([]string{"remote", "add", "bad", "ftp://x", "--config", cfgPath}); err == nil {
		t.Fatal("bad URL accepted")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Remote("box")
	if r == nil || r.URL != "https://box.example.com" || r.TokenEnv != "BOX_TOKEN" {
		t.Fatalf("remote: %+v", r)
	}
	if got, _ := resolveServer(cfg, "box"); got != "https://box.example.com" {
		t.Fatalf("resolve: %s", got)
	}
	if err := run([]string{"remote", "remove", "box", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(cfgPath)
	if cfg.Remote("box") != nil {
		t.Fatal("not removed")
	}
}

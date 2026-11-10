package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varops/actp/internal/config"
)

func testServerConfig(t *testing.T) (*config.Server, string) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	for _, d := range []string{"site", "site/sub", "other"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	_ = os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "site", "escape"))
	return &config.Server{Workspaces: []config.Workspace{
		{Name: "site", Path: filepath.Join(root, "site")},
		{Name: "other", Path: filepath.Join(root, "other")},
	}}, root
}

func TestResolveCwd(t *testing.T) {
	s, root := testServerConfig(t)
	tok := &config.Token{Workspaces: []string{"site"}, Map: map[string]string{"/client/repo": "site"}}
	site := filepath.Join(root, "site")
	ok := map[string]string{
		"actp://site":              site,
		"actp://site/sub":          filepath.Join(site, "sub"),
		filepath.Join(site, "sub"): filepath.Join(site, "sub"),
		"/client/repo":             site,
		"/client/repo/sub":         filepath.Join(site, "sub"),
	}
	for in, want := range ok {
		got, err := resolveCwd(s, tok, in)
		if err != nil || got != want {
			t.Errorf("%s → %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"actp://other",                // not allowed for this token
		"actp://site/../other",        // leaves the workspace
		filepath.Join(site, "escape"), // symlink out of the workspace
		filepath.Join(root, "other"),  // not allowed
		"/client/repository",          // prefix of a map key, not a match
		"/somewhere/else",             // no fallback
	}
	for _, in := range bad {
		if got, err := resolveCwd(s, tok, in); !errors.Is(err, errCwdNotAllowed) {
			t.Errorf("%s → %q, %v; want rejection", in, got, err)
		}
	}
	tok.CwdFallback, tok.DefaultWorkspace = true, "site"
	if got, err := resolveCwd(s, tok, "/somewhere/else"); err != nil || got != site {
		t.Errorf("fallback → %q, %v", got, err)
	}
}

func TestStripClientCapabilities(t *testing.T) {
	out, err := stripClientCapabilities(json.RawMessage(`{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":true},"terminal":true,"elicitation":{"form":{}}},"clientInfo":{"name":"x"}}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "fs") || strings.Contains(s, "terminal") || !strings.Contains(s, `"elicitation":{"form":{}}`) || !strings.Contains(s, `"clientInfo"`) {
		t.Fatalf("got %s", s)
	}
}

func TestStripTerminalAuth(t *testing.T) {
	out, changed := stripTerminalAuth(json.RawMessage(`{"authMethods":[{"id":"a","description":"Run x","_meta":{"terminal-auth":true}}],"agentCapabilities":{"_meta":{"terminal-auth":true,"keep":1}}}`))
	s := string(out)
	if !changed || strings.Contains(s, "terminal-auth") || !strings.Contains(s, `"description":"Run x"`) || !strings.Contains(s, `"keep":1`) {
		t.Fatalf("got %s", s)
	}
}

func TestFilterMCPServers(t *testing.T) {
	in := json.RawMessage(`[{"name":"local","command":"npx","args":[]},{"name":"web","type":"http","url":"https://mcp.example.com"},{"name":"mine","type":"sse","url":"http://127.0.0.1:9000"}]`)
	out, dropped := filterMCPServers("remote", in)
	if !strings.Contains(string(out), `"web"`) || strings.Contains(string(out), `"local"`) || strings.Contains(string(out), `"mine"`) || len(dropped) != 2 {
		t.Fatalf("remote: %s %v", out, dropped)
	}
	if out, _ := filterMCPServers("none", in); string(out) != "[]" {
		t.Fatalf("none: %s", out)
	}
	if out, dropped := filterMCPServers("all", in); len(dropped) != 0 || !strings.Contains(string(out), `"local"`) {
		t.Fatalf("all: %s", out)
	}
}

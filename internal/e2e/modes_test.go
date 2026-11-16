package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSettings writes a workspace sub folder with agent project settings, as
// Claude Code reads them from .claude/settings.json.
func (e *env) writeSettings(t *testing.T, dir, body string) string {
	t.Helper()
	d := filepath.Join(e.workspace, dir, ".claude")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "settings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return "actp://site/" + dir
}

func TestStartingModeResetTimesOut(t *testing.T) {
	e := newEnv(t) // ModeResetTimeout: 1s
	cwd := e.writeSettings(t, "silent", `{"permissions":{"defaultMode":"bypass"},"actpTest":{"ignoreSetMode":true}}`)
	c := e.bridge()
	c.initialize()
	start := time.Now()
	r := c.call("session/new", map[string]any{"cwd": cwd, "mcpServers": []any{}})
	if r.Error == nil || !strings.Contains(r.Error.Message, "session refused: it starts in mode bypassPermissions") {
		t.Fatalf("got %s", r.Raw)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("refusal took %s", d)
	}
	if !e.auditHas("mode_reset_failed") {
		t.Fatal("not audited")
	}
}

func TestRequestsWaitForTheStartingModeCheck(t *testing.T) {
	e := newEnv(t)
	cwd := e.writeSettings(t, "slow", `{"permissions":{"defaultMode":"bypass"},"actpTest":{"setModeDelayMs":300}}`)
	c := e.bridge()
	c.initialize()
	sid := c.newSession(cwd)
	// Load the session again and prompt it at once: the prompt must wait until
	// the starting mode has been switched.
	c.request("session/load", map[string]any{"sessionId": sid, "cwd": cwd, "mcpServers": []any{}})
	c.response(c.prompt(sid, "mode"))
	c.chunk("mode: default")
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		if strings.Contains(string(m.Params), "mode: bypassPermissions") {
			t.Fatalf("a request reached the agent in the refused mode: %s", m.Raw)
		}
	}
}

func TestActpIDsAreReserved(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	raw := `{"jsonrpc":"2.0","id":"actp-7","method":"session/list","params":{}}`
	if _, err := c.in.Write([]byte(raw + "\n")); err != nil {
		t.Fatal(err)
	}
	r := c.response([]byte(`"actp-7"`))
	if r.Error == nil || r.Error.Code != -32600 || !strings.Contains(r.Error.Message, `"actp-" are reserved`) {
		t.Fatalf("got %s", r.Raw)
	}
}

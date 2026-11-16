package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varops/actp/internal/jsonrpc"
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

// A large queue released while the first queued request makes the agent write
// a lot must not deadlock: the queue drains off the goroutine that reads the
// agent, which keeps reading.
func TestLargeHeldBacklogDoesNotDeadlock(t *testing.T) {
	e := newEnv(t)
	cwd := e.writeSettings(t, "backlog", `{"permissions":{"defaultMode":"bypass"},"actpTest":{"setModeDelayMs":300}}`)
	c := e.bridge()
	c.initialize()
	sid := c.newSession(cwd)
	big := strings.Repeat("x", 300<<10)
	c.response(c.prompt(sid, "echo "+big)) // the session history now holds 300 KB
	load := map[string]any{"sessionId": sid, "cwd": cwd, "mcpServers": []any{}}
	first := c.request("session/load", load)
	second := c.request("session/load", load) // replays 300 KB while the queue drains
	pad := strings.Repeat("p", 2<<10)
	var ids []json.RawMessage
	for i := 0; i < 150; i++ {
		ids = append(ids, c.request("session/set_title", map[string]any{"sessionId": sid, "title": pad}))
	}
	c.response(first)
	c.response(second)
	for _, id := range ids {
		c.response(id)
	}
}

func TestHeldQueueIsBounded(t *testing.T) {
	e := newEnv(t) // MaxHeldMessages: 200
	cwd := e.writeSettings(t, "bounded", `{"permissions":{"defaultMode":"bypass"},"actpTest":{"setModeDelayMs":500}}`)
	c := e.bridge()
	c.initialize()
	sid := c.newSession(cwd)
	c.request("session/load", map[string]any{"sessionId": sid, "cwd": cwd, "mcpServers": []any{}})
	var ids []json.RawMessage
	for i := 0; i < 205; i++ {
		ids = append(ids, c.request("session/set_title", map[string]any{"sessionId": sid, "title": "t"}))
	}
	busy := 0
	for _, id := range ids {
		if r := c.response(id); r.Error != nil && strings.HasPrefix(r.Error.Message, "session busy:") {
			busy++
		}
	}
	if busy != 5 {
		t.Fatalf("%d requests refused, want 5", busy)
	}
	if !e.auditHas("held_overflow") {
		t.Fatal("not audited")
	}
}

func TestHeldLoadTimesOut(t *testing.T) {
	e := newEnv(t) // HeldLoadTimeout: 2s
	cwd := e.writeSettings(t, "slowload", `{"actpTest":{"loadDelayMs":4000}}`)
	c := e.bridge()
	c.initialize()
	sid := c.newSession(cwd)
	load := c.request("session/load", map[string]any{"sessionId": sid, "cwd": cwd, "mcpServers": []any{}})
	prompt := c.prompt(sid, "echo waiting")
	for _, id := range []json.RawMessage{load, prompt} {
		if r := c.response(id); r.Error == nil || r.Error.Message != "session refused: the agent did not answer in time" {
			t.Fatalf("got %s", r.Raw)
		}
	}
	time.Sleep(3 * time.Second) // the agent's late answer to the load is dropped
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.msgs {
		if m.Kind() == jsonrpc.KindResponse && m.IDKey() == string(load) {
			n++
		}
	}
	if n != 1 || !e.auditHas("load_timed_out") {
		t.Fatalf("%d answers to the load", n)
	}
}

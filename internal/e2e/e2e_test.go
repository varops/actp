package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/varops/actp/internal/bridge"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/jsonrpc"
	"github.com/varops/actp/internal/server"
)

func TestBasicTurn(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	id := c.prompt(sid, "echo hello there")
	c.chunk("hello there")
	if r := c.response(id); stopReason(r) != "end_turn" {
		t.Fatalf("stop reason %s", r.Raw)
	}
	c.closeStdin()
	if err := c.wait(); err != nil {
		t.Fatalf("bridge exit: %v", err)
	}
}

func TestClientCapabilitiesAreStripped(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.prompt(sid, "caps")
	m := c.chunk("elicitation")
	if strings.Contains(string(m.Params), "readTextFile") || strings.Contains(string(m.Params), "terminal") {
		t.Fatalf("fs or terminal reached the agent: %s", m.Params)
	}
}

func TestFilesAndTerminalsStayOnTheAgentHost(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	id := c.prompt(sid, "fs")
	c.chunk(fmt.Sprintf("fs: error %d", jsonrpc.CodeMethodNotFound))
	c.response(id)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		if strings.HasPrefix(m.Method, "fs/") {
			t.Fatalf("client received %s", m.Raw)
		}
	}
}

func TestCwdResolution(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("/client/repo")
	c.prompt(sid, "cwd")
	c.chunk(e.workspace)

	r := c.call("session/new", map[string]any{"cwd": "/somewhere/else", "mcpServers": []any{}})
	if r.Error == nil || r.Error.Code != jsonrpc.CodeInvalidParams || !strings.Contains(r.Error.Message, "cwd not allowed") {
		t.Fatalf("got %s", r.Raw)
	}
}

func TestBridgeCwdOverride(t *testing.T) {
	e := newEnv(t)
	c := e.bridge(func(o *bridge.Options) { o.Cwd = "actp://site" })
	c.initialize()
	sid := c.newSession("/anything/on/the/client")
	c.prompt(sid, "cwd")
	c.chunk(e.workspace)
}

func TestMCPServersAreFiltered(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	r := c.call("session/new", map[string]any{"cwd": "actp://site", "mcpServers": []any{
		map[string]any{"name": "local", "command": "npx", "args": []any{}, "env": []any{}},
		map[string]any{"name": "web", "type": "http", "url": "https://mcp.example.com", "headers": []any{}},
	}})
	var res struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(r.Result, &res)
	c.prompt(res.SessionID, "mcp")
	m := c.chunk("mcp.example.com")
	if strings.Contains(string(m.Params), "npx") {
		t.Fatalf("stdio MCP server reached the agent: %s", m.Params)
	}
}

func TestPermissionRoundTrip(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	id := c.prompt(sid, "permission")
	req := c.waitMsg("permission request", func(m *jsonrpc.Message) bool { return m.Method == "session/request_permission" })
	c.send(jsonrpc.NewResult(req.ID, map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": "allow"}}))
	c.chunk(`\"optionId\":\"allow\"`)
	c.response(id)
}

func TestPermissionPolicyAutoDeny(t *testing.T) {
	e := newEnv(t, func(s *config.Server) { s.Agents[0].Permissions = "auto_deny" })
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.prompt(sid, "permission")
	c.chunk(`\"optionId\":\"deny\"`)
}

func TestAuthAndManagementEndpoints(t *testing.T) {
	e := newEnv(t)
	get := func(path, token string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", e.http.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf strings.Builder
		_, _ = fmt.Fprint(&buf, mustRead(resp))
		return resp, buf.String()
	}
	if resp, _ := get("/health", ""); resp.StatusCode != 200 {
		t.Fatalf("/health %d", resp.StatusCode)
	}
	for _, p := range []string{"/api/v1/info", "/api/v1/agents", "/actp/v1/agents/test/link"} {
		if resp, _ := get(p, ""); resp.StatusCode != 401 {
			t.Fatalf("%s without token: %d", p, resp.StatusCode)
		}
		if resp, _ := get(p, "actp_wrong"); resp.StatusCode != 401 {
			t.Fatalf("%s with wrong token: %d", p, resp.StatusCode)
		}
	}
	resp, body := get("/api/v1/info", testToken)
	if resp.StatusCode != 200 || !strings.Contains(body, `"actp.v1"`) {
		t.Fatalf("info: %d %s", resp.StatusCode, body)
	}
	resp, body = get("/api/v1/agents", testToken)
	if resp.StatusCode != 200 || !strings.Contains(body, `"id":"test"`) || !strings.Contains(body, `"default":true`) {
		t.Fatalf("agents: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get("/actp/v1/agents/test/link", testToken); resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET on link: %d", resp.StatusCode)
	}
	if resp, _ := get("/actp/v1/agents/nope/link", testToken); resp.StatusCode != 404 {
		t.Fatalf("unknown agent: %d", resp.StatusCode)
	}
}

func mustRead(resp *http.Response) string {
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

func TestResumeAfterDropLosesNothing(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	id := c.prompt(sid, "slow 20")
	c.chunk("chunk 3")
	e.proxy.drop() // drop every TCP connection mid-turn
	r := c.response(id)
	if stopReason(r) != "end_turn" {
		t.Fatalf("stop: %s", r.Raw)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var got []string
	for _, m := range c.msgs {
		if m.Method == "session/update" {
			var p struct {
				Update struct {
					Content struct{ Text string } `json:"content"`
				} `json:"update"`
			}
			_ = json.Unmarshal(m.Params, &p)
			got = append(got, p.Update.Content.Text)
		}
	}
	for i := 1; i <= 20; i++ {
		if i > len(got) || got[i-1] != fmt.Sprintf("chunk %d", i) {
			t.Fatalf("chunks out of order, lost or doubled: %v", got)
		}
	}
	if len(got) != 20 {
		t.Fatalf("got %d chunks: %v", len(got), got)
	}
	if !e.auditHas("link_resumed") {
		t.Fatal("the connection was never resumed: the drop did not happen")
	}
}

func TestSilentDropIsDetectedAndResumed(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	id := c.prompt(sid, "slow 20")
	c.chunk("chunk 2")
	e.proxy.freeze() // no FIN, no RST: only heartbeats can tell
	if r := c.response(id); stopReason(r) != "end_turn" {
		t.Fatalf("stop: %s", r.Raw)
	}
	c.chunk("chunk 20")
	if !e.auditHas("link_resumed") {
		t.Fatal("silent drop was not detected")
	}
}

func waitNoLinks(t *testing.T, srv *server.Server) {
	t.Helper()
	waitUntil(t, "all links to end", func() bool { return len(srv.Links()) == 0 })
}

func TestClientQuitFinishesTheTurn(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.prompt(sid, "slow 8")
	c.chunk("chunk 1")
	c.closeStdin()
	if err := c.wait(); err != nil {
		t.Fatalf("bridge exit: %v", err)
	}
	waitUntil(t, "link to be unattended", func() bool {
		l := e.srv.Links()
		return len(l) == 0 || l[0].State == server.StateUnattended
	})
	waitNoLinks(t, e.srv)

	c2 := e.bridge()
	c2.initialize()
	r := c2.call("session/load", map[string]any{"sessionId": sid, "cwd": "actp://site", "mcpServers": []any{}})
	if r.Error != nil {
		t.Fatalf("load: %s", r.Raw)
	}
	c2.chunk("chunk 8") // the turn finished while nobody was connected
}

func TestClientQuitWithCancelPolicy(t *testing.T) {
	e := newEnv(t, func(s *config.Server) { s.Agents[0].OnClientExit = "cancel" })
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.prompt(sid, "slow 100")
	c.chunk("chunk 1")
	c.closeStdin()
	_ = c.wait()
	start := time.Now()
	waitNoLinks(t, e.srv)
	if time.Since(start) > 3*time.Second {
		t.Fatalf("cancel took %s", time.Since(start))
	}
}

func TestUnattendedTurnIsCapped(t *testing.T) {
	e := newEnv(t) // max_unattended: 1s
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.prompt(sid, "slow 200")
	c.chunk("chunk 1")
	c.closeStdin()
	_ = c.wait()
	start := time.Now()
	waitNoLinks(t, e.srv)
	if time.Since(start) > 4*time.Second {
		t.Fatalf("unattended turn ran %s", time.Since(start))
	}
}

func TestUnattendedPermissionIsCancelledAtOnce(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.prompt(sid, "permission")
	c.waitMsg("permission request", func(m *jsonrpc.Message) bool { return m.Method == "session/request_permission" })
	c.closeStdin()
	_ = c.wait()
	waitNoLinks(t, e.srv)

	c2 := e.bridge()
	c2.initialize()
	c2.call("session/load", map[string]any{"sessionId": sid, "cwd": "actp://site", "mcpServers": []any{}})
	c2.chunk(`cancelled`)
}

func TestAgentCrashEndsTheSession(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	id := c.prompt(sid, "crash")
	r := c.response(id)
	if r.Error == nil || !strings.Contains(r.Error.Message, "remote session lost") {
		t.Fatalf("got %s", r.Raw)
	}
	var lost *bridge.LostError
	if err := c.wait(); !errors.As(err, &lost) || !strings.Contains(lost.Reason, "crashing on purpose") {
		t.Fatalf("bridge exit: %v", err)
	}
}

func TestLinkLimit(t *testing.T) {
	e := newEnv(t, func(s *config.Server) { s.Agents[0].MaxLinks = 1 })
	c := e.bridge()
	c.initialize()
	c2 := e.bridge()
	err := c2.wait()
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("second bridge: %v", err)
	}
}

func TestBadTokenFailsFast(t *testing.T) {
	e := newEnv(t)
	c := e.bridge(func(o *bridge.Options) { o.Token = "actp_wrong" })
	if err := c.wait(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("got %v", err)
	}
}

func TestAuthRequiredIsReported(t *testing.T) {
	e := newEnv(t, func(s *config.Server) { s.Agents[0].Env["ACTP_TESTAGENT_SCENARIO"] = "auth-required" })
	c := e.bridge()
	r := c.call("initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}})
	if strings.Contains(string(r.Result), "terminal-auth") {
		t.Fatalf("terminal-auth hint reached the client: %s", r.Result)
	}
	if r := c.call("session/new", map[string]any{"cwd": "actp://site", "mcpServers": []any{}}); r.Error == nil {
		t.Fatal("expected auth error")
	}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", e.http.URL+"/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := mustRead(resp); !strings.Contains(body, `"status":"auth_required"`) {
		t.Fatalf("agents: %s", body)
	}
}

func TestQuickRestartLoadsTheSession(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")
	c.response(c.prompt(sid, "echo before restart"))
	c.closeStdin()
	_ = c.wait()

	c2 := e.bridge() // no pause: the old link may still be closing
	c2.initialize()
	r := c2.call("session/load", map[string]any{"sessionId": sid, "cwd": "actp://site", "mcpServers": []any{}})
	if r.Error != nil {
		t.Fatalf("load right after restart: %s", r.Raw)
	}
	c2.chunk("before restart")
}

func TestProbe(t *testing.T) {
	e := newEnv(t)
	if status, detail := e.srv.Probe(&e.cfg.Agents[0]); status != "ready" {
		t.Fatalf("probe: %s %s", status, detail)
	}
	e.cfg.Agents[0].Command = "/nonexistent/agent"
	if status, _ := e.srv.Probe(&e.cfg.Agents[0]); status != "unavailable" {
		t.Fatalf("missing agent probed as %s", status)
	}
}

func TestReloadRevokesTokens(t *testing.T) {
	e := newEnv(t)
	c := e.bridge()
	c.initialize()
	sid := c.newSession("actp://site")

	next := *e.cfg
	next.Tokens = nil
	e.srv.Reload(&next)

	req, _ := http.NewRequest("GET", e.http.URL+"/api/v1/info", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token got %d", resp.StatusCode)
	}
	// The open link keeps working until it drops; then it cannot come back.
	c.response(c.prompt(sid, "echo still here"))
	e.proxy.drop()
	var lost *bridge.LostError
	if err := c.wait(); !errors.As(err, &lost) {
		t.Fatalf("bridge after revoke: %v", err)
	}
}

// Package e2e runs a stdio ACP client against the bridge, the server and the scripted agent.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varops/actp/internal/bridge"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/jsonrpc"
	"github.com/varops/actp/internal/server"
	"github.com/varops/actp/internal/wire"
)

var agentBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "actp-e2e")
	if err != nil {
		panic(err)
	}
	agentBin = filepath.Join(dir, "actp-testagent")
	if runtime.GOOS == "windows" {
		agentBin += ".exe"
	}
	out, err := exec.Command("go", "build", "-o", agentBin, "github.com/varops/actp/cmd/actp-testagent").CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("building test agent: %v\n%s", err, out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const testToken = "actp_testtoken"

var fastWire = wire.Options{HeartbeatEvery: 50 * time.Millisecond, DeadAfter: 400 * time.Millisecond, AckDelay: 20 * time.Millisecond, Tick: 10 * time.Millisecond}

type env struct {
	t         *testing.T
	cfg       *config.Server
	srv       *server.Server
	http      *httptest.Server
	workspace string
	store     string
}

type envOption func(*config.Server)

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	ws := filepath.Join(root, "site")
	store := filepath.Join(root, "store")
	_ = os.MkdirAll(ws, 0o755)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
server:
  idle_close: 1s
  prompt_timeout: 2s
  log_dir: %q
  state_dir: %q
  tokens_file: %q
  workspaces:
    - name: site
      path: %q
  agents:
    - id: test
      command: %q
      env:
        ACTP_TESTAGENT_STORE: %q
      max_unattended: 1s
  tokens:
    - name: tester
      hash: %q
      agents: ["*"]
      workspaces: ["*"]
      default_workspace: site
      map:
        /client/repo: site
`, filepath.Join(root, "logs"), filepath.Join(root, "state"), filepath.Join(root, "tokens.yaml"), ws, agentBin, store, config.HashToken(testToken))))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range opts {
		o(cfg.Server)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg.Server, server.Options{
		Version: "test", BaseEnv: os.Environ(), Wire: fastWire, Tick: 20 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(srv.Handler())
	e := &env{t: t, cfg: cfg.Server, srv: srv, http: h, workspace: ws, store: store}
	t.Cleanup(func() {
		h.CloseClientConnections()
		srv.Close(0)
		h.Close()
	})
	return e
}

// client is a stdio ACP client driving one bridge.
type client struct {
	t      *testing.T
	in     *io.PipeWriter
	out    *jsonrpc.Writer
	done   chan error
	nextID int

	mu      sync.Mutex
	cond    *sync.Cond
	msgs    []*jsonrpc.Message
	stdinCl sync.Once
}

func (e *env) bridge(opts ...func(*bridge.Options)) *client {
	e.t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{t: e.t, in: inW, out: jsonrpc.NewWriter(inW), done: make(chan error, 1)}
	c.cond = sync.NewCond(&c.mu)
	o := bridge.Options{Agent: "test", BaseURL: e.http.URL, Token: testToken, ClientName: "e2e", Wire: fastWire, MaxBackoff: 100 * time.Millisecond, GiveUpAfter: 3 * time.Second}
	for _, f := range opts {
		f(&o)
	}
	go func() {
		err := bridge.Run(context.Background(), o, inR, outW)
		outW.Close()
		c.done <- err
	}()
	go func() {
		rd := jsonrpc.NewReader(outR)
		for {
			m, _, err := rd.Read()
			if err != nil {
				if m == nil {
					c.mu.Lock()
					c.cond.Broadcast()
					c.mu.Unlock()
					if err == io.EOF || strings.Contains(err.Error(), "closed pipe") {
						return
					}
					continue
				}
			}
			c.mu.Lock()
			c.msgs = append(c.msgs, m)
			c.cond.Broadcast()
			c.mu.Unlock()
		}
	}()
	e.t.Cleanup(c.closeStdin)
	return c
}

func (c *client) closeStdin() { c.stdinCl.Do(func() { c.in.Close() }) }

// request sends a request and returns its id.
func (c *client) request(method string, params any) json.RawMessage {
	c.t.Helper()
	c.nextID++
	id := json.RawMessage(fmt.Sprint(c.nextID))
	m, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := c.out.Write(m); err != nil {
		c.t.Fatal(err)
	}
	return id
}

func (c *client) send(m *jsonrpc.Message) {
	c.t.Helper()
	if err := c.out.Write(m); err != nil {
		c.t.Fatal(err)
	}
}

// waitMsg waits for a message matching f.
func (c *client) waitMsg(what string, f func(*jsonrpc.Message) bool) *jsonrpc.Message {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	timer := time.AfterFunc(10*time.Second, func() { c.mu.Lock(); c.cond.Broadcast(); c.mu.Unlock() })
	defer timer.Stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := 0
	for {
		for ; seen < len(c.msgs); seen++ {
			if f(c.msgs[seen]) {
				return c.msgs[seen]
			}
		}
		if time.Now().After(deadline) {
			var got []string
			for _, m := range c.msgs {
				got = append(got, string(m.Raw))
			}
			c.t.Fatalf("timed out waiting for %s; got:\n%s", what, strings.Join(got, "\n"))
		}
		c.cond.Wait()
	}
}

func (c *client) response(id json.RawMessage) *jsonrpc.Message {
	c.t.Helper()
	return c.waitMsg("response "+string(id), func(m *jsonrpc.Message) bool {
		return m.Kind() == jsonrpc.KindResponse && m.IDKey() == string(id)
	})
}

func (c *client) call(method string, params any) *jsonrpc.Message {
	c.t.Helper()
	return c.response(c.request(method, params))
}

func (c *client) chunk(text string) *jsonrpc.Message {
	c.t.Helper()
	return c.waitMsg("chunk "+text, func(m *jsonrpc.Message) bool {
		return m.Method == "session/update" && strings.Contains(string(m.Params), text)
	})
}

func (c *client) initialize() {
	c.t.Helper()
	r := c.call("initialize", map[string]any{
		"protocolVersion": 1,
		"clientCapabilities": map[string]any{
			"fs": map[string]any{"readTextFile": true}, "terminal": true, "elicitation": map[string]any{"form": map[string]any{}},
		},
	})
	if r.Error != nil {
		c.t.Fatalf("initialize: %v", r.Error)
	}
}

func (c *client) newSession(cwd string) string {
	c.t.Helper()
	r := c.call("session/new", map[string]any{"cwd": cwd, "mcpServers": []any{}})
	if r.Error != nil {
		c.t.Fatalf("session/new: %v", r.Error)
	}
	var res struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(r.Result, &res)
	return res.SessionID
}

func (c *client) prompt(sessionID, text string) json.RawMessage {
	return c.request("session/prompt", map[string]any{"sessionId": sessionID, "prompt": []any{map[string]any{"type": "text", "text": text}}})
}

func stopReason(m *jsonrpc.Message) string {
	var r struct {
		StopReason string `json:"stopReason"`
	}
	_ = json.Unmarshal(m.Result, &r)
	return r.StopReason
}

func (c *client) wait() error {
	select {
	case err := <-c.done:
		return err
	case <-time.After(10 * time.Second):
		c.t.Fatal("bridge did not exit")
		return nil
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

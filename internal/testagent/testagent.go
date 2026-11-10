// Package testagent is a scripted ACP agent for tests. It speaks ACP over stdio
// and reacts to commands in the prompt text:
//
//	echo <text>     reply with <text>
//	slow <n>        send n chunks, 100 ms apart
//	permission      ask the client for permission, reply with the outcome
//	ask             send an elicitation, reply with the answer
//	fs              call fs/read_text_file, reply with the result or error
//	caps            reply with the client capabilities from initialize
//	cwd             reply with the session cwd
//	mcp             reply with the session MCP servers
//	crash           exit with code 3
//
// Sessions are stored as files under $ACTP_TESTAGENT_STORE so session/load
// works from a fresh process. With ACTP_TESTAGENT_SCENARIO=auth-required,
// session/new fails with an authentication error.
package testagent

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/varops/actp/internal/jsonrpc"
)

type session struct {
	ID         string          `json:"id"`
	Cwd        string          `json:"cwd"`
	MCPServers json.RawMessage `json:"mcpServers"`
	History    []string        `json:"history"`
}

type agent struct {
	out      *jsonrpc.Writer
	store    string
	scenario string

	mu         sync.Mutex
	clientCaps json.RawMessage
	sessions   map[string]*session
	running    map[string]chan struct{} // sessionId → cancel
	pending    map[string]chan *jsonrpc.Message
	nextID     int
}

// Run serves ACP on r/w until r closes.
func Run(r io.Reader, w io.Writer) error {
	a := &agent{
		out:      jsonrpc.NewWriter(w),
		store:    os.Getenv("ACTP_TESTAGENT_STORE"),
		scenario: os.Getenv("ACTP_TESTAGENT_SCENARIO"),
		sessions: map[string]*session{},
		running:  map[string]chan struct{}{},
		pending:  map[string]chan *jsonrpc.Message{},
	}
	if a.store == "" {
		a.store = filepath.Join(os.TempDir(), "actp-testagent")
	}
	_ = os.MkdirAll(a.store, 0o700)
	rd := jsonrpc.NewReader(r)
	var wg sync.WaitGroup
	for {
		m, _, err := rd.Read()
		if err != nil {
			if err == io.EOF {
				wg.Wait()
				return nil
			}
			if m == nil && strings.HasPrefix(err.Error(), "invalid message") {
				continue
			}
			return err
		}
		switch m.Kind() {
		case jsonrpc.KindResponse:
			a.mu.Lock()
			ch := a.pending[m.IDKey()]
			delete(a.pending, m.IDKey())
			a.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case jsonrpc.KindNotification:
			if m.Method == "session/cancel" {
				var p struct {
					SessionID string `json:"sessionId"`
				}
				_ = json.Unmarshal(m.Params, &p)
				a.mu.Lock()
				if ch := a.running[p.SessionID]; ch != nil {
					close(ch)
					delete(a.running, p.SessionID)
				}
				a.mu.Unlock()
			}
		case jsonrpc.KindRequest:
			if m.Method == "session/prompt" {
				wg.Add(1)
				go func() { defer wg.Done(); a.prompt(m) }()
				continue
			}
			a.handle(m)
		}
	}
}

func (a *agent) send(m *jsonrpc.Message) { _ = a.out.Write(m) }

func (a *agent) handle(m *jsonrpc.Message) {
	switch m.Method {
	case "initialize":
		var p struct {
			ClientCapabilities json.RawMessage `json:"clientCapabilities"`
		}
		_ = json.Unmarshal(m.Params, &p)
		a.mu.Lock()
		a.clientCaps = p.ClientCapabilities
		a.mu.Unlock()
		a.send(jsonrpc.NewResult(m.ID, map[string]any{
			"protocolVersion": 1,
			"agentCapabilities": map[string]any{
				"loadSession":         true,
				"sessionCapabilities": map[string]any{"close": map[string]any{}, "list": map[string]any{}},
			},
			"agentInfo": map[string]any{"name": "actp-testagent", "version": "1.0.0"},
			"authMethods": []any{map[string]any{
				"id": "login", "name": "Login", "description": "Run `testagent login` on the agent host",
				"_meta": map[string]any{"terminal-auth": true},
			}},
		}))
	case "session/new", "session/load", "session/resume":
		if a.scenario == "auth-required" {
			a.send(jsonrpc.NewError(m.ID, jsonrpc.CodeServerError, "Authentication required", nil))
			return
		}
		var p struct {
			SessionID  string          `json:"sessionId"`
			Cwd        string          `json:"cwd"`
			MCPServers json.RawMessage `json:"mcpServers"`
		}
		_ = json.Unmarshal(m.Params, &p)
		s := &session{ID: p.SessionID, Cwd: p.Cwd, MCPServers: p.MCPServers}
		if m.Method == "session/new" {
			s.ID = fmt.Sprintf("s-%d", time.Now().UnixNano())
		} else {
			stored, err := a.load(p.SessionID)
			if err != nil {
				a.send(jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidParams, "unknown session", nil))
				return
			}
			s.History = stored.History
			if m.Method == "session/load" {
				for _, text := range s.History {
					a.chunk(s.ID, text)
				}
			}
		}
		a.mu.Lock()
		a.sessions[s.ID] = s
		a.mu.Unlock()
		a.save(s)
		if m.Method == "session/new" {
			a.send(jsonrpc.NewResult(m.ID, map[string]any{"sessionId": s.ID}))
		} else {
			a.send(jsonrpc.NewResult(m.ID, map[string]any{}))
		}
	case "session/list":
		entries, _ := os.ReadDir(a.store)
		var list []map[string]any
		for _, e := range entries {
			if s, err := a.load(strings.TrimSuffix(e.Name(), ".json")); err == nil {
				list = append(list, map[string]any{"sessionId": s.ID, "cwd": s.Cwd})
			}
		}
		a.send(jsonrpc.NewResult(m.ID, map[string]any{"sessions": list}))
	case "session/close":
		a.send(jsonrpc.NewResult(m.ID, map[string]any{}))
	default:
		a.send(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "Method not found", nil))
	}
}

func (a *agent) prompt(m *jsonrpc.Message) {
	var p struct {
		SessionID string `json:"sessionId"`
		Prompt    []struct {
			Text string `json:"text"`
		} `json:"prompt"`
	}
	_ = json.Unmarshal(m.Params, &p)
	a.mu.Lock()
	s := a.sessions[p.SessionID]
	if s == nil {
		a.mu.Unlock()
		a.send(jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidParams, "unknown session", nil))
		return
	}
	if a.running[s.ID] != nil {
		a.mu.Unlock()
		a.send(jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidRequest, "a turn is already running", nil))
		return
	}
	cancel := make(chan struct{})
	a.running[s.ID] = cancel
	a.mu.Unlock()

	text := ""
	for _, block := range p.Prompt {
		text += block.Text
	}
	cmd, arg, _ := strings.Cut(strings.TrimSpace(text), " ")
	reply := func(t string) {
		a.chunk(s.ID, t)
		a.mu.Lock()
		s.History = append(s.History, t)
		a.mu.Unlock()
	}
	stop := "end_turn"
	switch cmd {
	case "echo":
		reply(arg)
	case "slow":
		n, _ := strconv.Atoi(arg)
		for i := 1; i <= n; i++ {
			select {
			case <-cancel:
				stop = "cancelled"
			case <-time.After(100 * time.Millisecond):
				reply(fmt.Sprintf("chunk %d", i))
				continue
			}
			break
		}
	case "permission":
		resp := a.request("session/request_permission", map[string]any{
			"sessionId": s.ID,
			"toolCall":  map[string]any{"toolCallId": "t1", "title": "Write file"},
			"options": []any{
				map[string]any{"optionId": "allow", "name": "Allow", "kind": "allow_once"},
				map[string]any{"optionId": "deny", "name": "Deny", "kind": "reject_once"},
			},
		}, cancel)
		reply("permission: " + describe(resp))
	case "ask":
		resp := a.request("elicitation/create", map[string]any{"sessionId": s.ID, "mode": "form", "message": "Pick", "requestedSchema": map[string]any{"type": "object"}}, cancel)
		reply("ask: " + describe(resp))
	case "fs":
		resp := a.request("fs/read_text_file", map[string]any{"sessionId": s.ID, "path": "/etc/hostname"}, cancel)
		reply("fs: " + describe(resp))
	case "caps":
		a.mu.Lock()
		caps := string(a.clientCaps)
		a.mu.Unlock()
		reply(caps)
	case "cwd":
		reply(s.Cwd)
	case "mcp":
		reply(string(s.MCPServers))
	case "crash":
		fmt.Fprintln(os.Stderr, "testagent: crashing on purpose")
		os.Exit(3)
	default:
		reply("unknown command: " + text)
	}
	select {
	case <-cancel:
		stop = "cancelled"
	default:
	}
	a.mu.Lock()
	delete(a.running, s.ID)
	a.mu.Unlock()
	a.save(s)
	a.send(jsonrpc.NewResult(m.ID, map[string]any{"stopReason": stop}))
}

func (a *agent) chunk(sessionID, text string) {
	n, _ := jsonrpc.NewNotification("session/update", map[string]any{
		"sessionId": sessionID,
		"update": map[string]any{
			"sessionUpdate": "agent_message_chunk",
			"content":       map[string]any{"type": "text", "text": text},
		},
	})
	a.send(n)
}

// request sends an agent→client request and waits for the answer or a cancel.
func (a *agent) request(method string, params any, cancel chan struct{}) *jsonrpc.Message {
	a.mu.Lock()
	a.nextID++
	id := json.RawMessage(fmt.Sprintf(`"agent-%d"`, a.nextID))
	ch := make(chan *jsonrpc.Message, 1)
	a.pending[string(id)] = ch
	a.mu.Unlock()
	m, _ := jsonrpc.NewRequest(id, method, params)
	a.send(m)
	select {
	case resp := <-ch:
		return resp
	case <-cancel:
		return nil
	}
}

func describe(m *jsonrpc.Message) string {
	switch {
	case m == nil:
		return "turn cancelled"
	case m.Error != nil:
		return fmt.Sprintf("error %d", m.Error.Code)
	default:
		return string(m.Result)
	}
}

func (a *agent) save(s *session) {
	a.mu.Lock()
	data, _ := json.Marshal(s)
	a.mu.Unlock()
	_ = os.WriteFile(filepath.Join(a.store, s.ID+".json"), data, 0o600)
}

func (a *agent) load(id string) (*session, error) {
	if strings.ContainsAny(id, `/\`) || id == "" {
		return nil, fmt.Errorf("bad id")
	}
	data, err := os.ReadFile(filepath.Join(a.store, id+".json"))
	if err != nil {
		return nil, err
	}
	var s session
	return &s, json.Unmarshal(data, &s)
}

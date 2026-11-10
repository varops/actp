package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/varops/actp/internal/bridge"
	"github.com/varops/actp/internal/jsonrpc"
	"github.com/varops/actp/internal/wire"
)

// rawLink drives a link directly, so tests can drop it without a bye and never come back.
type rawLink struct {
	t      *testing.T
	e      *env
	ep     *wire.Endpoint
	id     string
	mu     sync.Mutex
	got    []*jsonrpc.Message
	served chan error
	nextID int
}

func (e *env) raw() *rawLink {
	r := &rawLink{t: e.t, e: e}
	r.ep = wire.NewEndpoint(fastWire, func(raw json.RawMessage) error {
		m, err := jsonrpc.Parse(raw)
		if err == nil {
			r.mu.Lock()
			r.got = append(r.got, m)
			r.mu.Unlock()
		}
		return nil
	})
	r.connect("")
	return r
}

func (r *rawLink) connect(linkID string) (*http.Response, error) {
	u, _ := bridge.LinkURL(r.e.http.URL, "test")
	h := http.Header{}
	h.Set("Authorization", "Bearer "+testToken)
	if linkID != "" {
		h.Set(wire.HeaderLinkID, linkID)
		h.Set(wire.HeaderLastSeq, strconv.FormatInt(r.ep.LastReceived(), 10))
	}
	conn, resp, err := websocket.Dial(context.Background(), u, &websocket.DialOptions{HTTPHeader: h, Subprotocols: wire.Versions})
	if err != nil {
		return resp, err
	}
	r.id = resp.Header.Get(wire.HeaderLinkID)
	last, _ := strconv.ParseInt(resp.Header.Get(wire.HeaderLastSeq), 10, 64)
	r.served = make(chan error, 1)
	go func() { r.served <- r.ep.Serve(context.Background(), conn, last) }()
	return resp, nil
}

func (r *rawLink) call(method string, params any) *jsonrpc.Message {
	r.t.Helper()
	r.nextID++
	id := json.RawMessage(strconv.Itoa(r.nextID))
	m, _ := jsonrpc.NewRequest(id, method, params)
	r.ep.Send(m.Raw)
	var found *jsonrpc.Message
	waitUntil(r.t, method+" response", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, g := range r.got {
			if g.Kind() == jsonrpc.KindResponse && g.IDKey() == string(id) {
				found = g
				return true
			}
		}
		return false
	})
	return found
}

func (r *rawLink) waitChunk(text string) {
	r.t.Helper()
	waitUntil(r.t, text, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, g := range r.got {
			if g.Method == "session/update" && strings.Contains(string(g.Params), text) {
				return true
			}
		}
		return false
	})
}

func (r *rawLink) drop() {
	r.ep.Detach(websocket.StatusGoingAway, "test drop")
	<-r.served
}

func TestDetachedIdleLinkClosesAndCannotResume(t *testing.T) {
	e := newEnv(t) // idle_close: 1s
	r := e.raw()
	r.call("initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}})
	r.call("session/new", map[string]any{"cwd": "actp://site", "mcpServers": []any{}})
	r.drop()
	waitUntil(t, "link detached", func() bool {
		l := e.srv.Links()
		return len(l) == 1 && l[0].State == "detached"
	})
	start := time.Now()
	waitNoLinks(t, e.srv)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("idle link lived %s", d)
	}
	resp, err := r.connect(r.id)
	if err == nil || resp == nil || resp.StatusCode != http.StatusGone {
		t.Fatalf("resume after close: %v %v", resp, err)
	}
}

func TestDetachedLinkKeepsRunningTurnAndPrompt(t *testing.T) {
	e := newEnv(t) // idle_close 1s, prompt_timeout 2s
	r := e.raw()
	r.call("initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}})
	nr := r.call("session/new", map[string]any{"cwd": "actp://site", "mcpServers": []any{}})
	var s struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(nr.Result, &s)
	m, _ := jsonrpc.NewRequest(json.RawMessage(`"p"`), "session/prompt", map[string]any{"sessionId": s.SessionID, "prompt": []any{map[string]any{"type": "text", "text": "permission"}}})
	r.ep.Send(m.Raw)
	waitUntil(t, "permission request", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, g := range r.got {
			if g.Method == "session/request_permission" {
				return true
			}
		}
		return false
	})
	r.drop()
	time.Sleep(1500 * time.Millisecond) // past idle_close: a waiting prompt keeps the link
	if len(e.srv.Links()) != 1 {
		t.Fatal("link closed while a prompt was waiting")
	}
	waitNoLinks(t, e.srv) // ends at prompt_timeout
}

func TestLoadingASessionHeldByADroppedLinkTakesItOver(t *testing.T) {
	e := newEnv(t)
	old := e.raw()
	old.call("initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}})
	nr := old.call("session/new", map[string]any{"cwd": "actp://site", "mcpServers": []any{}})
	var s struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(nr.Result, &s)
	m, _ := jsonrpc.NewRequest(json.RawMessage(`"p"`), "session/prompt", map[string]any{"sessionId": s.SessionID, "prompt": []any{map[string]any{"type": "text", "text": "slow 10"}}})
	old.ep.Send(m.Raw)
	old.waitChunk("chunk 1")
	old.drop() // killed hard: no bye

	c := e.bridge()
	c.initialize()
	r := c.call("session/load", map[string]any{"sessionId": s.SessionID, "cwd": "actp://site", "mcpServers": []any{}})
	if r.Error == nil || !strings.Contains(r.Error.Message, "session still running") {
		t.Fatalf("first load: %s", r.Raw)
	}
	waitUntil(t, "old link to finish and close", func() bool { return len(e.srv.Links()) == 1 })
	r = c.call("session/load", map[string]any{"sessionId": s.SessionID, "cwd": "actp://site", "mcpServers": []any{}})
	if r.Error != nil {
		t.Fatalf("second load: %s", r.Raw)
	}
	c.chunk("chunk 10")
}

func TestResumeWithAnotherTokenIsRefused(t *testing.T) {
	e := newEnv(t)
	r := e.raw()
	r.call("initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}})
	u, _ := bridge.LinkURL(e.http.URL, "test")
	h := http.Header{}
	h.Set("Authorization", "Bearer actp_other")
	h.Set(wire.HeaderLinkID, r.id)
	_, resp, err := websocket.Dial(context.Background(), u, &websocket.DialOptions{HTTPHeader: h, Subprotocols: wire.Versions})
	if err == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %v %v", resp, err)
	}
	var lost *bridge.LostError
	_ = errors.As(err, &lost)
}

func TestIdleCloseCountsFromWhenTheTurnEnded(t *testing.T) {
	e := newEnv(t) // idle_close: 1s
	r := e.raw()
	r.call("initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}})
	nr := r.call("session/new", map[string]any{"cwd": "actp://site", "mcpServers": []any{}})
	var s struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(nr.Result, &s)
	m, _ := jsonrpc.NewRequest(json.RawMessage(`"p"`), "session/prompt", map[string]any{"sessionId": s.SessionID, "prompt": []any{map[string]any{"type": "text", "text": "slow 20"}}})
	r.ep.Send(m.Raw)
	r.waitChunk("chunk 1")
	r.drop()
	// The turn runs about 2 s while detached, longer than idle_close.
	waitUntil(t, "turn to finish", func() bool {
		l := e.srv.Links()
		return len(l) == 1 && !l[0].Running
	})
	time.Sleep(300 * time.Millisecond) // well inside idle_close after the turn ended
	if resp, err := r.connect(r.id); err != nil {
		t.Fatalf("resume after the turn ended: %v %v", resp, err)
	}
	r.waitChunk("chunk 20")
	waitUntil(t, "prompt response", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, g := range r.got {
			if g.IDKey() == `"p"` && g.Kind() == jsonrpc.KindResponse {
				return true
			}
		}
		return false
	})
}

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/jsonrpc"
	"github.com/varops/actp/internal/wire"
)

// Link states (design 3.1).
const (
	StateAttached   = "attached"
	StateDetached   = "detached"
	StateUnattended = "unattended"
	StateEnded      = "ended"
)

type clientReq struct {
	method    string
	sessionID string
	origCwd   string
	cwd       string
}

type agentReq struct {
	id        json.RawMessage
	method    string
	sessionID string
	since     time.Time
}

type linkSession struct {
	origCwd     string
	cwd         string
	turnRunning bool
	lastOutput  time.Time
}

// Link is one ACP connection to one agent process (design 1, wire 3).
type Link struct {
	srv        *Server
	id         string
	agent      *config.Agent
	token      config.Token
	clientName string
	proc       *agentproc.Process
	toAgent    *jsonrpc.Writer
	ep         *wire.Endpoint
	created    time.Time

	mu              sync.Mutex
	state           string
	stateSince      time.Time
	protocolVersion int
	canClose        bool
	clientReqs      map[string]clientReq
	agentReqs       map[string]agentReq
	sessions        map[string]*linkSession
	serverReqs      map[string]bool
	nextServerReq   int
	cancelSent      bool
	ended           chan struct{}
	tomb            *tombstone // set when a link ended with output its client has not received
	finalized       bool
	drained         chan struct{} // closed when the agent's output has been handled
	lastBusy        time.Time     // last time a turn ran or a prompt waited
	endOnce         sync.Once
}

func newID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// startLink starts an agent process for a new link.
func (s *Server) startLink(agent *config.Agent, tok *config.Token, clientName string) (*Link, error) {
	dir := homeDir()
	if ws := s.conf().Workspace(tok.DefaultWorkspace); ws != nil {
		dir = ws.Path
	} else if names := tok.AllowedWorkspaces(s.conf()); len(names) > 0 {
		if ws := s.conf().Workspace(names[0]); ws != nil {
			dir = ws.Path
		}
	}
	proc, err := agentproc.Start(agentproc.Spec{
		Command: agent.Command, Args: agent.Args, Dir: dir,
		BaseEnv: s.opts.BaseEnv, Env: agent.Env, EnvRemove: agent.EnvRemove,
	})
	if err != nil {
		s.setStatus(agent.ID, func(st *agentStatus) { st.Status, st.Error = string(api.Unavailable), err.Error() })
		return nil, fmt.Errorf("agent %s did not start: %w", agent.ID, err)
	}
	l := &Link{
		srv: s, id: newID(), agent: agent, token: *tok, clientName: clientName,
		proc: proc, toAgent: jsonrpc.NewWriter(proc.Stdin), created: time.Now(),
		state: StateDetached, stateSince: time.Now(),
		clientReqs: map[string]clientReq{}, agentReqs: map[string]agentReq{},
		sessions: map[string]*linkSession{}, serverReqs: map[string]bool{},
		ended: make(chan struct{}), drained: make(chan struct{}),
	}
	wopts := s.opts.Wire
	wopts.SpoolPath = filepath.Join(s.spoolDir(), l.id+".spool")
	l.ep = wire.NewEndpoint(wopts, l.fromClient)
	s.mu.Lock()
	s.links[l.id] = l
	s.mu.Unlock()
	s.recordPIDs()
	s.audit.event("link_opened", map[string]any{"link": l.id[:8], "agent": agent.ID, "token": tok.Name, "client": clientName})
	go l.readAgent()
	go l.supervise()
	return l, nil
}

func (l *Link) logf(msg string, args ...any) {
	l.srv.log.Info(msg, append([]any{"link", l.id[:8], "agent", l.agent.ID}, args...)...)
}

// serve attaches a socket and runs it until it ends.
func (l *Link) serve(conn *websocket.Conn, lastSeq int64) {
	l.mu.Lock()
	tomb := l.tomb
	l.mu.Unlock()
	if tomb != nil {
		// The link ended while the client was away: hand over what it missed, then say why.
		l.srv.audit.event("link_resumed", map[string]any{"link": l.id[:8], "ended": true})
		l.ep.SendControl(tomb.frame())
		_ = l.ep.Serve(l.srv.ctx, conn, lastSeq)
		l.finalizeIfDelivered()
		return
	}
	l.setState(StateAttached)
	if lastSeq > 0 {
		l.srv.audit.event("link_resumed", map[string]any{"link": l.id[:8]})
	}
	err := l.ep.Serve(l.srv.ctx, conn, lastSeq)
	switch {
	case errors.Is(err, wire.ErrReplaced):
		// A newer socket owns the link now.
	case errors.Is(err, wire.ErrBye):
		l.logf("client left")
		l.becomeUnattended("client left")
	default:
		l.mu.Lock()
		if l.state == StateAttached {
			l.state, l.stateSince = StateDetached, time.Now()
		}
		ended := l.state == StateEnded
		l.mu.Unlock()
		if ended {
			l.finalizeIfDelivered()
		}
		if err != nil {
			l.logf("connection dropped", "reason", err.Error())
		}
	}
}

func (l *Link) setState(state string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == StateEnded || l.state == StateUnattended {
		return
	}
	l.state, l.stateSince = state, time.Now()
}

func (l *Link) resumable() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state == StateAttached || l.state == StateDetached || (l.tomb != nil && !l.finalized)
}

func (l *Link) info() LinkInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return LinkInfo{ID: l.id, Agent: l.agent.ID, Token: l.token.Name, ClientName: l.clientName, State: l.state, Since: l.stateSince, Running: l.runningLocked()}
}

func (l *Link) turnRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.runningLocked()
}

// runningLocked reports whether any session has a turn running (design 3.7).
func (l *Link) runningLocked() bool {
	for _, s := range l.sessions {
		if s.turnRunning {
			return true
		}
		if l.protocolVersion >= 2 && time.Since(s.lastOutput) < 2*time.Minute {
			return true
		}
	}
	return false
}

// toClient queues a message for the client.
func (l *Link) toClient(m *jsonrpc.Message) { l.ep.Send(m.Raw) }

func (l *Link) writeAgent(m *jsonrpc.Message) {
	if err := l.toAgent.Write(m); err != nil {
		l.logf("write to agent failed", "error", err.Error())
	}
}

// fromClient handles one ACP message from the bridge, in order.
func (l *Link) fromClient(raw json.RawMessage) error {
	m, err := jsonrpc.Parse(raw)
	if err != nil {
		l.logf("dropped invalid message from client", "error", err.Error())
		return nil
	}
	switch m.Kind() {
	case jsonrpc.KindResponse:
		l.mu.Lock()
		_, ok := l.agentReqs[m.IDKey()]
		delete(l.agentReqs, m.IDKey())
		l.mu.Unlock()
		if !ok {
			return nil // a late answer to a request already settled
		}
		l.writeAgent(m)
	case jsonrpc.KindNotification:
		l.writeAgent(m)
	case jsonrpc.KindRequest:
		out, reply := l.rewriteClientRequest(m)
		if reply != nil {
			l.toClient(reply)
			return nil
		}
		l.writeAgent(out)
	}
	return nil
}

var sessionParams = map[string]bool{"session/new": true, "session/load": true, "session/resume": true, "session/list": true}

// rewriteClientRequest applies design 3.3 to a client request. A non-nil reply
// means the server answers the client itself and nothing goes to the agent.
func (l *Link) rewriteClientRequest(m *jsonrpc.Message) (*jsonrpc.Message, *jsonrpc.Message) {
	req := clientReq{method: m.Method}
	var p map[string]json.RawMessage
	_ = json.Unmarshal(m.Params, &p)
	if p != nil {
		_ = json.Unmarshal(p["sessionId"], &req.sessionID)
	}
	changed := false

	switch {
	case m.Method == "initialize":
		if stripped, err := stripClientCapabilities(m.Params); err == nil {
			_ = json.Unmarshal(stripped, &p)
			changed = true
		}
	case sessionParams[m.Method]:
		var cwd string
		_ = json.Unmarshal(p["cwd"], &cwd)
		if cwd != "" || m.Method != "session/list" {
			resolved, err := resolveCwd(l.srv.conf(), &l.token, cwd)
			if err != nil {
				l.srv.audit.event("cwd_rejected", map[string]any{"link": l.id[:8], "cwd": cwd})
				return nil, jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidParams, err.Error(), nil)
			}
			req.origCwd, req.cwd = cwd, resolved
			p["cwd"], _ = json.Marshal(resolved)
			changed = true
		}
		if servers, ok := p["mcpServers"]; ok {
			kept, dropped := filterMCPServers(l.token.MCPServers, servers)
			for _, d := range dropped {
				l.logf("dropped MCP server", "server", d)
			}
			p["mcpServers"] = kept
			changed = true
		}
		if (m.Method == "session/load" || m.Method == "session/resume") && req.sessionID != "" {
			if other := l.srv.sessionHolder(l.agent.ID, req.sessionID); other != nil && other != l {
				if other.token.Name == l.token.Name {
					other.becomeUnattended("session taken over by a new connection")
				}
				// A link with nothing running is closing right now; wait for it instead of failing.
				if other.turnRunning() || !other.waitEnded(5*time.Second) {
					return nil, jsonrpc.NewError(m.ID, jsonrpc.CodeServerError, "session still running on the agent host", nil)
				}
			}
		}
	case m.Method == "session/prompt":
		l.mu.Lock()
		if s := l.sessions[req.sessionID]; s != nil {
			s.turnRunning = true
			s.lastOutput = time.Now()
		}
		l.mu.Unlock()
	}

	l.mu.Lock()
	l.clientReqs[m.IDKey()] = req
	l.mu.Unlock()
	if !changed {
		return m, nil
	}
	out, err := m.WithParams(p)
	if err != nil {
		return m, nil
	}
	return out, nil
}

// readAgent handles the agent's output until it exits.
func (l *Link) readAgent() {
	rd := jsonrpc.NewReader(l.proc.Stdout)
	for {
		m, raw, err := rd.Read()
		if err != nil {
			if m == nil && raw != nil {
				l.logf("agent wrote a non-JSON-RPC line", "line", truncate(string(raw), 200))
				continue
			}
			if !errors.Is(err, io.EOF) {
				l.logf("reading agent failed", "error", err.Error())
			}
			break
		}
		l.fromAgent(m)
	}
	close(l.drained)
	<-l.proc.Done()
	data, _ := json.Marshal(map[string]any{"exitCode": l.proc.ExitCode(), "stderr": l.proc.Stderr()})
	l.endWithData(wire.ErrAgentExited, fmt.Sprintf("agent %s exited with code %d", l.agent.ID, l.proc.ExitCode()), data)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var authErrorText = regexp.MustCompile(`(?i)auth(entication|orization)? required|not (logged|signed) in|unauthenticated|please (log|sign) ?in`)

func isAuthError(e *jsonrpc.Error) bool {
	return e != nil && (authErrorText.MatchString(e.Message) || authErrorText.MatchString(string(e.Data)))
}

// fromAgent handles one ACP message from the agent.
func (l *Link) fromAgent(m *jsonrpc.Message) {
	switch m.Kind() {
	case jsonrpc.KindResponse:
		l.mu.Lock()
		if l.serverReqs[m.IDKey()] {
			delete(l.serverReqs, m.IDKey())
			l.mu.Unlock()
			return
		}
		req, ok := l.clientReqs[m.IDKey()]
		delete(l.clientReqs, m.IDKey())
		l.mu.Unlock()
		if ok {
			m = l.afterResponse(req, m)
		}
		l.toClient(m)
	case jsonrpc.KindRequest:
		if reply := l.answerAgentRequest(m); reply != nil {
			l.writeAgent(reply)
			return
		}
		l.toClient(m)
	case jsonrpc.KindNotification:
		var p struct {
			SessionID string          `json:"sessionId"`
			ID        json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(m.Params, &p)
		l.mu.Lock()
		if s := l.sessions[p.SessionID]; s != nil {
			s.lastOutput = time.Now()
		}
		if m.Method == "$/cancel_request" && p.ID != nil {
			delete(l.agentReqs, string(compactJSON(p.ID)))
		}
		l.mu.Unlock()
		l.toClient(m)
	}
}

func compactJSON(raw json.RawMessage) json.RawMessage {
	m, err := jsonrpc.Parse([]byte(`{"jsonrpc":"2.0","id":` + string(raw) + `,"result":null}`))
	if err != nil {
		return raw
	}
	return m.ID
}

// afterResponse tracks sessions and turns from a response, and rewrites it for the client.
func (l *Link) afterResponse(req clientReq, m *jsonrpc.Message) *jsonrpc.Message {
	switch req.method {
	case "initialize":
		if m.Error != nil {
			break
		}
		var r struct {
			ProtocolVersion   int                        `json:"protocolVersion"`
			AgentCapabilities map[string]json.RawMessage `json:"agentCapabilities"`
			AgentInfo         *api.AgentInfo             `json:"agentInfo"`
		}
		_ = json.Unmarshal(m.Result, &r)
		var sc map[string]json.RawMessage
		_ = json.Unmarshal(r.AgentCapabilities["sessionCapabilities"], &sc)
		_, canClose := sc["close"]
		l.mu.Lock()
		l.protocolVersion, l.canClose = r.ProtocolVersion, canClose
		l.mu.Unlock()
		var caps map[string]any
		_ = json.Unmarshal(m.Result, &struct {
			C *map[string]any `json:"agentCapabilities"`
		}{&caps})
		l.srv.setStatus(l.agent.ID, func(st *agentStatus) {
			st.AgentInfo, st.Capabilities = r.AgentInfo, caps
		})
		if stripped, changed := stripTerminalAuth(m.Result); changed {
			if out, err := m.WithResult(stripped); err == nil {
				return out
			}
		}
	case "session/new", "session/load", "session/resume":
		if m.Error != nil {
			if isAuthError(m.Error) {
				l.srv.markAuthRequired(l.agent.ID, m.Error.Message)
			}
			break
		}
		id := req.sessionID
		if req.method == "session/new" {
			var r struct {
				SessionID string `json:"sessionId"`
			}
			_ = json.Unmarshal(m.Result, &r)
			id = r.SessionID
		}
		if id != "" {
			l.mu.Lock()
			l.sessions[id] = &linkSession{origCwd: req.origCwd, cwd: req.cwd, lastOutput: time.Now()}
			l.mu.Unlock()
			l.srv.holdSession(l.agent.ID, id, l)
			l.srv.audit.event("session_opened", map[string]any{"link": l.id[:8], "session": id, "method": req.method})
		}
		l.srv.setStatus(l.agent.ID, func(st *agentStatus) { st.Status, st.AuthHint, st.Error = string(api.Ready), "", "" })
	case "session/prompt":
		l.mu.Lock()
		if s := l.sessions[req.sessionID]; s != nil {
			s.turnRunning = false
		}
		l.mu.Unlock()
		if isAuthError(m.Error) {
			l.srv.markAuthRequired(l.agent.ID, m.Error.Message)
		}
	case "session/list":
		if req.cwd != "" && m.Error == nil {
			return mapListCwd(m, req.cwd, req.origCwd)
		}
	case "session/close":
		l.mu.Lock()
		delete(l.sessions, req.sessionID)
		l.mu.Unlock()
		l.srv.releaseSession(l.agent.ID, req.sessionID, l)
	}
	return m
}

// mapListCwd shows the client its own cwd form in session/list results.
func mapListCwd(m *jsonrpc.Message, resolved, orig string) *jsonrpc.Message {
	var r map[string]json.RawMessage
	if json.Unmarshal(m.Result, &r) != nil {
		return m
	}
	var sessions []map[string]json.RawMessage
	if json.Unmarshal(r["sessions"], &sessions) != nil {
		return m
	}
	for _, s := range sessions {
		var cwd string
		_ = json.Unmarshal(s["cwd"], &cwd)
		if cwd == resolved {
			s["cwd"], _ = json.Marshal(orig)
		}
	}
	r["sessions"], _ = json.Marshal(sessions)
	out, err := m.WithResult(r)
	if err != nil {
		return m
	}
	return out
}

func isElicitation(method string) bool {
	return method == "elicitation/create" || method == "session/elicitation"
}

// answerAgentRequest answers agent→client requests the server handles itself,
// and records the rest as pending. A nil reply means forward to the client.
func (l *Link) answerAgentRequest(m *jsonrpc.Message) *jsonrpc.Message {
	if strings.HasPrefix(m.Method, "fs/") || strings.HasPrefix(m.Method, "terminal/") {
		return jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "Method not found: files and terminals stay on the agent host", nil)
	}
	l.mu.Lock()
	unattended := l.state == StateUnattended || l.state == StateEnded
	l.mu.Unlock()
	if m.Method == "session/request_permission" {
		policy := l.token.EffectivePermissions(l.agent)
		if unattended {
			policy = "cancel"
		}
		if reply := permissionReply(m, policy); reply != nil {
			l.srv.audit.event("permission_answered", map[string]any{"link": l.id[:8], "by": "policy", "policy": policy})
			return reply
		}
	} else if unattended {
		return settleReply(m)
	}
	var p struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(m.Params, &p)
	l.mu.Lock()
	l.agentReqs[m.IDKey()] = agentReq{id: m.ID, method: m.Method, sessionID: p.SessionID, since: time.Now()}
	l.mu.Unlock()
	return nil
}

type permissionOption struct {
	OptionID string `json:"optionId"`
	Kind     string `json:"kind"`
}

// permissionReply answers a permission request by policy, or returns nil to forward it.
func permissionReply(m *jsonrpc.Message, policy string) *jsonrpc.Message {
	var p struct {
		Options []permissionOption `json:"options"`
	}
	_ = json.Unmarshal(m.Params, &p)
	pick := func(kind string) string {
		for _, o := range p.Options {
			if o.Kind == kind {
				return o.OptionID
			}
		}
		return ""
	}
	cancelled := jsonrpc.NewResult(m.ID, map[string]any{"outcome": map[string]any{"outcome": "cancelled"}})
	switch policy {
	case "auto_allow":
		if id := pick("allow_once"); id != "" {
			return jsonrpc.NewResult(m.ID, map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": id}})
		}
	case "auto_deny":
		if id := pick("reject_once"); id != "" {
			return jsonrpc.NewResult(m.ID, map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": id}})
		}
		return cancelled
	case "cancel":
		return cancelled
	}
	return nil
}

// settleReply is the answer to an agent request nobody will answer (design 3.2).
func settleReply(m *jsonrpc.Message) *jsonrpc.Message {
	switch {
	case m.Method == "session/request_permission":
		return jsonrpc.NewResult(m.ID, map[string]any{"outcome": map[string]any{"outcome": "cancelled"}})
	case isElicitation(m.Method):
		return jsonrpc.NewResult(m.ID, map[string]any{"action": "cancel"})
	default:
		return jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "Method not found: the client has left", nil)
	}
}

// settlePending answers every request the agent is waiting on.
func (l *Link) settlePending() {
	l.mu.Lock()
	reqs := make([]agentReq, 0, len(l.agentReqs))
	for _, r := range l.agentReqs {
		reqs = append(reqs, r)
	}
	l.agentReqs = map[string]agentReq{}
	l.mu.Unlock()
	for _, r := range reqs {
		m, err := jsonrpc.NewRequest(r.id, r.method, map[string]any{})
		if err != nil {
			continue
		}
		l.writeAgent(settleReply(m))
	}
}

// serverRequest sends a request the client did not make, in actp's own id namespace.
func (l *Link) serverRequest(method string, params any) {
	l.mu.Lock()
	l.nextServerReq++
	id := json.RawMessage(fmt.Sprintf(`"actp-%d"`, l.nextServerReq))
	l.serverReqs[string(id)] = true
	l.mu.Unlock()
	if m, err := jsonrpc.NewRequest(id, method, params); err == nil {
		l.writeAgent(m)
	}
}

func (l *Link) cancelRunningTurns() {
	l.mu.Lock()
	var ids []string
	for id, s := range l.sessions {
		if s.turnRunning {
			ids = append(ids, id)
		}
	}
	l.mu.Unlock()
	for _, id := range ids {
		if n, err := jsonrpc.NewNotification("session/cancel", map[string]any{"sessionId": id}); err == nil {
			l.writeAgent(n)
		}
	}
}

// becomeUnattended marks that nobody will come back to this link (design 3.1).
func (l *Link) becomeUnattended(reason string) {
	l.mu.Lock()
	if l.state == StateUnattended || l.state == StateEnded {
		l.mu.Unlock()
		return
	}
	l.state, l.stateSince = StateUnattended, time.Now()
	l.mu.Unlock()
	l.srv.audit.event("link_unattended", map[string]any{"link": l.id[:8], "reason": reason})
	l.ep.SetDiscard(true)
	l.ep.Detach(wire.CloseLinkEnded, reason)
	l.settlePending()
	if l.agent.OnClientExit == "cancel" {
		l.cancelRunningTurns()
	}
}

// supervise runs the link timers (design 3.1).
func (l *Link) supervise() {
	t := time.NewTicker(l.srv.opts.Tick)
	defer t.Stop()
	for {
		select {
		case <-l.ended:
			return
		case <-t.C:
		}
		l.mu.Lock()
		state, since := l.state, l.stateSince
		running := l.runningLocked()
		var oldest time.Time
		for _, r := range l.agentReqs {
			if oldest.IsZero() || r.since.Before(oldest) {
				oldest = r.since
			}
		}
		cancelSent := l.cancelSent
		if running || !oldest.IsZero() {
			l.lastBusy = time.Now()
		}
		idleSince := since
		if l.lastBusy.After(idleSince) {
			idleSince = l.lastBusy
		}
		l.mu.Unlock()
		if state != StateEnded && state != StateUnattended {
			// Disk is bounded in every state, also for a slow client that is still attached.
			if l.ep.OutboxBytes() > int64(l.srv.conf().SpoolLimit) {
				l.end(wire.ErrSpoolFull, "output spool is full")
				continue
			}
			if err := l.ep.SpoolError(); err != nil {
				l.end(wire.ErrSpoolFull, "output spool failed: "+err.Error())
				continue
			}
		}
		cfg := l.srv.conf()
		switch state {
		case StateDetached:
			switch {
			case !oldest.IsZero() && time.Since(oldest) >= cfg.PromptTimeout.D():
				l.end(wire.ErrLinkEnded, "prompt unanswered past prompt_timeout")
			case !running && oldest.IsZero() && time.Since(idleSince) >= cfg.IdleClose.D():
				l.end(wire.ErrLinkEnded, "detached and idle past idle_close")
			}
		case StateUnattended:
			switch {
			case !running:
				l.end(wire.ErrLinkEnded, "client left and the turn is done")
			case time.Since(since) >= l.agent.MaxUnattended.D()+30*time.Second:
				l.end(wire.ErrLinkEnded, "unattended turn did not stop after cancel")
			case !cancelSent && time.Since(since) >= l.agent.MaxUnattended.D():
				l.mu.Lock()
				l.cancelSent = true
				l.mu.Unlock()
				l.logf("unattended turn ran past max_unattended, cancelling")
				l.cancelRunningTurns()
			}
		}
	}
}

func (l *Link) end(code, reason string) { l.endWithData(code, reason, nil) }

// tombstone keeps an ended link's unsent output for a returning client.
type tombstone struct {
	code, reason string
	data         json.RawMessage
}

func (t *tombstone) frame() wire.Frame {
	return wire.Frame{T: wire.TError, Code: t.code, Message: t.reason, Data: t.data}
}

// finalizeIfDelivered forgets an ended link once its client has everything.
func (l *Link) finalizeIfDelivered() {
	if !l.ep.Attached() && l.ep.OutboxBytes() == 0 {
		l.finalize()
	}
}

// TombstoneFor is how long an ended link keeps output its client has not received.
const TombstoneFor = 10 * time.Minute

// finalize drops what an ended link still holds and forgets it.
func (l *Link) finalize() {
	l.mu.Lock()
	if l.finalized {
		l.mu.Unlock()
		return
	}
	l.finalized = true
	l.mu.Unlock()
	l.ep.SetDiscard(true)
	l.ep.Close()
	l.srv.mu.Lock()
	delete(l.srv.links, l.id)
	l.srv.mu.Unlock()
	l.srv.recordPIDs()
}

// endWithData settles the agent and closes the link (design 3.2).
func (l *Link) endWithData(code, reason string, data json.RawMessage) {
	l.endOnce.Do(func() {
		l.mu.Lock()
		l.state, l.stateSince = StateEnded, time.Now()
		var open []string
		for id := range l.sessions {
			open = append(open, id)
		}
		canClose := l.canClose
		l.mu.Unlock()
		l.logf("link ended", "reason", reason)
		l.srv.audit.event("link_ended", map[string]any{"link": l.id[:8], "code": code, "reason": reason})

		select {
		case <-l.proc.Done():
		default:
			// Writes to a wedged agent can block, so they get a deadline; Stop always runs.
			settled := make(chan struct{})
			go func() {
				defer close(settled)
				l.settlePending()
				l.cancelRunningTurns()
				if canClose {
					for _, id := range open {
						l.serverRequest("session/close", map[string]any{"sessionId": id})
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					l.waitServerReqs(ctx)
					cancel()
				}
			}()
			select {
			case <-settled:
			case <-time.After(3 * time.Second):
				l.logf("agent did not take the settle messages in time, stopping it")
			}
			l.proc.Stop(2 * time.Second)
		}

		// Let the agent's last output reach the client before the error frame,
		// which the endpoint sends only after everything queued is on the wire.
		select {
		case <-l.drained:
		case <-time.After(2 * time.Second):
		}
		for _, id := range open {
			l.srv.releaseSession(l.agent.ID, id, l)
		}
		// The error frame goes out on whatever socket is attached now or later,
		// after every queued message, so a client that is reconnecting still gets
		// its output and then the reason (design 3.1).
		tomb := &tombstone{code: code, reason: reason, data: data}
		l.mu.Lock()
		l.tomb = tomb
		l.mu.Unlock()
		if l.ep.Attached() || l.ep.OutboxBytes() > 0 {
			l.ep.SendControl(tomb.frame())
			time.AfterFunc(TombstoneFor, l.finalize)
		} else {
			l.finalize()
		}
		close(l.ended)
	})
}

// waitEnded waits for the link to end, up to d.
func (l *Link) waitEnded(d time.Duration) bool {
	select {
	case <-l.ended:
		return true
	case <-time.After(d):
		return false
	}
}

func (l *Link) waitServerReqs(ctx context.Context) {
	for {
		l.mu.Lock()
		n := len(l.serverReqs)
		l.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-l.proc.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (s *Server) holdSession(agentID, sessionID string, l *Link) {
	s.mu.Lock()
	s.sessions[agentID+"\x00"+sessionID] = l
	s.mu.Unlock()
}

func (s *Server) releaseSession(agentID, sessionID string, l *Link) {
	s.mu.Lock()
	if s.sessions[agentID+"\x00"+sessionID] == l {
		delete(s.sessions, agentID+"\x00"+sessionID)
	}
	s.mu.Unlock()
}

func (s *Server) sessionHolder(agentID, sessionID string) *Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[agentID+"\x00"+sessionID]
}

func (s *Server) markAuthRequired(agentID, message string) {
	hint := message
	s.setStatus(agentID, func(st *agentStatus) {
		st.Status = string(api.AuthRequired)
		if st.AuthHint == "" {
			st.AuthHint = hint
		}
	})
}

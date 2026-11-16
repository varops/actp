package server

import (
	"encoding/json"
	"time"

	"github.com/varops/actp/internal/jsonrpc"
)

// While a session's starting mode is being checked (design 3.3), the client's
// messages for that session wait in a queue, so none reaches the agent while
// the session may still be in a refused mode.
//
// A check starts with a session/load or session/resume request (or a reset of
// a new session's mode) and ends when the answer has passed the check. When no
// check is left, the queue drains in order on its own goroutine: never on the
// goroutine that reads the agent, which must keep reading while actp writes to
// the agent, or both sides could block on full pipes.

// heldSession is the queue of one session.
type heldSession struct {
	queue    []*jsonrpc.Message
	bytes    int
	checks   int  // checks still running
	draining bool // a drain goroutine owns the queue
}

// sessionCheck is one running check.
type sessionCheck struct {
	sessionID string
	reqID     json.RawMessage // the client's load/resume request; nil for a reset of a new session
	done      bool
}

// startCheck holds a session's client messages until the check ends. A check
// for a client's load or resume request times out after HeldLoadTimeout.
func (l *Link) startCheck(sessionID string, reqID json.RawMessage) *sessionCheck {
	c := &sessionCheck{sessionID: sessionID, reqID: reqID}
	l.mu.Lock()
	h := l.held[sessionID]
	if h == nil {
		h = &heldSession{}
		l.held[sessionID] = h
	}
	h.checks++
	l.mu.Unlock()
	if reqID != nil {
		key := string(reqID)
		time.AfterFunc(l.srv.opts.HeldLoadTimeout, func() { l.timeOutCheck(c, key) })
	}
	return c
}

// claimCheck marks a check as ending; false means it already ended (timed out).
// The caller answers the client, then calls endCheck.
func (l *Link) claimCheck(c *sessionCheck) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.done {
		return false
	}
	c.done = true
	return true
}

// endCheck ends a claimed check. Without a refusal the queue drains once no
// check is left; with one, queued requests get it and notifications are dropped.
func (l *Link) endCheck(c *sessionCheck, refusal *jsonrpc.Error) {
	l.mu.Lock()
	h := l.held[c.sessionID]
	if h == nil {
		l.mu.Unlock()
		return
	}
	h.checks--
	var refused []*jsonrpc.Message
	if refusal != nil {
		refused, h.queue, h.bytes = h.queue, nil, 0
	}
	drain := h.checks == 0 && !h.draining && len(h.queue) > 0
	if drain {
		h.draining = true
	}
	if h.checks == 0 && !h.draining && len(h.queue) == 0 {
		delete(l.held, c.sessionID)
	}
	l.mu.Unlock()
	answerQueued(l, refused, refusal)
	if drain {
		go l.drainHeld(c.sessionID)
	}
}

func answerQueued(l *Link, queue []*jsonrpc.Message, refusal *jsonrpc.Error) {
	for _, m := range queue {
		if m.Kind() == jsonrpc.KindRequest {
			l.toClient(jsonrpc.NewError(m.ID, refusal.Code, refusal.Message, nil))
		}
	}
}

// drainHeld hands queued messages on one at a time, and stops when one of
// them starts a new check (a queued load), which then owns what follows.
func (l *Link) drainHeld(sessionID string) {
	for {
		l.mu.Lock()
		h := l.held[sessionID]
		switch {
		case h == nil:
			l.mu.Unlock()
			return
		case h.checks > 0:
			h.draining = false
			l.mu.Unlock()
			return
		case len(h.queue) == 0:
			delete(l.held, sessionID)
			l.mu.Unlock()
			return
		}
		m := h.queue[0]
		h.queue = h.queue[1:]
		h.bytes -= len(m.Raw)
		l.mu.Unlock()
		l.handleClient(m)
	}
}

// holdIfChecking queues a client message for a session under check. It returns
// false when the message can go on now. A full queue refuses the message.
func (l *Link) holdIfChecking(m *jsonrpc.Message) bool {
	sid := paramsSessionID(m)
	if sid == "" {
		return false
	}
	l.mu.Lock()
	h := l.held[sid]
	if h == nil {
		l.mu.Unlock()
		return false
	}
	if len(h.queue) >= l.srv.opts.MaxHeldMessages || h.bytes+len(m.Raw) > l.srv.opts.MaxHeldBytes {
		l.mu.Unlock()
		l.srv.audit.event("held_overflow", map[string]any{"link": l.id[:8], "session": sid, "method": m.Method})
		if m.Kind() == jsonrpc.KindRequest {
			l.toClient(jsonrpc.NewError(m.ID, jsonrpc.CodeServerError, "session busy: too many messages are waiting for this session's mode check", nil))
		}
		return true
	}
	h.queue = append(h.queue, m)
	h.bytes += len(m.Raw)
	l.mu.Unlock()
	return true
}

// abandonPending forgets a client request actp has answered itself. Only a
// request whose agent answer is still to come is recorded, so that answer is
// dropped when it arrives (which also clears the record). If the answer was
// already taken, recording the id would drop the answer to a later request
// that reuses it.
func abandonPending(clientReqs map[string]clientReq, abandoned map[string]bool, key string) bool {
	if _, ok := clientReqs[key]; !ok {
		return false
	}
	delete(clientReqs, key)
	abandoned[key] = true
	return true
}

// timeOutCheck ends a load or resume the agent did not answer in time: the
// client gets an error for it and for everything queued, the agent's late
// answer is dropped, and the session is closed.
func (l *Link) timeOutCheck(c *sessionCheck, reqKey string) {
	l.mu.Lock()
	if c.done {
		l.mu.Unlock()
		return
	}
	c.done = true
	abandonPending(l.clientReqs, l.abandoned, reqKey)
	canClose := l.canClose
	delete(l.sessions, c.sessionID)
	l.mu.Unlock()
	l.srv.audit.event("load_timed_out", map[string]any{"link": l.id[:8], "session": c.sessionID})
	refusal := &jsonrpc.Error{Code: jsonrpc.CodeServerError, Message: "session refused: the agent did not answer in time"}
	l.toClient(jsonrpc.NewError(c.reqID, refusal.Code, refusal.Message, nil))
	l.endCheck(c, refusal)
	l.srv.releaseSession(l.agent.ID, c.sessionID, l)
	if canClose {
		l.serverRequest("session/close", map[string]any{"sessionId": c.sessionID})
	}
}

// Package wire is the internal bridge-to-server format described in docs/wire.md:
// ACP messages in numbered envelopes over a WebSocket, with cumulative acks,
// heartbeats, a send window and replay after a reconnect.
package wire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Wire versions, newest first. A server and bridge pick the newest they share.
var Versions = []string{"actp.v1"}

// Headers on the link upgrade request and response.
const (
	HeaderLinkID        = "Actp-Link-Id"
	HeaderLastSeq       = "Actp-Last-Seq"
	HeaderClientName    = "Actp-Client-Name"
	HeaderPromptTimeout = "Actp-Prompt-Timeout"
)

// WebSocket close codes.
const (
	CloseReplaced      websocket.StatusCode = 4001
	CloseLinkEnded     websocket.StatusCode = 4002
	CloseProtocolError websocket.StatusCode = 4003
	CloseDead          websocket.StatusCode = 4004
)

// Frame types.
const (
	TMsg   = "msg"
	TAck   = "ack"
	TPing  = "ping"
	TPong  = "pong"
	TBye   = "bye"
	TError = "error"
)

// Error codes sent in error frames.
const (
	ErrAgentExited    = "agent_exited"
	ErrSpoolFull      = "spool_full"
	ErrServerShutdown = "server_shutdown"
	ErrEndedByAdmin   = "ended_by_admin"
	ErrLinkEnded      = "link_ended"
	ErrSequenceGap    = "sequence_gap"
	ErrProtocol       = "protocol_error"
)

// Frame is one WebSocket text frame.
type Frame struct {
	T       string          `json:"t"`
	Seq     int64           `json:"seq,omitempty"`
	Ack     int64           `json:"ack,omitempty"`
	Msg     json.RawMessage `json:"msg,omitempty"`
	Code    string          `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// RemoteError is an error frame received from the other side.
type RemoteError struct {
	Code    string
	Message string
	Data    json.RawMessage
}

func (e *RemoteError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// Fatal reports whether the link has ended, as opposed to only this socket.
func (e *RemoteError) Fatal() bool {
	return e.Code != ErrSequenceGap && e.Code != ErrProtocol
}

var (
	// ErrBye means the peer said its client has left.
	ErrBye = errors.New("peer said bye")
	// ErrDead means nothing arrived from the peer for too long.
	ErrDead = errors.New("peer went silent")
	// ErrReplaced means a newer socket took over the link.
	ErrReplaced = errors.New("replaced by a newer connection")
	// ErrDetached means the socket was closed on purpose by this side.
	ErrDetached = errors.New("detached")
)

// Options tune liveness and flow control. Zero values use the defaults from docs/wire.md.
type Options struct {
	HeartbeatEvery time.Duration // send something at least this often (10 s)
	DeadAfter      time.Duration // peer silent this long → socket is dead (25 s)
	AckDelay       time.Duration // ack received messages within this delay (1 s)
	AckEvery       int64         // or after this many messages (50)
	WindowMsgs     int64         // stop sending with this many unacked (1000)
	WindowBytes    int64         // or this many bytes unacked (4 MB)
	HeartbeatPing  bool          // heartbeat with ping instead of ack
	Tick           time.Duration // writer housekeeping interval (100 ms)
	// SpoolPath, when set, is a file that unacked messages spill into once
	// MemoryLimit bytes are held in memory (8 MB). The file is private to the user.
	SpoolPath   string
	MemoryLimit int64
}

func (o *Options) defaults() {
	if o.HeartbeatEvery == 0 {
		o.HeartbeatEvery = 10 * time.Second
	}
	if o.DeadAfter == 0 {
		o.DeadAfter = 25 * time.Second
	}
	if o.AckDelay == 0 {
		o.AckDelay = time.Second
	}
	if o.AckEvery == 0 {
		o.AckEvery = 50
	}
	if o.WindowMsgs == 0 {
		o.WindowMsgs = 1000
	}
	if o.WindowBytes == 0 {
		o.WindowBytes = 4 << 20
	}
	if o.Tick == 0 {
		o.Tick = 100 * time.Millisecond
	}
	if o.MemoryLimit == 0 {
		o.MemoryLimit = 8 << 20
	}
}

type outItem struct {
	seq  int64
	raw  json.RawMessage // nil when the message is in the spool file
	off  int64
	size int64
}

// Endpoint is one side of a link. It outlives sockets: messages sent while no
// socket is attached wait in the outbox and go out after the next Serve.
type Endpoint struct {
	opts    Options
	deliver func(json.RawMessage) error

	mu        sync.Mutex
	nextSeq   int64
	outbox    []outItem
	outBytes  int64
	memBytes  int64
	spool     *os.File
	spoolEnd  int64
	spoolErr  error
	peerAck   int64
	sentSeq   int64
	lastRecv  int64
	ackSent   int64
	ackDue    time.Time
	pongDue   bool
	control   []Frame
	discard   bool
	conn      *websocket.Conn
	lastHeard time.Time
	lastSent  time.Time
	wake      chan struct{}
	closeConn func(websocket.StatusCode, string)
	serveDone chan struct{}
	deliverMu sync.Mutex
}

// NewEndpoint creates an endpoint. deliver is called once per peer message, in
// order; the message counts as processed when it returns nil.
func NewEndpoint(opts Options, deliver func(json.RawMessage) error) *Endpoint {
	opts.defaults()
	return &Endpoint{opts: opts, deliver: deliver, wake: make(chan struct{}, 1)}
}

// Send queues an ACP message for the peer.
func (e *Endpoint) Send(raw json.RawMessage) {
	e.mu.Lock()
	if e.discard {
		e.mu.Unlock()
		return
	}
	e.nextSeq++
	it := outItem{seq: e.nextSeq, raw: raw, size: int64(len(raw))}
	if e.opts.SpoolPath != "" && e.memBytes+it.size > e.opts.MemoryLimit {
		if err := e.spill(&it); err != nil {
			e.spoolErr = err
		}
	}
	if it.raw != nil {
		e.memBytes += it.size
	}
	e.outbox = append(e.outbox, it)
	e.outBytes += it.size
	e.mu.Unlock()
	e.poke()
}

// SetDiscard drops queued and future outgoing messages. Used once nobody will read them.
func (e *Endpoint) SetDiscard(on bool) {
	e.mu.Lock()
	e.discard = on
	if on {
		e.outbox = nil
		e.outBytes = 0
		e.memBytes = 0
		e.resetSpool()
		e.peerAck = e.nextSeq
		e.sentSeq = e.nextSeq
	}
	e.mu.Unlock()
}

// OutboxBytes is the size of messages waiting for an ack.
func (e *Endpoint) OutboxBytes() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.outBytes
}

// LastReceived is the highest peer sequence number processed.
func (e *Endpoint) LastReceived() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastRecv
}

// Attached reports whether a socket is being served.
func (e *Endpoint) Attached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.conn != nil
}

// SendControl queues a control frame (bye, error) on the current socket.
func (e *Endpoint) SendControl(f Frame) {
	e.mu.Lock()
	e.control = append(e.control, f)
	e.mu.Unlock()
	e.poke()
}

// Detach closes the current socket, if any, with the given code.
func (e *Endpoint) Detach(code websocket.StatusCode, reason string) {
	e.mu.Lock()
	closeFn := e.closeConn
	e.mu.Unlock()
	if closeFn != nil {
		closeFn(code, reason)
	}
}

func (e *Endpoint) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Serve runs the link over conn until the socket ends. peerLastSeq is the
// highest of our messages the peer has processed; everything after it is resent.
func (e *Endpoint) Serve(ctx context.Context, conn *websocket.Conn, peerLastSeq int64) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var closeOnce sync.Once
	closeFn := func(code websocket.StatusCode, reason string) {
		closeOnce.Do(func() {
			cancel(closeCause(code))
			_ = conn.Close(code, reason)
		})
	}

	// Only one socket at a time: close the old one and wait until its Serve has
	// fully returned, so it cannot deliver a message the new socket delivers again.
	e.mu.Lock()
	for e.closeConn != nil {
		old, oldDone := e.closeConn, e.serveDone
		e.mu.Unlock()
		old(CloseReplaced, "replaced")
		<-oldDone
		e.mu.Lock()
	}
	myDone := make(chan struct{})
	defer close(myDone)
	e.serveDone = myDone
	e.conn = conn
	e.closeConn = closeFn
	e.ackPeer(peerLastSeq)
	e.sentSeq = e.peerAck
	e.ackSent = 0 // re-announce our position on the new socket
	e.ackDue = time.Now()
	now := time.Now()
	e.lastHeard, e.lastSent = now, now
	e.mu.Unlock()
	e.poke()

	writerDone := make(chan error, 1)
	go func() { writerDone <- e.writeLoop(ctx, conn, closeFn) }()

	readErr := e.readLoop(ctx, conn, closeFn)
	closeFn(websocket.StatusNormalClosure, "")
	writeErr := <-writerDone

	e.mu.Lock()
	if e.conn == conn {
		e.conn = nil
		e.closeConn = nil
	}
	e.mu.Unlock()

	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) && readErr == nil {
		return cause
	}
	if readErr != nil {
		return readErr
	}
	return writeErr
}

type closeCause websocket.StatusCode

func (c closeCause) Error() string { return fmt.Sprintf("closed with %d", int(c)) }

func causeError(ctx context.Context) error {
	var cc closeCause
	if errors.As(context.Cause(ctx), &cc) {
		switch websocket.StatusCode(cc) {
		case CloseReplaced:
			return ErrReplaced
		case CloseDead:
			return ErrDead
		default:
			return ErrDetached
		}
	}
	return nil
}

func (e *Endpoint) readLoop(ctx context.Context, conn *websocket.Conn, closeFn func(websocket.StatusCode, string)) error {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			if ce := causeError(ctx); ce != nil {
				return ce
			}
			switch websocket.CloseStatus(err) {
			case CloseReplaced:
				return ErrReplaced
			}
			return err
		}
		e.mu.Lock()
		e.lastHeard = time.Now()
		e.mu.Unlock()
		if typ != websocket.MessageText {
			continue
		}
		var f Frame
		if err := json.Unmarshal(data, &f); err != nil {
			e.sendNow(ctx, conn, Frame{T: TError, Code: ErrProtocol, Message: "invalid frame"})
			closeFn(CloseProtocolError, "invalid frame")
			return fmt.Errorf("%s: %w", ErrProtocol, err)
		}
		switch f.T {
		case TMsg:
			e.handleAck(f.Ack)
			// deliverMu makes check, deliver and update one step, so a message is
			// never delivered twice or out of order, whichever socket it came on.
			e.deliverMu.Lock()
			e.mu.Lock()
			last := e.lastRecv
			e.mu.Unlock()
			if f.Seq <= last {
				e.deliverMu.Unlock()
				continue
			}
			if f.Seq != last+1 {
				e.deliverMu.Unlock()
				e.sendNow(ctx, conn, Frame{T: TError, Code: ErrSequenceGap, Message: fmt.Sprintf("expected %d, got %d", last+1, f.Seq)})
				closeFn(CloseProtocolError, "sequence gap")
				return &RemoteError{Code: ErrSequenceGap, Message: "sequence gap"}
			}
			if err := e.deliver(f.Msg); err != nil {
				e.deliverMu.Unlock()
				return err
			}
			e.mu.Lock()
			e.lastRecv = f.Seq
			e.deliverMu.Unlock()
			if e.lastRecv-e.ackSent >= e.opts.AckEvery {
				e.ackDue = time.Now()
			} else if e.ackDue.IsZero() {
				e.ackDue = time.Now().Add(e.opts.AckDelay)
			}
			e.mu.Unlock()
			e.poke()
		case TAck:
			e.handleAck(f.Ack)
		case TPing:
			e.mu.Lock()
			e.pongDue = true
			e.mu.Unlock()
			e.poke()
		case TPong:
		case TBye:
			return ErrBye
		case TError:
			return &RemoteError{Code: f.Code, Message: f.Message, Data: f.Data}
		}
	}
}

func (e *Endpoint) handleAck(a int64) {
	e.mu.Lock()
	changed := e.ackPeer(a)
	e.mu.Unlock()
	if changed {
		e.poke()
	}
}

// spill writes a message to the spool file; the caller holds mu.
func (e *Endpoint) spill(it *outItem) error {
	if e.spool == nil {
		if err := os.MkdirAll(filepath.Dir(e.opts.SpoolPath), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(e.opts.SpoolPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		e.spool, e.spoolEnd = f, 0
	}
	if _, err := e.spool.WriteAt(it.raw, e.spoolEnd); err != nil {
		return err
	}
	it.off, it.raw = e.spoolEnd, nil
	e.spoolEnd += it.size
	return nil
}

// load returns a message's bytes, reading the spool when needed; the caller holds mu.
func (e *Endpoint) load(it outItem) (json.RawMessage, error) {
	if it.raw != nil {
		return it.raw, nil
	}
	if e.spool == nil {
		return nil, errors.New("spool file is gone")
	}
	buf := make([]byte, it.size)
	if _, err := e.spool.ReadAt(buf, it.off); err != nil {
		return nil, fmt.Errorf("reading spool: %w", err)
	}
	return buf, nil
}

// resetSpool empties the spool file once nothing in it is needed; the caller holds mu.
func (e *Endpoint) resetSpool() {
	if e.spool != nil && e.spoolEnd > 0 {
		_ = e.spool.Truncate(0)
		e.spoolEnd = 0
	}
}

// compactMin is the amount of acked data in the spool that triggers compaction.
var compactMin int64 = 64 << 20

// maybeCompactSpool rewrites the spool without acked data once that data is
// most of the file, so a long stream to a slow reader does not grow it forever.
// The caller holds mu.
func (e *Endpoint) maybeCompactSpool() {
	if e.spool == nil {
		return
	}
	var live int64
	for _, it := range e.outbox {
		if it.raw == nil {
			live += it.size
		}
	}
	dead := e.spoolEnd - live
	if dead < compactMin || dead < e.spoolEnd/2 {
		return
	}
	tmpPath := e.opts.SpoolPath + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		e.spoolErr = err
		return
	}
	var off int64
	moved := make([]int64, len(e.outbox))
	for i, it := range e.outbox {
		if it.raw != nil {
			continue
		}
		buf, err := e.load(it)
		if err == nil {
			_, err = tmp.WriteAt(buf, off)
		}
		if err != nil {
			tmp.Close()
			_ = os.Remove(tmpPath)
			e.spoolErr = err
			return
		}
		moved[i] = off
		off += it.size
	}
	// Windows cannot rename open files, so close both, rename, and reopen.
	_ = e.spool.Close()
	_ = tmp.Close()
	if err := os.Rename(tmpPath, e.opts.SpoolPath); err != nil {
		_ = os.Remove(tmpPath)
		e.spoolErr = err
		e.spool, _ = os.OpenFile(e.opts.SpoolPath, os.O_RDWR, 0o600)
		return
	}
	tmp, err = os.OpenFile(e.opts.SpoolPath, os.O_RDWR, 0o600)
	if err != nil {
		e.spoolErr = err
		e.spool = nil
		return
	}
	for i := range e.outbox {
		if e.outbox[i].raw == nil {
			e.outbox[i].off = moved[i]
		}
	}
	e.spool, e.spoolEnd = tmp, off
}

// SpoolError reports a failure to use the spool file, if any.
func (e *Endpoint) SpoolError() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.spoolErr
}

// Close deletes the spool file. The endpoint must not be used afterwards.
func (e *Endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.spool != nil {
		_ = e.spool.Close()
		_ = os.Remove(e.opts.SpoolPath)
		e.spool = nil
	}
	e.outbox, e.outBytes, e.memBytes = nil, 0, 0
}

// ackPeer trims the outbox up to a; the caller holds mu.
func (e *Endpoint) ackPeer(a int64) bool {
	if a <= e.peerAck {
		return false
	}
	if a > e.nextSeq {
		a = e.nextSeq
	}
	e.peerAck = a
	n := 0
	for n < len(e.outbox) && e.outbox[n].seq <= a {
		e.outBytes -= e.outbox[n].size
		if e.outbox[n].raw != nil {
			e.memBytes -= e.outbox[n].size
		}
		n++
	}
	e.outbox = append(e.outbox[:0:0], e.outbox[n:]...)
	if len(e.outbox) == 0 {
		e.resetSpool()
	} else {
		e.maybeCompactSpool()
	}
	if e.sentSeq < a {
		e.sentSeq = a
	}
	return true
}

func (e *Endpoint) sendNow(ctx context.Context, conn *websocket.Conn, f Frame) {
	data, _ := json.Marshal(f)
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = conn.Write(wctx, websocket.MessageText, data)
}

func (e *Endpoint) writeLoop(ctx context.Context, conn *websocket.Conn, closeFn func(websocket.StatusCode, string)) error {
	ticker := time.NewTicker(e.opts.Tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-e.wake:
		}
		frames, dead, closeAfter := e.collect()
		if dead {
			closeFn(CloseDead, "peer silent")
			return ErrDead
		}
		for _, f := range frames {
			data, err := json.Marshal(f)
			if err != nil {
				return err
			}
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = conn.Write(wctx, websocket.MessageText, data)
			cancel()
			if err != nil {
				return err
			}
		}
		if closeAfter != 0 {
			closeFn(closeAfter, "")
			return nil
		}
	}
}

// collect decides what to write next; the writer sends it without holding mu.
func (e *Endpoint) collect() (frames []Frame, dead bool, closeAfter websocket.StatusCode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if now.Sub(e.lastHeard) > e.opts.DeadAfter {
		return nil, true, 0
	}
	// A bye or a link-ending error waits until every queued message is on the
	// wire, so nothing the peer still needs is overtaken by it.
	var bye []Frame
	for _, c := range e.control {
		switch c.T {
		case TBye, TError:
			bye = append(bye, c)
		default:
			frames = append(frames, c)
		}
	}
	e.control = bye
	if e.pongDue {
		frames = append(frames, Frame{T: TPong})
		e.pongDue = false
	}
	if closeAfter == 0 {
		var inflightBytes int64
		for _, it := range e.outbox {
			if it.seq > e.sentSeq {
				break
			}
			if it.seq > e.peerAck {
				inflightBytes += it.size
			}
		}
		for e.sentSeq < e.nextSeq && len(e.outbox) > 0 {
			if e.sentSeq-e.peerAck >= e.opts.WindowMsgs || inflightBytes >= e.opts.WindowBytes {
				break
			}
			idx := int(e.sentSeq + 1 - e.outbox[0].seq)
			if idx < 0 || idx >= len(e.outbox) {
				break
			}
			it := e.outbox[idx]
			raw, err := e.load(it)
			if err != nil {
				e.spoolErr = err
				break
			}
			frames = append(frames, Frame{T: TMsg, Seq: it.seq, Ack: e.lastRecv, Msg: raw})
			inflightBytes += it.size
			e.sentSeq = it.seq
			e.ackSent = e.lastRecv
		}
	}
	if len(e.control) > 0 && closeAfter == 0 && e.sentSeq >= e.nextSeq {
		closeAfter = websocket.StatusNormalClosure
		for _, c := range e.control {
			if c.T == TError {
				closeAfter = CloseLinkEnded
			}
		}
		frames = append(frames, e.control...)
		e.control = nil
	}
	ackOwed := e.lastRecv > e.ackSent && !e.ackDue.IsZero() && !now.Before(e.ackDue)
	heartbeat := now.Sub(e.lastSent) >= e.opts.HeartbeatEvery
	if len(frames) == 0 && (ackOwed || heartbeat) {
		if heartbeat && e.opts.HeartbeatPing && !ackOwed {
			frames = append(frames, Frame{T: TPing})
		} else {
			frames = append(frames, Frame{T: TAck, Ack: e.lastRecv})
			e.ackSent = e.lastRecv
		}
	}
	if e.lastRecv <= e.ackSent {
		e.ackDue = time.Time{}
	}
	if len(frames) > 0 {
		e.lastSent = now
	}
	return frames, false, closeAfter
}

// Package bridge is `actp <agent>@<server>`: a local stdio ACP agent that
// forwards everything to an agent on an actp server.
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/varops/actp/internal/jsonrpc"
	"github.com/varops/actp/internal/wire"
)

// Options configure a bridge.
type Options struct {
	Agent      string
	BaseURL    string // http(s)://host[:port][/prefix]
	Token      string
	ClientName string
	// Cwd replaces every cwd the client sends, for example "actp://website".
	Cwd string
	// Maps rewrite cwd values that start with From.
	Maps        []Map
	Wire        wire.Options
	Logger      *slog.Logger
	GiveUpAfter time.Duration // stop reconnecting after this long (10 min)
	MaxBackoff  time.Duration // 30 s
}

// Map is one --map FROM=TO rule.
type Map struct{ From, To string }

// LostError means the remote session is gone; the bridge should exit 1.
type LostError struct{ Reason string }

func (e *LostError) Error() string { return "remote session lost: " + e.Reason }

type bridge struct {
	opts Options
	log  *slog.Logger
	out  *jsonrpc.Writer
	ep   *wire.Endpoint

	mu      sync.Mutex
	pending map[string]json.RawMessage // client request ids waiting for an answer
	linkID  string
}

// Run bridges stdin/stdout to the remote agent until the client closes stdin
// (returns nil) or the remote session is lost (returns *LostError or another error).
func Run(ctx context.Context, opts Options, stdin io.Reader, stdout io.Writer) error {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.GiveUpAfter == 0 {
		opts.GiveUpAfter = 10 * time.Minute
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	b := &bridge{opts: opts, log: opts.Logger, out: jsonrpc.NewWriter(stdout), pending: map[string]json.RawMessage{}}
	b.ep = wire.NewEndpoint(opts.Wire, b.toClient)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Open the link before reading the client, so a bad URL or token fails fast.
	conn, peerLast, err := b.dial(ctx)
	if err != nil {
		return err
	}

	clientGone := make(chan struct{})
	go func() {
		b.readClient(stdin)
		close(clientGone)
	}()

	for {
		served := make(chan error, 1)
		go func(c *websocket.Conn, last int64) { served <- b.ep.Serve(ctx, c, last) }(conn, peerLast)
		var serveErr error
		select {
		case serveErr = <-served:
		case <-clientGone:
			b.sayBye(served)
			return nil
		}
		var re *wire.RemoteError
		if errors.As(serveErr, &re) && re.Fatal() {
			return b.lost(remoteReason(re))
		}
		b.log.Info("connection dropped, reconnecting", "reason", fmt.Sprint(serveErr))

		conn, peerLast, err = b.reconnect(ctx, clientGone)
		if errors.Is(err, errClientGone) {
			return nil
		}
		if err != nil {
			return b.lost(err.Error())
		}
	}
}

var errClientGone = errors.New("client gone")

func remoteReason(re *wire.RemoteError) string {
	if re.Code == wire.ErrAgentExited && len(re.Data) > 0 {
		var d struct {
			Stderr string `json:"stderr"`
		}
		if json.Unmarshal(re.Data, &d) == nil && strings.TrimSpace(d.Stderr) != "" {
			return re.Message + ": " + lastLine(d.Stderr)
		}
	}
	return re.Message
}

func lastLine(s string) string {
	s = strings.TrimRight(s, "\r\n")
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// reconnect retries with backoff until it gets through, the client leaves, or
// it is time to give up. Time asleep does not count: Go's monotonic clock stops during sleep.
func (b *bridge) reconnect(ctx context.Context, clientGone <-chan struct{}) (*websocket.Conn, int64, error) {
	start := time.Now()
	delay := 500 * time.Millisecond
	for {
		select {
		case <-clientGone:
			return nil, 0, errClientGone
		case <-time.After(jitter(delay)):
		}
		conn, last, err := b.dial(ctx)
		if err == nil {
			b.log.Info("reconnected")
			return conn, last, nil
		}
		var se *statusError
		if errors.As(err, &se) && se.permanent() {
			return nil, 0, err
		}
		if time.Since(start) > b.opts.GiveUpAfter {
			return nil, 0, fmt.Errorf("server unreachable for %s: %w", b.opts.GiveUpAfter, err)
		}
		delay = min(delay*2, b.opts.MaxBackoff)
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}

// sayBye tells the server the client has left (design 3.1), then lets the socket close.
func (b *bridge) sayBye(served chan error) {
	if b.ep.Attached() {
		b.ep.SendControl(wire.Frame{T: wire.TBye})
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			b.ep.Detach(websocket.StatusNormalClosure, "bye")
		}
		return
	}
	// Not connected right now: one quick try, so the server does not wait for a client that is gone.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, last, err := b.dial(ctx); err == nil {
		done := make(chan error, 1)
		go func() { done <- b.ep.Serve(ctx, conn, last) }()
		b.ep.SendControl(wire.Frame{T: wire.TBye})
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
}

// lost answers everything the client is waiting on, so it is not left hanging.
func (b *bridge) lost(reason string) error {
	b.mu.Lock()
	ids := make([]json.RawMessage, 0, len(b.pending))
	for _, id := range b.pending {
		ids = append(ids, id)
	}
	b.pending = map[string]json.RawMessage{}
	b.mu.Unlock()
	err := &LostError{Reason: reason}
	for _, id := range ids {
		_ = b.out.Write(jsonrpc.NewError(id, jsonrpc.CodeServerError, err.Error(), nil))
	}
	return err
}

// toClient delivers one message from the server to the client.
func (b *bridge) toClient(raw json.RawMessage) error {
	if m, err := jsonrpc.Parse(raw); err == nil && m.Kind() == jsonrpc.KindResponse {
		b.mu.Lock()
		delete(b.pending, m.IDKey())
		b.mu.Unlock()
	}
	return b.out.WriteRaw(raw)
}

// readClient forwards the client's messages until stdin closes.
func (b *bridge) readClient(stdin io.Reader) {
	rd := jsonrpc.NewReader(stdin)
	for {
		m, raw, err := rd.Read()
		if err != nil {
			if m == nil && raw != nil {
				b.log.Warn("client sent a line that is not JSON-RPC", "line", string(raw))
				continue
			}
			return
		}
		if m.Kind() == jsonrpc.KindRequest {
			m = b.rewrite(m)
			b.mu.Lock()
			b.pending[m.IDKey()] = m.ID
			b.mu.Unlock()
		}
		b.ep.Send(m.Raw)
	}
}

var cwdMethods = map[string]bool{"session/new": true, "session/load": true, "session/resume": true, "session/list": true}

// rewrite drops client capabilities that cannot work remotely and applies --cwd/--map.
func (b *bridge) rewrite(m *jsonrpc.Message) *jsonrpc.Message {
	var p map[string]json.RawMessage
	if json.Unmarshal(m.Params, &p) != nil {
		return m
	}
	changed := false
	switch {
	case m.Method == "initialize":
		var caps map[string]json.RawMessage
		if json.Unmarshal(p["clientCapabilities"], &caps) == nil {
			delete(caps, "fs")
			delete(caps, "terminal")
			p["clientCapabilities"], _ = json.Marshal(caps)
			changed = true
		}
	case cwdMethods[m.Method]:
		var cwd string
		_ = json.Unmarshal(p["cwd"], &cwd)
		if cwd == "" && m.Method == "session/list" {
			break
		}
		if newCwd := b.mapCwd(cwd); newCwd != cwd {
			p["cwd"], _ = json.Marshal(newCwd)
			changed = true
		}
	}
	if !changed {
		return m
	}
	out, err := m.WithParams(p)
	if err != nil {
		return m
	}
	return out
}

func (b *bridge) mapCwd(cwd string) string {
	if b.opts.Cwd != "" {
		return b.opts.Cwd
	}
	norm := strings.ReplaceAll(cwd, `\`, "/")
	best := -1
	for i, mp := range b.opts.Maps {
		from := strings.TrimSuffix(strings.ReplaceAll(mp.From, `\`, "/"), "/")
		if (norm == from || strings.HasPrefix(norm, from+"/")) && (best < 0 || len(from) > len(b.opts.Maps[best].From)) {
			best = i
		}
	}
	if best < 0 {
		return cwd
	}
	mp := b.opts.Maps[best]
	rest := strings.TrimPrefix(strings.TrimPrefix(norm, strings.TrimSuffix(strings.ReplaceAll(mp.From, `\`, "/"), "/")), "/")
	if rest == "" {
		return mp.To
	}
	return strings.TrimSuffix(mp.To, "/") + "/" + rest
}

// statusError is a failed upgrade with an HTTP status.
type statusError struct {
	Status  int
	Code    string
	Message string
}

func (e *statusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// permanent errors will not go away by retrying.
func (e *statusError) permanent() bool {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusGone, http.StatusUpgradeRequired:
		return true
	}
	return false
}

// LinkURL builds the WebSocket URL of an agent's link endpoint.
func LinkURL(base, agent string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(base, "/"))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	u.Path += "/actp/v1/agents/" + url.PathEscape(agent) + "/link"
	return u.String(), nil
}

func (b *bridge) dial(ctx context.Context) (*websocket.Conn, int64, error) {
	target, err := LinkURL(b.opts.BaseURL, b.opts.Agent)
	if err != nil {
		return nil, 0, err
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+b.opts.Token)
	if b.opts.ClientName != "" {
		h.Set(wire.HeaderClientName, b.opts.ClientName)
	}
	b.mu.Lock()
	linkID := b.linkID
	b.mu.Unlock()
	if linkID != "" {
		h.Set(wire.HeaderLinkID, linkID)
		h.Set(wire.HeaderLastSeq, strconv.FormatInt(b.ep.LastReceived(), 10))
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(dctx, target, &websocket.DialOptions{HTTPHeader: h, Subprotocols: wire.Versions})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			se := &statusError{Status: resp.StatusCode}
			if resp.Body != nil {
				var body struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				}
				_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
				se.Code, se.Message = body.Error, body.Message
			}
			return nil, 0, se
		}
		return nil, 0, err
	}
	conn.SetReadLimit(16 << 20)
	if id := resp.Header.Get(wire.HeaderLinkID); id != "" {
		b.mu.Lock()
		b.linkID = id
		b.mu.Unlock()
	}
	last, _ := strconv.ParseInt(resp.Header.Get(wire.HeaderLastSeq), 10, 64)
	return conn, last, nil
}

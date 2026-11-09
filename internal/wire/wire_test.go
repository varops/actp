package wire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type collector struct {
	mu   sync.Mutex
	msgs []string
}

func (c *collector) deliver(raw json.RawMessage) error {
	c.mu.Lock()
	c.msgs = append(c.msgs, string(raw))
	c.mu.Unlock()
	return nil
}

func (c *collector) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fastOpts() Options {
	return Options{HeartbeatEvery: 50 * time.Millisecond, DeadAfter: 300 * time.Millisecond, AckDelay: 20 * time.Millisecond, Tick: 10 * time.Millisecond}
}

// pair starts a server endpoint behind httptest and returns a dial function.
func pair(t *testing.T, server *Endpoint) (dial func() *websocket.Conn, serveErrs chan error) {
	serveErrs = make(chan error, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: Versions})
		if err != nil {
			return
		}
		var last int64
		fmt.Sscan(r.Header.Get(HeaderLastSeq), &last)
		serveErrs <- server.Serve(context.Background(), conn, last)
	}))
	t.Cleanup(srv.Close)
	dial = func() *websocket.Conn {
		conn, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{Subprotocols: Versions})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	return dial, serveErrs
}

func TestMessagesFlowBothWaysAndAreAcked(t *testing.T) {
	var sc, cc collector
	server := NewEndpoint(fastOpts(), sc.deliver)
	client := NewEndpoint(fastOpts(), cc.deliver)
	dial, _ := pair(t, server)
	go client.Serve(context.Background(), dial(), 0)

	for i := 1; i <= 120; i++ {
		server.Send(json.RawMessage(fmt.Sprintf(`{"n":%d}`, i)))
	}
	client.Send(json.RawMessage(`{"hello":1}`))
	waitFor(t, "client to get 120", func() bool { return len(cc.list()) == 120 })
	waitFor(t, "server to get 1", func() bool { return len(sc.list()) == 1 })
	waitFor(t, "server outbox to drain", func() bool { return server.OutboxBytes() == 0 })
	if cc.list()[0] != `{"n":1}` || cc.list()[119] != `{"n":120}` {
		t.Fatalf("order: %v ... %v", cc.list()[0], cc.list()[119])
	}
}

func TestResumeReplaysWhatWasMissed(t *testing.T) {
	var sc, cc collector
	server := NewEndpoint(fastOpts(), sc.deliver)
	client := NewEndpoint(fastOpts(), cc.deliver)
	dial, serveErrs := pair(t, server)

	conn := dial()
	done := make(chan error, 1)
	go func() { done <- client.Serve(context.Background(), conn, 0) }()
	server.Send(json.RawMessage(`{"n":1}`))
	waitFor(t, "first message", func() bool { return len(cc.list()) == 1 })

	// Drop the socket hard, then send while nobody is attached.
	client.Detach(websocket.StatusGoingAway, "test")
	<-done
	<-serveErrs
	server.Send(json.RawMessage(`{"n":2}`))
	server.Send(json.RawMessage(`{"n":3}`))
	client.Send(json.RawMessage(`{"c":1}`))

	conn2 := dial()
	go client.Serve(context.Background(), conn2, 0)
	waitFor(t, "replay", func() bool { return len(cc.list()) == 3 })
	waitFor(t, "client message after resume", func() bool { return len(sc.list()) == 1 })
	if got := strings.Join(cc.list(), ","); got != `{"n":1},{"n":2},{"n":3}` {
		t.Fatalf("got %s", got)
	}
}

func TestSilentPeerIsDetected(t *testing.T) {
	var sc collector
	server := NewEndpoint(fastOpts(), sc.deliver)
	dial, serveErrs := pair(t, server)
	conn := dial() // a client that never reads or writes
	defer conn.CloseNow()
	select {
	case err := <-serveErrs:
		if !errors.Is(err, ErrDead) {
			t.Fatalf("got %v, want ErrDead", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("silent peer not detected")
	}
}

func TestByeEndsServe(t *testing.T) {
	var sc, cc collector
	server := NewEndpoint(fastOpts(), sc.deliver)
	client := NewEndpoint(fastOpts(), cc.deliver)
	dial, serveErrs := pair(t, server)
	go client.Serve(context.Background(), dial(), 0)
	time.Sleep(50 * time.Millisecond)
	client.SendControl(Frame{T: TBye})
	select {
	case err := <-serveErrs:
		if !errors.Is(err, ErrBye) {
			t.Fatalf("got %v, want ErrBye", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bye not seen")
	}
}

func TestNewSocketReplacesOld(t *testing.T) {
	var sc, cc1, cc2 collector
	server := NewEndpoint(fastOpts(), sc.deliver)
	dial, serveErrs := pair(t, server)
	c1 := NewEndpoint(fastOpts(), cc1.deliver)
	go c1.Serve(context.Background(), dial(), 0)
	waitFor(t, "attach", server.Attached)
	c2 := NewEndpoint(fastOpts(), cc2.deliver)
	go c2.Serve(context.Background(), dial(), 0)
	select {
	case err := <-serveErrs:
		if !errors.Is(err, ErrReplaced) {
			t.Fatalf("got %v, want ErrReplaced", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old socket not replaced")
	}
	server.Send(json.RawMessage(`{"x":1}`))
	waitFor(t, "new socket gets messages", func() bool { return len(cc2.list()) == 1 })
}

func TestWindowStopsSendingWithoutAcks(t *testing.T) {
	opts := fastOpts()
	opts.WindowMsgs = 5
	server := NewEndpoint(opts, func(json.RawMessage) error { return nil })
	dial, _ := pair(t, server)
	conn := dial()
	defer conn.CloseNow()
	for i := 0; i < 20; i++ {
		server.Send(json.RawMessage(`{}`))
	}
	got := 0
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			break
		}
		var f Frame
		_ = json.Unmarshal(data, &f)
		if f.T == TMsg {
			got++
		}
	}
	if got != 5 {
		t.Fatalf("sent %d messages without acks, want 5", got)
	}
}

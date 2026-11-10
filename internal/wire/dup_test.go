package wire

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestDuplicateDeliveryAcrossReplace(t *testing.T) {
	var count atomic.Int32
	release := make(chan struct{})
	server := NewEndpoint(fastOpts(), func(raw json.RawMessage) error {
		if count.Add(1) == 1 {
			<-release // first delivery is slow (agent stdin full, waitEnded, ...)
		}
		return nil
	})
	var cc collector
	client := NewEndpoint(fastOpts(), cc.deliver)
	dial, _ := pair(t, server)

	done := make(chan error, 1)
	go func() { done <- client.Serve(context.Background(), dial(), 0) }()
	client.Send(json.RawMessage(`{"n":1}`))
	waitFor(t, "first delivery started", func() bool { return count.Load() == 1 })
	client.Detach(websocket.StatusGoingAway, "drop")
	<-done
	// Resume as the bridge does: Actp-Last-Seq from server.LastReceived().
	go client.Serve(context.Background(), dial(), server.LastReceived())
	time.Sleep(500 * time.Millisecond)
	close(release)
	time.Sleep(200 * time.Millisecond)
	if n := count.Load(); n != 1 {
		t.Fatalf("message seq 1 delivered %d times", n)
	}
}

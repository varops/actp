package tunnel

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The test binary plays cloudflared when FAKE_CLOUDFLARED is set.
func TestMain(m *testing.M) {
	switch os.Getenv("FAKE_CLOUDFLARED") {
	case "quick":
		fmt.Fprintln(os.Stderr, "INF Requesting new quick Tunnel on trycloudflare.com...")
		fmt.Fprintln(os.Stderr, "INF |  https://brave-fox-test.trycloudflare.com  |")
		if os.Getenv("FAKE_EXIT") == "1" {
			os.Exit(1)
		}
		time.Sleep(time.Minute)
		os.Exit(0)
	case "named":
		if os.Getenv("TUNNEL_TOKEN") == "" || strings.Contains(strings.Join(os.Args, " "), "secret") {
			fmt.Fprintln(os.Stderr, "ERR token missing or on the command line")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "INF Registered tunnel connection")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestQuickTunnelReportsURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan string, 1)
	tun, err := Start(ctx, Options{
		Mode: "quick", Target: "http://127.0.0.1:1", Binary: os.Args[0],
		Env:   append(os.Environ(), "FAKE_CLOUDFLARED=quick"),
		OnURL: func(u string) { got <- u },
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-got:
		if u != "https://brave-fox-test.trycloudflare.com" || tun.URL() != u {
			t.Fatalf("url %q", u)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no URL")
	}
	cancel()
	select {
	case <-tun.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("cloudflared not stopped")
	}
}

func TestTunnelRestartsAfterExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var urls atomic.Int32
	_, err := Start(ctx, Options{
		Mode: "quick", Target: "http://127.0.0.1:1", Binary: os.Args[0], MaxBackoff: 50 * time.Millisecond,
		Env:   append(os.Environ(), "FAKE_CLOUDFLARED=quick", "FAKE_EXIT=1"),
		OnURL: func(string) { urls.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if urls.Load() >= 1 {
			// Same URL each time: OnURL fires once, but the process restarted.
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("tunnel never came up")
}

func TestNamedTunnelTokenStaysOffTheCommandLine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tun, err := Start(ctx, Options{
		Mode: "named", Token: "secret-token", Binary: os.Args[0],
		Env: append(os.Environ(), "FAKE_CLOUDFLARED=named"),
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-tun.Done()
	for _, a := range tun.args() {
		if strings.Contains(a, "secret") {
			t.Fatal("token on the command line")
		}
	}
	if _, err := Start(context.Background(), Options{Mode: "named", Binary: os.Args[0]}); err == nil {
		t.Fatal("named tunnel without token accepted")
	}
}

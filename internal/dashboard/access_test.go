package dashboard

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func passwordDashboard(t *testing.T, terminal bool) *Dashboard {
	t.Helper()
	d, err := Listen(Options{Version: "test", Password: "letmein", Terminal: terminal})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func login(t *testing.T, base, password string) (*http.Client, int) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	code, _ := do(t, c, "POST", base+"/login", `{"password":"`+password+`"}`, true)
	return c, code
}

func TestPasswordLogin(t *testing.T) {
	d := passwordDashboard(t, false)
	base := strings.TrimSuffix(d.URL(), "/")
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if code, _ := do(t, anon, "GET", base+"/api/status", "", false); code != http.StatusUnauthorized {
		t.Fatalf("status without login = %d", code)
	}
	if code, _ := do(t, anon, "GET", base+"/", "", false); code != http.StatusSeeOther {
		t.Fatalf("page without login = %d, want a redirect to /login", code)
	}
	if code, body := do(t, anon, "GET", base+"/login", "", false); code != 200 || !strings.Contains(body, "password") {
		t.Fatalf("login page = %d", code)
	}
	if _, code := login(t, base, "nope"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d", code)
	}
	c, code := login(t, base, "letmein")
	if code != 200 {
		t.Fatalf("right password = %d", code)
	}
	code, body := do(t, c, "GET", base+"/api/status", "", false)
	if code != 200 || !strings.Contains(body, `"password":true`) {
		t.Fatalf("status after login = %d %s", code, body)
	}
	// Writes need the header, and no other site may send them.
	if code, _ := do(t, c, "POST", base+"/api/logout", "", false); code != http.StatusForbidden {
		t.Fatalf("write without header = %d", code)
	}
	req, _ := http.NewRequest("POST", base+"/api/logout", nil)
	req.Header.Set("X-Actp-Dashboard", "1")
	req.Header.Set("Origin", "http://evil.example")
	if resp, err := c.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site write: %v %v", resp, err)
	}
	if code, _ := do(t, c, "POST", base+"/api/logout", "", true); code != 200 {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := do(t, c, "GET", base+"/api/status", "", false); code != http.StatusUnauthorized {
		t.Fatalf("status after logout = %d", code)
	}
}

func TestPasswordRateLimit(t *testing.T) {
	old := failureWindow
	failureWindow = time.Hour
	t.Cleanup(func() { failureWindow = old })
	d := passwordDashboard(t, false)
	base := strings.TrimSuffix(d.URL(), "/")
	for i := 0; i < maxFailures; i++ {
		login(t, base, "nope")
	}
	if _, code := login(t, base, "letmein"); code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures the right password got %d, want 429", maxFailures, code)
	}
}

func TestTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no terminal on Windows")
	}
	d := passwordDashboard(t, true)
	base := strings.TrimSuffix(d.URL(), "/")
	c, _ := login(t, base, "letmein")
	u, _ := url.Parse(base)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws://"+u.Host+"/api/terminal", &websocket.DialOptions{HTTPClient: c, HTTPHeader: http.Header{"Origin": {base}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_ = ws.Write(ctx, websocket.MessageText, []byte(`{"cols":120,"rows":40}`))
	_ = ws.Write(ctx, websocket.MessageBinary, []byte("echo marker-$((40+2)); exit\n"))
	var out strings.Builder
	for !strings.Contains(out.String(), "marker-42") {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("no marker in %q: %v", out.String(), err)
		}
		out.Write(data)
	}

	// Another site cannot open a terminal, even with the cookie.
	if _, _, err := websocket.Dial(ctx, "ws://"+u.Host+"/api/terminal", &websocket.DialOptions{HTTPClient: c, HTTPHeader: http.Header{"Origin": {"http://evil.example"}}}); err == nil {
		t.Fatal("cross-site terminal opened")
	}
}

func TestTerminalOffByDefault(t *testing.T) {
	d := passwordDashboard(t, false)
	base := strings.TrimSuffix(d.URL(), "/")
	c, _ := login(t, base, "letmein")
	if code, _ := do(t, c, "GET", base+"/api/terminal", "", false); code != http.StatusNotFound {
		t.Fatalf("terminal while off = %d", code)
	}
}

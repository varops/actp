package dashboard

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/server"
)

func setup(t *testing.T) (*Dashboard, *http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	ws := filepath.Join(dir, "site")
	_ = os.MkdirAll(ws, 0o755)
	cfgPath := filepath.Join(dir, "actp.yaml")
	data := "remotes_file: " + filepath.Join(dir, "remotes.yaml") + "\nserver:\n  log_dir: " + filepath.Join(dir, "logs") + "\n  state_dir: " + filepath.Join(dir, "state") + "\n  tokens_file: " + filepath.Join(dir, "tokens.yaml") + "\n  workspaces:\n    - name: site\n      path: " + ws + "\n  agents:\n    - id: a\n      command: /bin/true\n"
	if err := os.WriteFile(cfgPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg.Server, server.Options{BaseEnv: os.Environ(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close(0) })
	reloads := 0
	d, err := Listen(Options{Server: srv, ConfigPath: cfgPath, Version: "test", Reload: func() error {
		reloads++
		c, err := config.Load(cfgPath)
		if err != nil {
			return err
		}
		srv.Reload(c.Server)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	jar, _ := cookiejar.New(nil)
	return d, &http.Client{Jar: jar}, cfgPath
}

func do(t *testing.T, c *http.Client, method, u string, body string, header bool) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	if header {
		req.Header.Set("X-Actp-Dashboard", "1")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestOneTimeLinkAndSession(t *testing.T) {
	d, c, _ := setup(t)
	base := "http://" + d.addr
	if code, _ := do(t, c, "GET", base+"/api/status", "", false); code != 403 {
		t.Fatalf("status without session: %d", code)
	}
	link := d.URL()
	if code, body := do(t, c, "GET", link, "", false); code != 200 || !strings.Contains(body, "<title>actp</title>") {
		t.Fatalf("first visit: %d", code)
	}
	if code, _ := do(t, c, "GET", base+"/api/status", "", false); code != 200 {
		t.Fatalf("status with session: %d", code)
	}
	other := &http.Client{}
	if code, _ := do(t, other, "GET", link, "", false); code != 403 {
		t.Fatalf("reused link: %d", code)
	}
	// DNS rebinding: right port, wrong host name.
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.Host = "evil.example.com"
	if resp, err := c.Do(req); err != nil || resp.StatusCode != 403 {
		t.Fatalf("wrong host: %v %v", resp, err)
	}
	// Writes need the custom header and a same-origin Origin.
	if code, _ := do(t, c, "POST", base+"/api/tokens", `{"name":"x"}`, false); code != 403 {
		t.Fatalf("write without header: %d", code)
	}
	req, _ = http.NewRequest("POST", base+"/api/tokens", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("X-Actp-Dashboard", "1")
	req.Header.Set("Origin", "https://evil.example.com")
	if resp, err := c.Do(req); err != nil || resp.StatusCode != 403 {
		t.Fatalf("cross-site write: %v %v", resp, err)
	}
	if fresh := d.NewLink(); fresh == link {
		t.Fatal("NewLink reused the token")
	}
}

func TestCreateTokenAndRemotes(t *testing.T) {
	keyring.MockInit()
	d, c, cfgPath := setup(t)
	base := "http://" + d.addr
	do(t, c, "GET", d.URL(), "", false)

	code, body := do(t, c, "POST", base+"/api/tokens", `{"name":"bot","agents":["a"],"workspaces":["site"],"defaultWorkspace":"site"}`, true)
	if code != 200 {
		t.Fatalf("create token: %d %s", code, body)
	}
	var res struct{ Token string }
	_ = json.Unmarshal([]byte(body), &res)
	if !strings.HasPrefix(res.Token, config.TokenPrefix) {
		t.Fatalf("token %q", res.Token)
	}
	if d.opts.Server.Config().FindToken(res.Token) == nil {
		t.Fatal("server did not reload the new token")
	}
	if code, _ := do(t, c, "POST", base+"/api/tokens", `{"name":"bot"}`, true); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code, _ := do(t, c, "POST", base+"/api/tokens", `{"name":"x","agents":["nope"]}`, true); code != 400 {
		t.Fatalf("unknown agent: %d", code)
	}

	if code, body := do(t, c, "POST", base+"/api/remotes", `{"name":"box","url":"https://box.example.com","token":"actp_abc"}`, true); code != 200 {
		t.Fatalf("add remote: %d %s", code, body)
	}
	cfg, _ := config.Load(cfgPath)
	r := cfg.Remote("box")
	if r == nil || !r.TokenKeychain {
		t.Fatalf("remote %+v", r)
	}
	if tok, err := config.RemoteToken(r); err != nil || tok != "actp_abc" {
		t.Fatalf("keychain token %q %v", tok, err)
	}
	_, body = do(t, c, "GET", base+"/api/status", "", false)
	if !strings.Contains(body, `"name":"box"`) || strings.Contains(body, "actp_abc") {
		t.Fatalf("status: %s", body)
	}
	if code, _ := do(t, c, "DELETE", base+"/api/remotes/"+url.PathEscape("box"), "", true); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	if _, err := config.RemoteToken(r); err == nil {
		t.Fatal("keychain token kept after remove")
	}
}

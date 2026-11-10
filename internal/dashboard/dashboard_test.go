package dashboard

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	d, err := Listen(Options{Server: func() *server.Server { return srv }, ConfigPath: cfgPath, ConfigFile: cfgPath, Version: "test", Reload: func() error {
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
	if d.opts.Server().Config().FindToken(res.Token) == nil {
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

func TestAutostartToggle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("touches the real registry")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	d, c, _ := setup(t)
	base := "http://" + d.addr
	do(t, c, "GET", d.URL(), "", false)
	if code, body := do(t, c, "POST", base+"/api/autostart", `{"enabled":true}`, true); code != 200 || !strings.Contains(body, `"enabled":true`) {
		t.Fatalf("enable: %d %s", code, body)
	}
	if _, body := do(t, c, "GET", base+"/api/status", "", false); !strings.Contains(body, `"autostart":true`) {
		t.Fatalf("status: %s", body)
	}
	if code, body := do(t, c, "POST", base+"/api/autostart", `{"enabled":false}`, true); code != 200 || !strings.Contains(body, `"enabled":false`) {
		t.Fatalf("disable: %d %s", code, body)
	}
}

func TestSetupWithoutAConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "actp.yaml") // does not exist yet
	ws := filepath.Join(dir, "code")
	_ = os.MkdirAll(ws, 0o755)
	started := 0
	d, err := Listen(Options{
		Server: func() *server.Server { return nil }, ConfigPath: cfgPath, ConfigFile: cfgPath, Version: "test",
		StartServer: func() error { started++; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	base := "http://" + d.addr
	do(t, c, "GET", d.URL(), "", false)

	// A missing config is not an error: the page shows the setup.
	if code, body := do(t, c, "GET", base+"/api/status", "", false); code != 200 || strings.Contains(body, `"server"`) {
		t.Fatalf("status without config: %d %s", code, body)
	}
	if code, body := do(t, c, "GET", base+"/api/setup", "", false); code != 200 || !strings.Contains(body, `"preset":"claude-code"`) {
		t.Fatalf("setup info: %d %s", code, body)
	}
	if code, body := do(t, c, "POST", base+"/api/setup", `{"name":"mac","agents":["claude-code","pi"],"folders":["`+filepath.ToSlash(ws)+`"],"tunnel":true}`, true); code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	if started != 1 {
		t.Fatalf("StartServer called %d times", started)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Server
	if s == nil || s.Name != "mac" || s.Tunnel.Mode != "quick" || s.Agent("claude") == nil || s.Agent("pi") == nil || s.Workspace("code") == nil {
		t.Fatalf("written config: %+v", s)
	}
	if code, _ := do(t, c, "POST", base+"/api/setup", `{"agents":["pi"],"folders":["`+filepath.ToSlash(ws)+`"]}`, true); code != 409 {
		t.Fatalf("second setup: %d", code)
	}
	if code, _ := do(t, c, "POST", base+"/api/setup", `{"agents":["pi"],"folders":["/no/such/folder"]}`, true); code != 409 && code != 400 {
		t.Fatalf("bad folder: %d", code)
	}
}

func TestSetupAppendsToAnExistingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "actp.yaml")
	_ = os.WriteFile(cfgPath, []byte("remotes_file: "+filepath.Join(dir, "remotes.yaml")+"\n# my comment\n"), 0o600)
	if err := appendConfig(cfgPath, []byte("server:\n  listen: 127.0.0.1:7860\n")); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), "# my comment") || !strings.Contains(string(data), "server:") {
		t.Fatalf("file:\n%s", data)
	}
	// A block that breaks the config is rolled back.
	if err := appendConfig(cfgPath, []byte("server:\n  nonsense: [\n")); err == nil {
		t.Fatal("broken config accepted")
	}
	after, _ := os.ReadFile(cfgPath)
	if string(after) != string(data) {
		t.Fatal("broken append was not rolled back")
	}
}

func TestEditFoldersAgentsAndRevoke(t *testing.T) {
	keyring.MockInit()
	d, c, cfgPath := setup(t)
	base := "http://" + d.addr
	do(t, c, "GET", d.URL(), "", false)
	dir := filepath.Dir(cfgPath)
	site, extra := filepath.Join(dir, "site"), filepath.Join(dir, "Extra Stuff")
	_ = os.MkdirAll(extra, 0o755)

	body := `{"folders":[` + strconv.Quote(site) + `,` + strconv.Quote(extra) + `]}`
	if code, out := do(t, c, "PUT", base+"/api/server/folders", body, true); code != 200 {
		t.Fatalf("folders: %d %s", code, out)
	}
	if _, out := do(t, c, "GET", base+"/api/status", "", false); !strings.Contains(out, `"name":"extra-stuff"`) {
		t.Fatalf("status folders: %s", out)
	}
	sc := d.opts.Server().Config()
	if sc.Workspace("site") == nil || sc.Workspace("extra-stuff") == nil {
		t.Fatalf("workspaces after edit: %+v", sc.Workspaces)
	}
	if code, _ := do(t, c, "PUT", base+"/api/server/folders", `{"folders":["/no/such/dir"]}`, true); code != 400 {
		t.Fatalf("bad folder: %d", code)
	}

	if code, out := do(t, c, "PUT", base+"/api/server/agents", `{"presets":["pi"]}`, true); code != 200 {
		t.Fatalf("agents: %d %s", code, out)
	}
	sc = d.opts.Server().Config()
	if sc.Agent("pi") == nil || sc.Agent("a") == nil { // "a" has no preset and is kept
		t.Fatalf("agents after edit: %+v", sc.Agents)
	}

	code, out := do(t, c, "POST", base+"/api/tokens", `{"name":"laptop","agents":["a"],"workspaces":["site"],"defaultWorkspace":"site"}`, true)
	if code != 200 {
		t.Fatalf("token: %d %s", code, out)
	}
	var tok struct{ Token string }
	_ = json.Unmarshal([]byte(out), &tok)
	if _, out := do(t, c, "GET", base+"/api/status", "", false); !strings.Contains(out, `"name":"laptop"`) || !strings.Contains(out, `"revocable":true`) {
		t.Fatalf("status tokens: %s", out)
	}

	// The bridge tab lists a remote's agents with the remote's own token.
	h := httptest.NewServer(d.opts.Server().Handler())
	defer h.Close()
	rbody := `{"name":"self","url":"` + h.URL + `","token":"` + tok.Token + `"}`
	if code, out := do(t, c, "POST", base+"/api/remotes", rbody, true); code != 200 {
		t.Fatalf("remote: %d %s", code, out)
	}
	if code, out := do(t, c, "GET", base+"/api/remotes/self/agents", "", false); code != 200 || !strings.Contains(out, `"id":"a"`) {
		t.Fatalf("remote agents: %d %s", code, out)
	}

	if code, out := do(t, c, "DELETE", base+"/api/tokens/laptop", "", true); code != 200 {
		t.Fatalf("revoke: %d %s", code, out)
	}
	if d.opts.Server().Config().FindToken(tok.Token) != nil {
		t.Fatal("revoked token still accepted")
	}
	if code, out := do(t, c, "GET", base+"/api/remotes/self/agents", "", false); code != 502 || !strings.Contains(out, "did not accept this token") {
		t.Fatalf("remote agents after revoke: %d %s", code, out)
	}
}

func TestRemoteWithNoServerExplainsWhy(t *testing.T) {
	keyring.MockInit()
	d, c, _ := setup(t)
	base := "http://" + d.addr
	do(t, c, "GET", d.URL(), "", false)
	gone := httptest.NewServer(http.NotFoundHandler()) // like an old quick tunnel address
	defer gone.Close()
	if code, out := do(t, c, "POST", base+"/api/remotes", `{"name":"old","url":"`+gone.URL+`","token":"actp_x"}`, true); code != 200 {
		t.Fatalf("add: %d %s", code, out)
	}
	if code, out := do(t, c, "GET", base+"/api/remotes/old/agents", "", false); code != 502 || !strings.Contains(out, "no actp server answers") {
		t.Fatalf("got %d %s", code, out)
	}
	// Point it at a live server (the address changed) and it works again.
	live := httptest.NewServer(d.opts.Server().Handler())
	defer live.Close()
	if code, out := do(t, c, "PUT", base+"/api/remotes/old", `{"url":"`+live.URL+`"}`, true); code != 200 {
		t.Fatalf("update: %d %s", code, out)
	}
	if code, out := do(t, c, "GET", base+"/api/remotes/old/agents", "", false); code != 502 || !strings.Contains(out, "did not accept this token") {
		t.Fatalf("after update: %d %s", code, out)
	}
}

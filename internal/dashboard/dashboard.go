// Package dashboard is the local web page behind the tray (design 5): server
// status, agents, links, adding clients and remotes. It only listens on
// loopback and only answers the browser that opened its one-time link.
package dashboard

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/autostart"
	"github.com/varops/actp/internal/cliinstall"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/installer"
	"github.com/varops/actp/internal/server"
	"github.com/varops/actp/internal/terminal"
	"github.com/varops/actp/internal/tunnel"
)

//go:embed index.html
var indexHTML []byte

//go:embed login.html
var loginHTML []byte

//go:embed static
var staticFS embed.FS

const cookieName = "actp_dashboard"

// Options configure the dashboard.
type Options struct {
	// Server returns the running server, or nil when this machine runs none (yet).
	Server func() *server.Server
	// ConfigPath is the --config value ("" for the default); ConfigFile is the
	// file the dashboard writes when it sets up a server.
	ConfigPath string
	ConfigFile string
	Version    string
	// StartServer starts the server after the dashboard wrote its config.
	StartServer func() error
	// Reload re-reads the config after the dashboard changed tokens.
	Reload func() error
	// StartTunnel starts the configured tunnel, for example after installing cloudflared.
	StartTunnel func() error
	// TunnelError returns cloudflared's last error line, if any.
	TunnelError func() string

	// Listen is the address to serve on; default a random loopback port.
	Listen string
	// Password switches from one-time links to a login form, for a dashboard
	// reached over the network (Docker). Empty means one-time links.
	Password string
	// Terminal adds a shell in the browser.
	Terminal bool
	// Installer installs agents from the dashboard; nil hides it.
	Installer *installer.Installer
	// Env is the environment of terminal shells; nil means os.Environ().
	Env    []string
	Logger *slog.Logger
}

// Dashboard serves the local page.
type Dashboard struct {
	opts    Options
	ln      net.Listener
	addr    string
	once    string // one-time token in the first URL
	session string // cookie value after the first visit
	mu      sync.Mutex
	used    bool
	login   *logins // password mode only
}

// Listen starts the dashboard.
func Listen(opts Options) (*Dashboard, error) {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, err
	}
	d := newDashboard(opts)
	d.ln, d.addr = ln, ln.Addr().String()
	srv := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return d, nil
}

func newDashboard(opts Options) *Dashboard {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	d := &Dashboard{opts: opts, once: randomHex(), session: randomHex()}
	if opts.Password != "" {
		d.login = newLogins(opts.Password)
	}
	if opts.Installer != nil && opts.Installer.OnDone == nil {
		opts.Installer.OnDone = d.AfterInstall
	}
	return d
}

// URL is the link that opens the dashboard. Without a password it is a
// one-time link; open it again through the tray, which calls NewLink.
func (d *Dashboard) URL() string {
	if d.login != nil {
		return "http://" + d.addr + "/"
	}
	return "http://" + d.addr + "/?t=" + d.once
}

// NewLink issues a fresh one-time link, for example when the tray is clicked again.
func (d *Dashboard) NewLink() string {
	d.mu.Lock()
	d.once, d.used = randomHex(), false
	d.mu.Unlock()
	return d.URL()
}

// Close stops the dashboard.
func (d *Dashboard) Close() error { return d.ln.Close() }

func randomHex() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Handler is the dashboard's HTTP handler (exported for tests).
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.index)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /login", d.loginPage)
	mux.HandleFunc("POST /login", d.doLogin)
	mux.HandleFunc("POST /api/logout", d.logout)
	mux.HandleFunc("GET /api/status", d.status)
	mux.HandleFunc("POST /api/links/{id}/end", d.endLink)
	mux.HandleFunc("POST /api/agents/{id}/probe", d.probe)
	mux.HandleFunc("POST /api/tokens", d.createToken)
	mux.HandleFunc("POST /api/remotes", d.addRemote)
	mux.HandleFunc("DELETE /api/remotes/{name}", d.removeRemote)
	mux.HandleFunc("POST /api/autostart", d.setAutostart)
	mux.HandleFunc("POST /api/cloudflared", d.installCloudflared)
	mux.HandleFunc("GET /api/setup", d.setupInfo)
	mux.HandleFunc("PUT /api/server/folders", d.setFolders)
	mux.HandleFunc("PUT /api/server/agents", d.setAgents)
	mux.HandleFunc("DELETE /api/tokens/{name}", d.revokeToken)
	mux.HandleFunc("GET /api/remotes/{name}/agents", d.remoteAgents)
	mux.HandleFunc("PUT /api/remotes/{name}", d.updateRemote)
	mux.HandleFunc("POST /api/cli", d.installCLI)
	mux.HandleFunc("POST /api/setup", d.setup)
	mux.HandleFunc("GET /api/terminal", d.terminal)
	mux.HandleFunc("GET /api/installer", d.installerInfo)
	mux.HandleFunc("GET /api/installer/job", d.installerJob)
	mux.HandleFunc("POST /api/installer/{preset}/{action}", d.installerStart)
	return d.guard(mux)
}

func (d *Dashboard) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

type statusResponse struct {
	Version    string        `json:"version"`
	ConfigPath string        `json:"configPath"`
	Server     *serverStatus `json:"server,omitempty"`
	Remotes    []remoteView  `json:"remotes"`
	Autostart  bool          `json:"autostart"`
	// ActpPath is this actp binary, for agent commands a client can paste.
	ActpPath string `json:"actpPath"`
	// CLI says whether an actp command is on the PATH, and whether it is this one.
	CLI      cliinstall.Status `json:"cli"`
	Features features          `json:"features"`
}

type features struct {
	Terminal  bool `json:"terminal"`
	Installer bool `json:"installer"`
	Password  bool `json:"password"`
}

type serverStatus struct {
	Name      string `json:"name"`
	Listen    string `json:"listen"`
	PublicURL string `json:"publicUrl,omitempty"`
	Tunnel    string `json:"tunnel"`
	// Cloudflared is "ok", "missing" (installable) or "unavailable" (no pinned build for this platform).
	Cloudflared string `json:"cloudflared"`
	// PublicCheck says whether the public URL reached this server at the last check.
	PublicCheck *server.PublicCheck `json:"publicCheck,omitempty"`
	TunnelError string              `json:"tunnelError,omitempty"`
	Agents      []server.AgentState `json:"agents"`
	Links       []linkView          `json:"links"`
	Tokens      []tokenView         `json:"tokens"`
	Workspaces  []string            `json:"workspaces"`
	Folders     []config.Workspace  `json:"folders"`
	Presets     []string            `json:"presets"`
}

type tokenView struct {
	Name       string   `json:"name"`
	Agents     []string `json:"agents"`
	Workspaces []string `json:"workspaces"`
	Revocable  bool     `json:"revocable"`
}

type linkView struct {
	ID         string `json:"id"`
	Agent      string `json:"agent"`
	Token      string `json:"token"`
	ClientName string `json:"clientName"`
	State      string `json:"state"`
	Since      string `json:"since"`
	Running    bool   `json:"running"`
}

type remoteView struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func (d *Dashboard) status(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	resp := statusResponse{Version: d.opts.Version, ConfigPath: cfg.Path(), Remotes: []remoteView{}, Autostart: autostart.Enabled(), ActpPath: actpPath(),
		CLI:      cliinstall.Check(actpPath(), agentproc.Getenv(agentproc.CachedLoginShellEnv(), "PATH")),
		Features: features{Terminal: d.opts.Terminal && terminal.Supported, Installer: d.opts.Installer != nil, Password: d.login != nil}}
	for _, r := range cfg.Remotes {
		resp.Remotes = append(resp.Remotes, remoteView{Name: r.Name, URL: r.URL})
	}
	if srv := d.server(); srv != nil {
		sc := srv.Config()
		st := &serverStatus{Name: sc.Name, Listen: sc.Listen, PublicURL: srv.PublicURL(), Tunnel: string(sc.Tunnel.Mode), Agents: srv.Agents(), Links: []linkView{}, Cloudflared: "ok"}
		if c, ok := srv.LastPublicCheck(); ok {
			st.PublicCheck = &c
		}
		if d.opts.TunnelError != nil {
			st.TunnelError = d.opts.TunnelError()
		}
		if _, err := tunnel.FindBinary(nil); err != nil {
			st.Cloudflared = "unavailable"
			if tunnel.CanDownload() {
				st.Cloudflared = "missing"
			}
		}
		for _, l := range srv.Links() {
			st.Links = append(st.Links, linkView{ID: l.ID, Agent: l.Agent, Token: l.Token, ClientName: l.ClientName, State: l.State, Since: l.Since.UTC().Format("2006-01-02T15:04:05Z"), Running: l.Running})
		}
		inFile := map[string]bool{}
		if tf, err := config.ReadTokensFile(sc.TokensFile); err == nil {
			for _, t := range tf.Tokens {
				inFile[t.Name] = true
			}
		}
		st.Tokens = []tokenView{}
		for _, t := range sc.Tokens {
			st.Tokens = append(st.Tokens, tokenView{Name: t.Name, Agents: t.Agents, Workspaces: t.Workspaces, Revocable: inFile[t.Name]})
		}
		for _, ws := range sc.Workspaces {
			st.Workspaces = append(st.Workspaces, ws.Name)
			st.Folders = append(st.Folders, config.Workspace{Name: ws.Name, Path: ws.Path})
		}
		for _, a := range sc.Agents {
			if a.Preset != "" {
				st.Presets = append(st.Presets, a.Preset)
			}
		}
		resp.Server = st
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Dashboard) server() *server.Server {
	if d.opts.Server == nil {
		return nil
	}
	return d.opts.Server()
}

func (d *Dashboard) endLink(w http.ResponseWriter, r *http.Request) {
	if d.server() == nil || !d.server().EndLink(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, errors.New("no such link"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Dashboard) probe(w http.ResponseWriter, r *http.Request) {
	srv := d.server()
	if srv == nil {
		writeErr(w, http.StatusNotFound, errors.New("no server"))
		return
	}
	sc := srv.Config()
	a := sc.Agent(r.PathValue("id"))
	if a == nil {
		writeErr(w, http.StatusNotFound, errors.New("no such agent"))
		return
	}
	status, detail := srv.Probe(a)
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "detail": detail})
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func (d *Dashboard) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name             string   `json:"name"`
		Agents           []string `json:"agents"`
		Workspaces       []string `json:"workspaces"`
		DefaultWorkspace string   `json:"defaultWorkspace"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !namePattern.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, errors.New("the name may only use letters, digits, '.', '-' and '_'"))
		return
	}
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil || cfg.Server == nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("no server configured: %v", err))
		return
	}
	for _, t := range cfg.Server.Tokens {
		if t.Name == req.Name {
			writeErr(w, http.StatusConflict, fmt.Errorf("a client named %q already exists", req.Name))
			return
		}
	}
	if len(req.Agents) == 0 {
		req.Agents = []string{"*"}
	}
	if len(req.Workspaces) == 0 {
		req.Workspaces = []string{"*"}
	}
	token, hash, err := config.NewToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	entry := config.Token{Name: req.Name, Hash: hash, Agents: req.Agents, Workspaces: req.Workspaces, DefaultWorkspace: req.DefaultWorkspace}
	check, sc, withDefaults := *cfg, *cfg.Server, entry
	config.ApplyTokenDefaults(&withDefaults)
	sc.Tokens = append(append([]config.Token(nil), cfg.Server.Tokens...), withDefaults)
	check.Server = &sc
	if err := check.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	tf, err := config.ReadTokensFile(cfg.Server.TokensFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	tf.Tokens = append(tf.Tokens, entry)
	if err := config.WriteTokensFile(cfg.Server.TokensFile, tf); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if d.opts.Reload != nil {
		if err := d.opts.Reload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("token saved, but reloading failed: %w", err))
			return
		}
	}
	publicURL := ""
	if srv := d.server(); srv != nil {
		publicURL = srv.PublicURL()
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "publicUrl": publicURL})
}

func (d *Dashboard) addRemote(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !namePattern.MatchString(req.Name) || strings.Contains(req.Name, ".") {
		writeErr(w, http.StatusBadRequest, errors.New("the name may only use letters, digits, '-' and '_'"))
		return
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		writeErr(w, http.StatusBadRequest, errors.New("the URL must look like https://host[:port]"))
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" {
		writeErr(w, http.StatusBadRequest, errors.New("a token is required"))
		return
	}
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if cfg.Remote(req.Name) != nil {
		writeErr(w, http.StatusConflict, fmt.Errorf("a remote named %q already exists", req.Name))
		return
	}
	remote := config.Remote{Name: req.Name, URL: strings.TrimSuffix(req.URL, "/")}
	if err := config.SaveRemoteToken(cfg, &remote, req.Token); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rf, err := config.ReadRemotesFile(cfg.RemotesFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rf.Remotes = append(rf.Remotes, remote)
	if err := config.WriteRemotesFile(cfg.RemotesFile, rf); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Dashboard) removeRemote(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rf, err := config.ReadRemotesFile(cfg.RemotesFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	name := r.PathValue("name")
	kept := rf.Remotes[:0]
	found := false
	for _, rm := range rf.Remotes {
		if rm.Name == name {
			found = true
			config.DeleteRemoteToken(cfg, &rm)
			continue
		}
		kept = append(kept, rm)
	}
	if !found {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no saved remote %q (remotes in the config file are edited there)", name))
		return
	}
	rf.Remotes = kept
	if err := config.WriteRemotesFile(cfg.RemotesFile, rf); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (d *Dashboard) installCloudflared(w http.ResponseWriter, r *http.Request) {
	path, err := tunnel.Download(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	resp := map[string]string{"path": path}
	if d.opts.StartTunnel != nil {
		if err := d.opts.StartTunnel(); err != nil {
			resp["tunnelError"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Dashboard) setAutostart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	var err error
	if req.Enabled {
		var exe string
		if exe, err = os.Executable(); err == nil {
			err = autostart.Enable(exe)
		}
	} else {
		err = autostart.Disable()
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": autostart.Enabled()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (d *Dashboard) installCLI(w http.ResponseWriter, r *http.Request) {
	link, err := cliinstall.Install(actpPath(), agentproc.Getenv(agentproc.CachedLoginShellEnv(), "PATH"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": link})
}

func actpPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "actp"
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		return real
	}
	return exe
}

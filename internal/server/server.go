// Package server is `actp serve`: it runs ACP agents and serves them to actp bridges.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/wire"
)

// Options are knobs mostly used by tests.
type Options struct {
	Version string
	// BaseEnv is the environment agents start from. Nil means the login shell's
	// environment when shell_env is on (the default), else os.Environ().
	BaseEnv []string
	Logger  *slog.Logger
	Wire    wire.Options
	// Tick is how often links check their timers (1 s).
	Tick time.Duration
	// ProbeOnStart runs an initialize probe against every agent at start.
	ProbeOnStart bool
	// ReadOnly is for tools like `actp doctor`: no crash cleanup, no audit log.
	ReadOnly bool
}

// Server holds configuration, links and agent status.
type Server struct {
	cfg   atomic.Pointer[config.Server]
	opts  Options
	log   *slog.Logger
	audit *auditLog
	ctx   context.Context
	stop  context.CancelFunc

	publicURL   atomic.Value // string
	publicCheck atomic.Value // PublicCheck

	mu       sync.Mutex
	links    map[string]*Link
	sessions map[string]*Link // agentID + "\x00" + sessionId → link holding it
	status   map[string]*agentStatus
}

type agentStatus struct {
	Status       string
	AuthHint     string
	Error        string
	AgentInfo    *api.AgentInfo
	Capabilities map[string]any
}

// New builds a server for a validated config.
func New(cfg *config.Server, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if opts.Tick == 0 {
		opts.Tick = time.Second
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	ctx, stop := context.WithCancel(context.Background())
	s := &Server{
		opts:     opts,
		log:      opts.Logger,
		ctx:      ctx,
		stop:     stop,
		links:    map[string]*Link{},
		sessions: map[string]*Link{},
		status:   map[string]*agentStatus{},
	}
	s.cfg.Store(cfg)
	if s.opts.BaseEnv == nil {
		if cfg.ShellEnv == nil || *cfg.ShellEnv {
			s.opts.BaseEnv = loginShellEnv(ctx)
		} else {
			s.opts.BaseEnv = os.Environ()
		}
	}
	s.opts.BaseEnv = agentproc.AppendPath(s.opts.BaseEnv, config.AgentBinDir())
	for _, a := range cfg.Agents {
		s.status[a.ID] = &agentStatus{Status: string(api.Unknown)}
	}
	if !opts.ReadOnly {
		audit, err := openAudit(cfg.LogDir)
		if err != nil {
			s.log.Warn("audit log disabled", "error", err)
		}
		s.audit = audit
		s.cleanupLeftovers()
	}
	if opts.ProbeOnStart {
		for i := range cfg.Agents {
			go s.Probe(&cfg.Agents[i])
		}
	}
	return s, nil
}

// conf is the current configuration. Links keep the agent settings they started with.
func (s *Server) conf() *config.Server { return s.cfg.Load() }

// Reload switches to a new configuration. New links and new requests use it;
// open links keep running with the settings they started with. A revoked token
// cannot open or resume links any more.
func (s *Server) Reload(cfg *config.Server) {
	s.mu.Lock()
	for _, a := range cfg.Agents {
		if s.status[a.ID] == nil {
			s.status[a.ID] = &agentStatus{Status: string(api.Unknown)}
		}
	}
	s.mu.Unlock()
	s.cfg.Store(cfg)
	s.log.Info("configuration reloaded", "agents", len(cfg.Agents), "tokens", len(cfg.Tokens))
	if s.opts.ProbeOnStart {
		for i := range cfg.Agents {
			go s.Probe(&cfg.Agents[i])
		}
	}
}

// SetPublicURL records the tunnel's public URL for /api/v1/info.
func (s *Server) SetPublicURL(u string) { s.publicURL.Store(u) }

// Handler serves the HTTP API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	api.HandlerWithOptions(s, api.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		},
	})
	return s.authMiddleware(mux)
}

// Close ends every link, settling its agent, and waits up to grace for running turns.
func (s *Server) Close(grace time.Duration) {
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) && s.anyTurnRunning() {
		time.Sleep(100 * time.Millisecond)
	}
	s.mu.Lock()
	links := make([]*Link, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, l := range links {
		wg.Add(1)
		go func() { defer wg.Done(); l.end(wire.ErrServerShutdown, "server is stopping") }()
	}
	wg.Wait()
	for _, l := range links {
		l.finalize()
	}
	s.stop()
	s.audit.close()
}

func (s *Server) anyTurnRunning() bool {
	s.mu.Lock()
	links := make([]*Link, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()
	for _, l := range links {
		if l.turnRunning() {
			return true
		}
	}
	return false
}

// LinkInfo describes a link for the tray and the CLI.
type LinkInfo struct {
	ID         string
	Agent      string
	Token      string
	ClientName string
	State      string
	Since      time.Time
	Running    bool
}

// Links lists the open links.
func (s *Server) Links() []LinkInfo {
	s.mu.Lock()
	links := make([]*Link, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	s.mu.Unlock()
	out := make([]LinkInfo, 0, len(links))
	for _, l := range links {
		if info := l.info(); info.State != StateEnded {
			out = append(out, info)
		}
	}
	return out
}

// EndLink ends a link on an operator's request.
func (s *Server) EndLink(id string) bool {
	s.mu.Lock()
	l := s.links[id]
	s.mu.Unlock()
	if l == nil {
		return false
	}
	l.end(wire.ErrEndedByAdmin, "ended by an operator")
	l.finalize()
	return true
}

func (s *Server) setStatus(agentID string, update func(*agentStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status[agentID]
	if st == nil {
		st = &agentStatus{}
		s.status[agentID] = st
	}
	update(st)
}

type ctxKey struct{}

func tokenFrom(ctx context.Context) *config.Token {
	t, _ := ctx.Value(ctxKey{}).(*config.Token)
	return t
}

// authMiddleware requires a token on everything except /health. There is no
// exception for local connections: a tunnel makes remote traffic look local.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok := s.conf().FindToken(strings.TrimSpace(presented))
		if !ok || tok == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="actp"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, tok)))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, api.Error{Error: code, Message: &message})
}

// statePath is where the server records agent process ids, for crash cleanup.
func (s *Server) statePath() string {
	return filepath.Join(s.conf().StateDir, "agents.json")
}

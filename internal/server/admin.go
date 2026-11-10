package server

import (
	"time"

	"github.com/varops/actp/internal/config"
)

// Config is the configuration the server runs with now.
func (s *Server) Config() *config.Server { return s.conf() }

// PublicURL is the tunnel's public URL, if any.
func (s *Server) PublicURL() string {
	u, _ := s.publicURL.Load().(string)
	return u
}

// AgentState is an agent's status for the dashboard and the tray.
type AgentState struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	AuthHint string `json:"authHint,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Agents lists every configured agent with its last known status.
func (s *Server) Agents() []AgentState {
	cfg := s.conf()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AgentState, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		st := AgentState{ID: a.ID, Name: a.Name, Status: "unknown"}
		if cur := s.status[a.ID]; cur != nil {
			st.Status, st.AuthHint, st.Error = cur.Status, cur.AuthHint, cur.Error
		}
		out = append(out, st)
	}
	return out
}

// PublicCheck is the result of the last check of the public URL from outside.
type PublicCheck struct {
	OK     bool      `json:"ok"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// SetPublicCheck records whether the public URL answered.
func (s *Server) SetPublicCheck(c PublicCheck) { s.publicCheck.Store(c) }

// LastPublicCheck returns the last public URL check, if any.
func (s *Server) LastPublicCheck() (PublicCheck, bool) {
	c, ok := s.publicCheck.Load().(PublicCheck)
	return c, ok
}

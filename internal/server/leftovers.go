package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/varops/actp/internal/agentproc"
)

func loginShellEnv(ctx context.Context) []string { return agentproc.LoginShellEnv(ctx) }

// recordPIDs writes the running agents' process ids, so a crashed server can
// stop them on its next start.
func (s *Server) recordPIDs() {
	s.mu.Lock()
	pids := make([]int, 0, len(s.links))
	for _, l := range s.links {
		pids = append(pids, l.proc.PID())
	}
	s.mu.Unlock()
	if err := os.MkdirAll(s.conf().StateDir, 0o700); err != nil {
		return
	}
	data, _ := json.Marshal(map[string]any{"serverPid": os.Getpid(), "agentPids": pids})
	tmp := s.statePath() + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.statePath())
	}
}

func (s *Server) spoolDir() string { return filepath.Join(s.conf().StateDir, "spool") }

// cleanupLeftovers stops agents left running by a server that crashed, and
// deletes spool files, which can hold code and secrets.
func (s *Server) cleanupLeftovers() {
	purgeSpool := func() {
		if entries, err := os.ReadDir(s.spoolDir()); err == nil {
			for _, e := range entries {
				_ = os.Remove(filepath.Join(s.spoolDir(), e.Name()))
			}
		}
	}
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		purgeSpool()
		return
	}
	var st struct {
		ServerPID int   `json:"serverPid"`
		AgentPIDs []int `json:"agentPids"`
	}
	if json.Unmarshal(data, &st) != nil {
		return
	}
	if st.ServerPID != os.Getpid() && processAlive(st.ServerPID) {
		s.log.Warn("another actp server seems to be running with the same state folder", "pid", st.ServerPID, "state", filepath.Dir(s.statePath()))
		return
	}
	purgeSpool()
	for _, pid := range st.AgentPIDs {
		if processAlive(pid) {
			s.log.Info("stopping agent left over from an earlier run", "pid", pid)
			agentproc.KillGroupByPID(pid)
		}
	}
	_ = os.Remove(s.statePath())
}

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/jsonrpc"
)

// ProbeTimeout bounds how long an agent may take to answer initialize.
const ProbeTimeout = 10 * time.Second

// Probe starts an agent, runs initialize without a session, and records the
// result for /api/v1/agents (design 3.4). It returns the recorded status.
func (s *Server) Probe(agent *config.Agent) (status, detail string) {
	result, err := probeAgent(agent, s.opts.BaseEnv, homeDir())
	s.setStatus(agent.ID, func(st *agentStatus) {
		switch {
		case err != nil:
			st.Status, st.Error = string(api.Unavailable), err.Error()
		case result.authHint != "" && st.Status == string(api.AuthRequired):
			st.AuthHint = result.authHint
		default:
			if st.Status != string(api.AuthRequired) {
				st.Status, st.Error = string(api.Ready), ""
			}
			st.AuthHint = result.authHint
		}
		if result != nil {
			st.AgentInfo, st.Capabilities = result.info, result.caps
		}
		status, detail = st.Status, st.Error
		if st.Status == string(api.AuthRequired) {
			detail = st.AuthHint
		}
	})
	return status, detail
}

type probeResult struct {
	info     *api.AgentInfo
	caps     map[string]any
	authHint string
}

func probeAgent(agent *config.Agent, baseEnv []string, dir string) (*probeResult, error) {
	proc, err := agentproc.Start(agentproc.Spec{
		Command: agent.Command, Args: agent.Args, Dir: dir,
		BaseEnv: baseEnv, Env: agent.Env, EnvRemove: agent.EnvRemove,
	})
	if err != nil {
		return nil, err
	}
	defer proc.Stop(2 * time.Second)

	req, _ := jsonrpc.NewRequest(json.RawMessage(`"actp-probe"`), "initialize", map[string]any{
		"protocolVersion":    1,
		"clientCapabilities": map[string]any{},
		"clientInfo":         map[string]any{"name": "actp", "title": "actp probe"},
	})
	if err := jsonrpc.NewWriter(proc.Stdin).Write(req); err != nil {
		return nil, err
	}
	answer := make(chan *jsonrpc.Message, 1)
	go func() {
		rd := jsonrpc.NewReader(proc.Stdout)
		for {
			m, raw, err := rd.Read()
			if err != nil {
				if m == nil && raw != nil {
					continue
				}
				close(answer)
				return
			}
			if m.Kind() == jsonrpc.KindResponse && m.IDKey() == `"actp-probe"` {
				answer <- m
				return
			}
		}
	}()
	select {
	case m, ok := <-answer:
		if !ok {
			<-proc.Done()
			return nil, fmt.Errorf("exited with code %d before answering initialize: %s", proc.ExitCode(), lastLine(proc.Stderr()))
		}
		if m.Error != nil {
			return nil, fmt.Errorf("initialize failed: %s", m.Error.Message)
		}
		var r struct {
			AgentInfo         *api.AgentInfo `json:"agentInfo"`
			AgentCapabilities map[string]any `json:"agentCapabilities"`
			AuthMethods       []struct {
				Description string `json:"description"`
				Name        string `json:"name"`
			} `json:"authMethods"`
		}
		_ = json.Unmarshal(m.Result, &r)
		res := &probeResult{info: r.AgentInfo, caps: r.AgentCapabilities}
		for _, am := range r.AuthMethods {
			if am.Description != "" {
				res.authHint = am.Description
				break
			}
		}
		return res, nil
	case <-time.After(ProbeTimeout):
		return nil, errors.New("did not answer initialize within 10 s")
	}
}

func lastLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '\n' {
			return s[i+1:]
		}
	}
	if s == "" {
		return "no output on stderr"
	}
	return s
}

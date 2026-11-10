package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/coder/websocket"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/wire"
)

var _ api.ServerInterface = (*Server)(nil)

func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, api.Health{Ok: true})
}

func (s *Server) GetInfo(w http.ResponseWriter, r *http.Request) {
	info := api.Info{
		Version:              s.opts.Version,
		WireVersions:         wire.Versions,
		PromptTimeoutSeconds: int(s.conf().PromptTimeout.D().Seconds()),
	}
	if u, _ := s.publicURL.Load().(string); u != "" {
		info.PublicUrl = &u
	}
	if s.conf().Name != "" {
		info.Name = &s.conf().Name
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) ListAgents(w http.ResponseWriter, r *http.Request) {
	tok := tokenFrom(r.Context())
	out := api.AgentList{Agents: []api.Agent{}}
	workspaces := tok.AllowedWorkspaces(s.conf())
	for i := range s.conf().Agents {
		a := &s.conf().Agents[i]
		if !tok.AllowsAgent(a.ID) {
			continue
		}
		entry := api.Agent{Id: a.ID, Workspaces: []api.Workspace{}}
		if a.Name != "" {
			entry.Name = &a.Name
		}
		if a.Description != "" {
			entry.Description = &a.Description
		}
		for _, name := range workspaces {
			ws := api.Workspace{Name: name}
			if name == tok.DefaultWorkspace {
				def := true
				ws.Default = &def
			}
			entry.Workspaces = append(entry.Workspaces, ws)
		}
		s.mu.Lock()
		st := *s.status[a.ID]
		s.mu.Unlock()
		entry.Status = api.AgentStatus(st.Status)
		if st.AuthHint != "" {
			entry.AuthHint = &st.AuthHint
		}
		if st.Error != "" {
			entry.Error = &st.Error
		}
		entry.AgentInfo = st.AgentInfo
		if st.Capabilities != nil {
			caps := st.Capabilities
			entry.AgentCapabilities = &caps
		}
		out.Agents = append(out.Agents, entry)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) OpenLink(w http.ResponseWriter, r *http.Request, agentID api.AgentId, params api.OpenLinkParams) {
	tok := tokenFrom(r.Context())
	agent := s.conf().Agent(agentID)
	if agent == nil {
		writeError(w, http.StatusNotFound, "unknown_agent", "no agent named "+agentID)
		return
	}
	if !tok.AllowsAgent(agentID) {
		writeError(w, http.StatusForbidden, "forbidden", "this token may not use agent "+agentID)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		writeError(w, http.StatusUpgradeRequired, "upgrade_required", "the link endpoint needs a WebSocket upgrade")
		return
	}
	if !offersVersion(r.Header.Values("Sec-WebSocket-Protocol")) {
		writeError(w, http.StatusUpgradeRequired, "no_common_version", "supported wire versions: "+strings.Join(wire.Versions, ", "))
		return
	}

	var link *Link
	var lastSeq int64
	if params.ActpLinkId != nil {
		s.mu.Lock()
		link = s.links[*params.ActpLinkId]
		s.mu.Unlock()
		if link == nil || !link.resumable() {
			writeError(w, http.StatusGone, "link_gone", "the link has ended")
			return
		}
		if link.token.Name != tok.Name {
			writeError(w, http.StatusConflict, "wrong_token", "the link belongs to another token")
			return
		}
		if params.ActpLastSeq != nil {
			lastSeq = *params.ActpLastSeq
		}
	} else {
		if msg := s.overLimit(agentID, tok.Name, agent.MaxLinks, tok.MaxLinks); msg != "" {
			w.Header().Set("Retry-After", "30")
			writeError(w, http.StatusTooManyRequests, "too_many_links", msg)
			return
		}
		clientName := ""
		if params.ActpClientName != nil {
			clientName = *params.ActpClientName
		}
		var err error
		link, err = s.startLink(agent, tok, clientName)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "agent_unavailable", err.Error())
			return
		}
	}

	w.Header().Set(wire.HeaderLinkID, link.id)
	w.Header().Set(wire.HeaderLastSeq, strconv.FormatInt(link.ep.LastReceived(), 10))
	w.Header().Set(wire.HeaderPromptTimeout, strconv.Itoa(int(s.conf().PromptTimeout.D().Seconds())))
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       wire.Versions,
		InsecureSkipVerify: true, // bridges are not browsers; the token is the check
	})
	if err != nil {
		if params.ActpLinkId == nil {
			link.end(wire.ErrLinkEnded, "upgrade failed")
		}
		return
	}
	conn.SetReadLimit(16 << 20)
	link.serve(conn, lastSeq)
}

func offersVersion(headers []string) bool {
	for _, h := range headers {
		for _, v := range strings.Split(h, ",") {
			for _, have := range wire.Versions {
				if strings.TrimSpace(v) == have {
					return true
				}
			}
		}
	}
	return false
}

func (s *Server) overLimit(agentID, tokenName string, agentMax, tokenMax int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	perAgent, perToken := 0, 0
	for _, l := range s.links {
		if l.agent.ID == agentID {
			perAgent++
		}
		if l.token.Name == tokenName {
			perToken++
		}
	}
	switch {
	case perAgent >= agentMax:
		return "agent " + agentID + " has reached its link limit"
	case perToken >= tokenMax:
		return "this token has reached its link limit"
	}
	return ""
}

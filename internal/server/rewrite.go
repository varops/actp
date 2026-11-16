package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/varops/actp/internal/config"
)

// WorkspaceScheme is the cwd form that names a workspace: actp://<workspace>/<sub/path>.
const WorkspaceScheme = "actp://"

var errCwdNotAllowed = errors.New("cwd not allowed")

// resolveCwd maps a client cwd to a folder on this machine (design 3.3).
func resolveCwd(s *config.Server, tok *config.Token, cwd string) (string, error) {
	allowed := map[string]bool{}
	for _, name := range tok.AllowedWorkspaces(s) {
		allowed[name] = true
	}
	inWorkspace := func(name, sub string) (string, error) {
		ws := s.Workspace(name)
		if ws == nil || !allowed[name] {
			return "", fmt.Errorf("%w: %s (unknown workspace %q)", errCwdNotAllowed, cwd, name)
		}
		root := realPath(ws.Path)
		target := realPath(filepath.Join(root, filepath.FromSlash(sub)))
		if !within(target, root) {
			return "", fmt.Errorf("%w: %s (leaves workspace %q)", errCwdNotAllowed, cwd, name)
		}
		return target, nil
	}

	if rest, ok := strings.CutPrefix(cwd, WorkspaceScheme); ok {
		name, sub, _ := strings.Cut(rest, "/")
		return inWorkspace(name, sub)
	}
	if filepath.IsAbs(cwd) {
		target := realPath(cwd)
		for _, w := range s.Workspaces {
			if allowed[w.Name] && within(target, realPath(w.Path)) {
				return target, nil
			}
		}
	}
	// Longest matching prefix wins, so nested mappings behave.
	clean := filepath.ToSlash(filepath.Clean(cwd))
	keys := make([]string, 0, len(tok.Map))
	for k := range tok.Map {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, from := range keys {
		f := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(from)), "/")
		if clean == f || strings.HasPrefix(clean, f+"/") {
			return inWorkspace(tok.Map[from], strings.TrimPrefix(strings.TrimPrefix(clean, f), "/"))
		}
	}
	if tok.CwdFallback && tok.DefaultWorkspace != "" {
		return inWorkspace(tok.DefaultWorkspace, "")
	}
	return "", fmt.Errorf("%w: %s", errCwdNotAllowed, cwd)
}

// realPath cleans a path and resolves symlinks for the part that exists.
func realPath(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	// Resolve the nearest existing parent, keep the rest as written.
	dir, rest := p, ""
	for {
		parent := filepath.Dir(dir)
		rest = filepath.Join(filepath.Base(dir), rest)
		if parent == dir {
			return p
		}
		dir = parent
		if r, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(r, rest)
		}
	}
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// resolveAdditionalDirectories applies the cwd rules to every entry of
// additionalDirectories (design 3.3), without the token's cwd_fallback: an
// unknown folder must not silently become the default workspace. null stays null.
func resolveAdditionalDirectories(s *config.Server, tok *config.Token, raw json.RawMessage) (json.RawMessage, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return raw, nil
	}
	var dirs []string
	if err := json.Unmarshal(raw, &dirs); err != nil {
		return nil, errors.New("additionalDirectories must be a list of folders")
	}
	strict := *tok
	strict.CwdFallback = false
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		r, err := resolveCwd(s, &strict, d)
		if err != nil {
			return nil, fmt.Errorf("additional directory not allowed: %s", strings.TrimPrefix(err.Error(), "cwd not allowed: "))
		}
		out = append(out, r)
	}
	return json.Marshal(out)
}

// keepMetaKeys keeps only the allow-listed top-level keys of a session request's
// _meta (agent setting keep_session_meta, empty by default). Agents read _meta as
// options (Claude's adapter takes SDK options and MCP servers from it), so by
// default it is dropped. A nil result means: drop _meta.
func keepMetaKeys(raw json.RawMessage, keep []string) json.RawMessage {
	if len(keep) == 0 {
		return nil
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(raw, &meta) != nil || meta == nil {
		return nil
	}
	kept := map[string]json.RawMessage{}
	for _, k := range keep {
		if v, ok := meta[k]; ok {
			kept[k] = v
		}
	}
	if len(kept) == 0 {
		return nil
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return nil
	}
	return out
}

// Session methods that take no folders, MCP servers or session options, so they
// pass through as they are.
var sessionPlain = map[string]bool{
	"session/prompt": true, "session/cancel": true, "session/close": true, "session/set_mode": true,
	"session/set_model": true, "session/set_config_option": true, "session/status": true,
	"session/set_title": true, "session/delete": true, "session/archive": true, "session/unarchive": true,
}

// policyFields are the params actp checks on session requests.
var policyFields = []string{"cwd", "additionalDirectories", "mcpServers", "_meta"}

// uncheckedSessionField reports the first policy field carried by a session
// method actp does not know: such a message could create or re-target a session
// past the checks, so it is refused instead of forwarded (default deny).
func uncheckedSessionField(method string, p map[string]json.RawMessage) string {
	if !strings.HasPrefix(method, "session/") || sessionPlain[method] || sessionCwdRequired[method] || sessionCwdOptional[method] {
		return ""
	}
	for _, f := range policyFields {
		if _, ok := p[f]; ok {
			return f
		}
	}
	return ""
}

func uncheckedSessionMessage(method, field string) string {
	return fmt.Sprintf("invalid request: actp does not know %s and cannot check its %q", method, field)
}

// stripClientCapabilities removes fs and terminal from initialize params (design 3.3).
func stripClientCapabilities(params json.RawMessage) (json.RawMessage, error) {
	var p map[string]json.RawMessage
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if raw, ok := p["clientCapabilities"]; ok {
		var caps map[string]json.RawMessage
		if err := json.Unmarshal(raw, &caps); err == nil {
			delete(caps, "fs")
			delete(caps, "terminal")
			p["clientCapabilities"], _ = json.Marshal(caps)
		}
	}
	return json.Marshal(p)
}

// stripTerminalAuth removes terminal-login hints from an initialize result,
// because the client would run that login on its own machine.
func stripTerminalAuth(result json.RawMessage) (json.RawMessage, bool) {
	var r map[string]json.RawMessage
	if err := json.Unmarshal(result, &r); err != nil {
		return result, false
	}
	changed := false
	if raw, ok := r["authMethods"]; ok {
		var methods []map[string]json.RawMessage
		if json.Unmarshal(raw, &methods) == nil {
			for _, m := range methods {
				if dropMetaKey(m, "terminal-auth") {
					changed = true
				}
			}
			r["authMethods"], _ = json.Marshal(methods)
		}
	}
	if raw, ok := r["agentCapabilities"]; ok {
		var caps map[string]json.RawMessage
		if json.Unmarshal(raw, &caps) == nil && dropMetaKey(caps, "terminal-auth") {
			r["agentCapabilities"], _ = json.Marshal(caps)
			changed = true
		}
	}
	if !changed {
		return result, false
	}
	out, err := json.Marshal(r)
	if err != nil {
		return result, false
	}
	return out, true
}

func dropMetaKey(obj map[string]json.RawMessage, key string) bool {
	raw, ok := obj["_meta"]
	if !ok {
		return false
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(raw, &meta) != nil {
		return false
	}
	if _, ok := meta[key]; !ok {
		return false
	}
	delete(meta, key)
	if len(meta) == 0 {
		delete(obj, "_meta")
	} else {
		obj["_meta"], _ = json.Marshal(meta)
	}
	return true
}

// filterMCPServers applies a token's MCP policy (design 3.3). It returns the
// kept entries and a short description of each dropped one.
func filterMCPServers(policy string, servers json.RawMessage) (json.RawMessage, []string) {
	var list []map[string]json.RawMessage
	if len(servers) == 0 || json.Unmarshal(servers, &list) != nil {
		return servers, nil
	}
	kept := make([]map[string]json.RawMessage, 0, len(list))
	var dropped []string
	for _, entry := range list {
		name := stringField(entry, "name")
		typ := stringField(entry, "type")
		if typ == "" {
			typ = "stdio"
		}
		switch {
		case policy == "all":
			kept = append(kept, entry)
		case policy == "none":
			dropped = append(dropped, name+" (mcp_servers: none)")
		case typ == "stdio":
			dropped = append(dropped, name+" (stdio would run a command on the agent host)")
		case isLoopbackURL(stringField(entry, "url")):
			dropped = append(dropped, name+" (localhost means the agent host, not the client)")
		default:
			kept = append(kept, entry)
		}
	}
	out, _ := json.Marshal(kept)
	return out, dropped
}

func stringField(obj map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(obj[key], &s)
	return s
}

func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// homeDir is where agents start when the token has no workspace.
func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/"
}

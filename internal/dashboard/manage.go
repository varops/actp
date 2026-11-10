package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/config"
)

// setFolders replaces the server's workspaces. Folders that stay keep their
// names, so tokens that point at them keep working.
func (d *Dashboard) setFolders(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Folders []string `json:"folders"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil || cfg.Server == nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("no server configured: %v", err))
		return
	}
	existing := map[string]string{} // path → name
	used := map[string]bool{}
	for _, ws := range cfg.Server.Workspaces {
		existing[filepath.Clean(ws.Path)] = ws.Name
	}
	var out []config.Workspace
	for _, f := range req.Folders {
		path := filepath.Clean(config.ExpandHome(strings.TrimSpace(f)))
		if strings.TrimSpace(f) == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("%q is not a full path", f))
			return
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("%s is not a folder", path))
			return
		}
		name, ok := existing[path]
		if !ok || used[name] {
			name = uniqueName(folderName(path), used, existing)
		}
		used[name] = true
		out = append(out, config.Workspace{Name: name, Path: path})
	}
	if len(out) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("keep at least one folder"))
		return
	}
	d.applyServerList(w, "workspaces", out)
}

func folderName(path string) string {
	name := strings.Trim(wsName.ReplaceAllString(strings.ToLower(filepath.Base(path)), "-"), "-")
	if name == "" {
		return "workspace"
	}
	return name
}

func uniqueName(base string, used map[string]bool, existing map[string]string) string {
	taken := func(n string) bool {
		if used[n] {
			return true
		}
		for _, e := range existing {
			if e == n {
				return true
			}
		}
		return false
	}
	name := base
	for i := 2; taken(name); i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// setAgents turns preset agents on and off. Agents written by hand (without a
// preset) are kept as they are.
func (d *Dashboard) setAgents(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Presets []string `json:"presets"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	want := map[string]bool{}
	for _, p := range req.Presets {
		if _, ok := config.Presets[p]; !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown agent %q", p))
			return
		}
		want[p] = true
	}
	current, err := config.ReadServerList(d.opts.ConfigFile, "agents")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var out []yaml.MapSlice
	have := map[string]bool{}
	for _, a := range current {
		preset, _ := mapValue(a, "preset").(string)
		if preset == "" || want[preset] {
			out = append(out, a)
			have[preset] = true
		}
	}
	for _, p := range req.Presets {
		if !have[p] {
			out = append(out, yaml.MapSlice{{Key: "id", Value: setupID(p)}, {Key: "preset", Value: p}})
		}
	}
	if len(out) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("keep at least one agent"))
		return
	}
	d.applyServerList(w, "agents", out)
}

func mapValue(m yaml.MapSlice, key string) any {
	for _, it := range m {
		if k, _ := it.Key.(string); k == key {
			return it.Value
		}
	}
	return nil
}

func (d *Dashboard) applyServerList(w http.ResponseWriter, key string, value any) {
	if err := config.SetServerList(d.opts.ConfigFile, key, value); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if d.opts.Reload != nil {
		if err := d.opts.Reload(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("saved, but reloading failed: %w", err))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// revokeToken removes a token the dashboard or `actp token` created.
func (d *Dashboard) revokeToken(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil || cfg.Server == nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("no server configured: %v", err))
		return
	}
	tf, err := config.ReadTokensFile(cfg.Server.TokensFile)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	name := r.PathValue("name")
	kept := tf.Tokens[:0]
	found := false
	for _, t := range tf.Tokens {
		if t.Name == name {
			found = true
			continue
		}
		kept = append(kept, t)
	}
	if !found {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no token %q in %s (tokens written in the config file are removed there)", name, cfg.Server.TokensFile))
		return
	}
	tf.Tokens = kept
	if err := config.WriteTokensFile(cfg.Server.TokensFile, tf); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if d.opts.Reload != nil {
		if err := d.opts.Reload(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// remoteAgents asks a saved remote which agents it offers this token.
func (d *Dashboard) remoteAgents(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	rm := cfg.Remote(r.PathValue("name"))
	if rm == nil {
		writeErr(w, http.StatusNotFound, errors.New("no such remote"))
		return
	}
	token, err := config.RemoteToken(rm)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	client, err := api.NewClientWithResponses(rm.URL, api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resp, err := client.ListAgentsWithResponse(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("could not reach %s: %w", rm.URL, err))
		return
	}
	if resp.JSON200 == nil {
		msg := strings.TrimSpace(string(resp.Body))
		if resp.StatusCode() == http.StatusUnauthorized {
			msg = "the server did not accept this token"
		}
		writeErr(w, http.StatusBadGateway, fmt.Errorf("%s answered HTTP %d: %s", rm.URL, resp.StatusCode(), msg))
		return
	}
	writeJSON(w, http.StatusOK, resp.JSON200)
}

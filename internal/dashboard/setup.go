package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
)

// Agent ids the setup uses for presets, so bridge commands read naturally (claude@host).
var setupIDs = map[string]string{"claude-code": "claude"}

func setupID(preset string) string {
	if id, ok := setupIDs[preset]; ok {
		return id
	}
	return preset
}

type detectedAgent struct {
	Preset string `json:"preset"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

var installHints = map[string]string{
	"claude-code": "npm install -g @agentclientprotocol/claude-agent-acp",
	"codex":       "npm install -g @agentclientprotocol/codex-acp",
	"pi":          "npm install -g pi-acp",
	"opencode":    "npm install -g opencode-ai",
	"gemini":      "npm install -g @google/gemini-cli",
}

// setupInfo tells the page what it can offer: agents found on this machine and a starting folder.
func (d *Dashboard) setupInfo(w http.ResponseWriter, r *http.Request) {
	env := agentproc.CachedLoginShellEnv()
	var agents []detectedAgent
	for name, p := range config.Presets {
		a := detectedAgent{Preset: name, ID: setupID(name), Name: p.Name, Hint: installHints[name]}
		if path, err := agentproc.LookPath(p.Command, env); err == nil {
			a.Path = path
		}
		agents = append(agents, a)
	}
	sort.Slice(agents, func(i, j int) bool {
		if (agents[i].Path != "") != (agents[j].Path != "") {
			return agents[i].Path != ""
		}
		return agents[i].Name < agents[j].Name
	})
	home, _ := os.UserHomeDir()
	folder := home
	for _, guess := range []string{"code", "Code", "src", "Projects", "projects", "dev", "Developer"} {
		if info, err := os.Stat(filepath.Join(home, guess)); err == nil && info.IsDir() {
			folder = filepath.Join(home, guess)
			break
		}
	}
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".") // m1pro.cable.example.net → m1pro
	writeJSON(w, http.StatusOK, map[string]any{
		"agents":     agents,
		"folder":     folder,
		"name":       strings.TrimSuffix(host, ".local"),
		"configFile": d.opts.ConfigFile,
	})
}

type setupRequest struct {
	Name    string   `json:"name"`
	Agents  []string `json:"agents"`  // preset names
	Folders []string `json:"folders"` // absolute paths
	Tunnel  bool     `json:"tunnel"`
}

// The server section the setup writes, in the order a person would read it.
type setupServer struct {
	Name   string `yaml:"name,omitempty"`
	Listen string `yaml:"listen"`
	Tunnel struct {
		Mode string `yaml:"mode"`
	} `yaml:"tunnel"`
	Workspaces []config.Workspace `yaml:"workspaces"`
	Agents     []setupAgent       `yaml:"agents"`
}

type setupAgent struct {
	ID     string `yaml:"id"`
	Preset string `yaml:"preset"`
}

var wsName = regexp.MustCompile(`[^a-z0-9_-]+`)

// setup writes a server section into the config and starts the server.
func (d *Dashboard) setup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if cfg.Server != nil {
		writeErr(w, http.StatusConflict, errors.New("this machine already has a server section in its config"))
		return
	}
	if len(req.Agents) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("pick at least one agent"))
		return
	}
	if len(req.Folders) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("pick at least one folder for the agents to work in"))
		return
	}
	sec := setupServer{Name: strings.TrimSpace(req.Name), Listen: "127.0.0.1:7860"}
	sec.Tunnel.Mode = "off"
	if req.Tunnel {
		sec.Tunnel.Mode = "quick"
	}
	for _, p := range req.Agents {
		if _, ok := config.Presets[p]; !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown agent %q", p))
			return
		}
		sec.Agents = append(sec.Agents, setupAgent{ID: setupID(p), Preset: p})
	}
	used := map[string]bool{}
	for _, f := range req.Folders {
		path := config.ExpandHome(strings.TrimSpace(f))
		if !filepath.IsAbs(path) {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("%q is not a full path", f))
			return
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("%s is not a folder", path))
			return
		}
		name := strings.Trim(wsName.ReplaceAllString(strings.ToLower(filepath.Base(path)), "-"), "-")
		if name == "" {
			name = "workspace"
		}
		for base, i := name, 2; used[name]; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		used[name] = true
		sec.Workspaces = append(sec.Workspaces, config.Workspace{Name: name, Path: path})
	}
	out, err := yaml.Marshal(map[string]setupServer{"server": sec})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := appendConfig(d.opts.ConfigFile, out); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if d.opts.StartServer != nil {
		if err := d.opts.StartServer(); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("the config was saved, but the server did not start: %w", err))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configFile": d.opts.ConfigFile})
}

// appendConfig adds a block to the config file (creating it), and checks the
// result still loads; if not, the file is put back as it was.
func appendConfig(path string, block []byte) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var next []byte
	if len(old) == 0 {
		next = append([]byte("# actp configuration. See docs/design.md section 2.4.\nversion: 1\n\n"), block...)
	} else {
		next = append([]byte{}, old...)
		if next[len(next)-1] != '\n' {
			next = append(next, '\n')
		}
		next = append(append(next, "\n# Added by the actp dashboard.\n"...), block...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, next, 0o600); err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		if len(old) == 0 {
			_ = os.Remove(path)
		} else {
			_ = os.WriteFile(path, old, 0o600)
		}
		return fmt.Errorf("the new config did not load, nothing was changed: %w", err)
	}
	return nil
}

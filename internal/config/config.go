// Package config loads and validates actp.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// CurrentVersion is the config file format version this build writes and reads.
const CurrentVersion = 1

type Config struct {
	Version int      `yaml:"version"`
	Server  *Server  `yaml:"server"`
	Remotes []Remote `yaml:"remotes"`
	// RemotesFile holds remotes saved by `actp remote`, apart from this hand-edited file.
	RemotesFile string `yaml:"remotes_file"`
	path        string
}

type Server struct {
	Name           string      `yaml:"name"`
	Listen         string      `yaml:"listen"`
	TLSCert        string      `yaml:"tls_cert"`
	TLSKey         string      `yaml:"tls_key"`
	InsecureListen bool        `yaml:"insecure_listen"`
	IdleClose      Duration    `yaml:"idle_close"`
	PromptTimeout  Duration    `yaml:"prompt_timeout"`
	SpoolLimit     ByteSize    `yaml:"spool_limit"`
	LogDir         string      `yaml:"log_dir"`
	StateDir       string      `yaml:"state_dir"`
	ShellEnv       *bool       `yaml:"shell_env"`
	Audit          Audit       `yaml:"audit"`
	Tunnel         Tunnel      `yaml:"tunnel"`
	Workspaces     []Workspace `yaml:"workspaces"`
	Agents         []Agent     `yaml:"agents"`
	Tokens         []Token     `yaml:"tokens"`
	TokensFile     string      `yaml:"tokens_file"`
}

type Audit struct {
	LogPrompts bool `yaml:"log_prompts"`
}

type Tunnel struct {
	Provider string     `yaml:"provider"`
	Mode     TunnelMode `yaml:"mode"`
	TokenEnv string     `yaml:"token_env"`
}

// TunnelMode accepts `off` even when a YAML parser reads it as a boolean.
type TunnelMode string

func (m *TunnelMode) UnmarshalYAML(unmarshal func(any) error) error {
	var b bool
	if err := unmarshal(&b); err == nil {
		if b {
			return errors.New("tunnel mode must be off, quick or named")
		}
		*m = "off"
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*m = TunnelMode(s)
	return nil
}

type Workspace struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

type Agent struct {
	ID            string            `yaml:"id"`
	Name          string            `yaml:"name"`
	Description   string            `yaml:"description"`
	Preset        string            `yaml:"preset"`
	Command       string            `yaml:"command"`
	Args          []string          `yaml:"args"`
	Env           map[string]string `yaml:"env"`
	EnvRemove     []string          `yaml:"env_remove"`
	Permissions   string            `yaml:"permissions"`
	MaxLinks      int               `yaml:"max_links"`
	OnClientExit  string            `yaml:"on_client_exit"`
	MaxUnattended Duration          `yaml:"max_unattended"`
}

type Token struct {
	Name             string            `yaml:"name"`
	Hash             string            `yaml:"hash"`
	Agents           []string          `yaml:"agents"`
	Workspaces       []string          `yaml:"workspaces"`
	DefaultWorkspace string            `yaml:"default_workspace"`
	CwdFallback      bool              `yaml:"cwd_fallback"`
	MCPServers       string            `yaml:"mcp_servers"`
	Permissions      string            `yaml:"permissions"`
	MaxLinks         int               `yaml:"max_links"`
	Map              map[string]string `yaml:"map"`
}

type Remote struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"`
	TokenEnv  string `yaml:"token_env"`
	TokenFile string `yaml:"token_file"`
	// TokenKeychain means the token is in the OS keychain (service "actp", account "remote:<name>").
	TokenKeychain bool `yaml:"token_keychain,omitempty"`
}

// Path is the file the config was loaded from ("" when built in code).
func (c *Config) Path() string { return c.path }

// DefaultPath is ~/.actp/actp.yaml, or %APPDATA%\actp\actp.yaml on Windows.
func DefaultPath() string {
	return filepath.Join(Dir(), "actp.yaml")
}

// Dir is the actp home folder.
func Dir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "actp")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".actp"
	}
	return filepath.Join(home, ".actp")
}

// Load reads, defaults and validates a config file. A missing file at the
// default path is an empty config, not an error.
func Load(path string) (*Config, error) {
	explicit := path != ""
	if !explicit {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			cfg := &Config{Version: CurrentVersion, path: path}
			if err := cfg.finish(); err != nil {
				return nil, err
			}
			return cfg, cfg.loadRemotesFile()
		}
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.path = path
	if err := cfg.loadTokensFile(); err != nil {
		return nil, err
	}
	if err := cfg.loadRemotesFile(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and defaults a config without touching the file system.
func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.UnmarshalWithOptions(data, cfg, yaml.Strict()); err != nil {
		return nil, errors.New(yaml.FormatError(err, false, true))
	}
	if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	if cfg.Version > CurrentVersion {
		return nil, fmt.Errorf("config version %d is newer than this actp (supports %d)", cfg.Version, CurrentVersion)
	}
	return cfg, cfg.finish()
}

func (c *Config) finish() error {
	if c.RemotesFile == "" {
		c.RemotesFile = filepath.Join(Dir(), "remotes.yaml")
	}
	c.RemotesFile = ExpandHome(c.RemotesFile)
	if c.Server == nil {
		return nil
	}
	s := c.Server
	if s.Listen == "" {
		s.Listen = "127.0.0.1:7860"
	}
	if s.IdleClose == 0 {
		s.IdleClose = Duration(10 * time.Minute)
	}
	if s.PromptTimeout == 0 {
		s.PromptTimeout = Duration(24 * time.Hour)
	}
	if s.SpoolLimit == 0 {
		s.SpoolLimit = 1 << 30
	}
	if s.LogDir == "" {
		s.LogDir = filepath.Join(Dir(), "logs")
	}
	if s.StateDir == "" {
		s.StateDir = filepath.Join(Dir(), "state")
	}
	if s.TokensFile == "" {
		s.TokensFile = filepath.Join(Dir(), "tokens.yaml")
	}
	if s.Tunnel.Mode == "" {
		s.Tunnel.Mode = "off"
	}
	s.LogDir = ExpandHome(s.LogDir)
	s.StateDir = ExpandHome(s.StateDir)
	s.TokensFile = ExpandHome(s.TokensFile)
	for i := range s.Workspaces {
		s.Workspaces[i].Path = ExpandHome(s.Workspaces[i].Path)
	}
	for i := range s.Agents {
		a := &s.Agents[i]
		if err := applyPreset(a); err != nil {
			return err
		}
		if a.Permissions == "" {
			a.Permissions = "forward"
		}
		if a.MaxLinks == 0 {
			a.MaxLinks = 16
		}
		if a.OnClientExit == "" {
			a.OnClientExit = "finish"
		}
		if a.MaxUnattended == 0 {
			a.MaxUnattended = Duration(time.Hour)
		}
		if a.Name == "" {
			a.Name = a.ID
		}
	}
	for i := range s.Tokens {
		ApplyTokenDefaults(&s.Tokens[i])
	}
	return nil
}

// ApplyTokenDefaults fills in default values for a token entry.
func ApplyTokenDefaults(t *Token) {
	if t.MCPServers == "" {
		t.MCPServers = "remote"
	}
	if t.MaxLinks == 0 {
		t.MaxLinks = 8
	}
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Validate checks references and enum values.
func (c *Config) Validate() error {
	var errs []error
	if s := c.Server; s != nil {
		workspaces := map[string]bool{}
		for _, w := range s.Workspaces {
			if w.Name == "" || w.Path == "" {
				errs = append(errs, errors.New("every workspace needs a name and a path"))
				continue
			}
			if workspaces[w.Name] {
				errs = append(errs, fmt.Errorf("workspace %q is defined twice", w.Name))
			}
			if !filepath.IsAbs(w.Path) {
				errs = append(errs, fmt.Errorf("workspace %q: path must be absolute", w.Name))
			}
			workspaces[w.Name] = true
		}
		agents := map[string]bool{}
		for _, a := range s.Agents {
			if !idPattern.MatchString(a.ID) {
				errs = append(errs, fmt.Errorf("agent id %q must match %s", a.ID, idPattern))
			}
			if agents[a.ID] {
				errs = append(errs, fmt.Errorf("agent %q is defined twice", a.ID))
			}
			agents[a.ID] = true
			if a.Command == "" {
				errs = append(errs, fmt.Errorf("agent %q needs a command or a preset", a.ID))
			}
			if !oneOf(a.Permissions, "forward", "auto_allow", "auto_deny") {
				errs = append(errs, fmt.Errorf("agent %q: permissions must be forward, auto_allow or auto_deny", a.ID))
			}
			if !oneOf(a.OnClientExit, "finish", "cancel") {
				errs = append(errs, fmt.Errorf("agent %q: on_client_exit must be finish or cancel", a.ID))
			}
		}
		names := map[string]bool{}
		for _, t := range s.Tokens {
			if t.Name == "" {
				errs = append(errs, errors.New("every token needs a name"))
			}
			if names[t.Name] {
				errs = append(errs, fmt.Errorf("token %q is defined twice", t.Name))
			}
			names[t.Name] = true
			if !strings.HasPrefix(t.Hash, "sha256:") {
				errs = append(errs, fmt.Errorf("token %q: hash must start with sha256:", t.Name))
			}
			for _, a := range t.Agents {
				if a != "*" && !agents[a] {
					errs = append(errs, fmt.Errorf("token %q: unknown agent %q", t.Name, a))
				}
			}
			for _, w := range t.Workspaces {
				if w != "*" && !workspaces[w] {
					errs = append(errs, fmt.Errorf("token %q: unknown workspace %q", t.Name, w))
				}
			}
			if t.DefaultWorkspace != "" && !workspaces[t.DefaultWorkspace] {
				errs = append(errs, fmt.Errorf("token %q: unknown default_workspace %q", t.Name, t.DefaultWorkspace))
			}
			for from, to := range t.Map {
				if !workspaces[to] {
					errs = append(errs, fmt.Errorf("token %q: map %q points to unknown workspace %q", t.Name, from, to))
				}
			}
			if !oneOf(t.MCPServers, "none", "remote", "all") {
				errs = append(errs, fmt.Errorf("token %q: mcp_servers must be none, remote or all", t.Name))
			}
			if t.Permissions != "" && !oneOf(t.Permissions, "forward", "auto_allow", "auto_deny") {
				errs = append(errs, fmt.Errorf("token %q: permissions must be forward, auto_allow or auto_deny", t.Name))
			}
		}
		if !oneOf(string(s.Tunnel.Mode), "off", "quick", "named") {
			errs = append(errs, errors.New("tunnel mode must be off, quick or named"))
		}
		if s.Tunnel.Mode == "named" && s.Tunnel.TokenEnv == "" {
			errs = append(errs, errors.New("a named tunnel needs token_env: the variable holding the Cloudflare tunnel token"))
		}
		if s.TLSCert == "" != (s.TLSKey == "") {
			errs = append(errs, errors.New("tls_cert and tls_key must be set together"))
		}
	}
	remotes := map[string]bool{}
	for _, r := range c.Remotes {
		if r.Name == "" || r.URL == "" {
			errs = append(errs, errors.New("every remote needs a name and a url"))
		}
		if remotes[r.Name] {
			errs = append(errs, fmt.Errorf("remote %q is defined twice", r.Name))
		}
		remotes[r.Name] = true
	}
	return errors.Join(errs...)
}

// Agent returns the agent with this id, or nil.
func (s *Server) Agent(id string) *Agent {
	for i := range s.Agents {
		if s.Agents[i].ID == id {
			return &s.Agents[i]
		}
	}
	return nil
}

// Workspace returns the workspace with this name, or nil.
func (s *Server) Workspace(name string) *Workspace {
	for i := range s.Workspaces {
		if s.Workspaces[i].Name == name {
			return &s.Workspaces[i]
		}
	}
	return nil
}

// Remote returns the saved remote with this name, or nil.
func (c *Config) Remote(name string) *Remote {
	for i := range c.Remotes {
		if c.Remotes[i].Name == name {
			return &c.Remotes[i]
		}
	}
	return nil
}

// AllowsAgent reports whether the token may use the agent.
func (t *Token) AllowsAgent(id string) bool {
	return oneOf(id, t.Agents...) || oneOf("*", t.Agents...)
}

// AllowedWorkspaces lists the workspace names the token may use.
func (t *Token) AllowedWorkspaces(s *Server) []string {
	if oneOf("*", t.Workspaces...) {
		names := make([]string, 0, len(s.Workspaces))
		for _, w := range s.Workspaces {
			names = append(names, w.Name)
		}
		return names
	}
	return t.Workspaces
}

// EffectivePermissions is the token override, else the agent setting.
func (t *Token) EffectivePermissions(a *Agent) string {
	if t.Permissions != "" {
		return t.Permissions
	}
	return a.Permissions
}

// ExpandHome replaces a leading ~ with the user's home folder.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

func oneOf(v string, options ...string) bool {
	for _, o := range options {
		if v == o {
			return true
		}
	}
	return false
}

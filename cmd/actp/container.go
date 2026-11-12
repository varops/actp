package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/installer"
)

const containerHelp = `actp container – run actp in the Docker image

Settings come from environment variables. The config, tokens, installed agents
and agent logins live in $HOME (a volume at /data in the image).

  ACTP_AGENTS           agents to install and turn on, e.g. claude-code,codex
  ACTP_TOKEN            a client token to accept (create one with: actp token generate)
  ACTP_ADMIN_PASSWORD   dashboard password; generated and saved when empty
  ACTP_TUNNEL           quick (default), named or off
  ACTP_TUNNEL_TOKEN     Cloudflare tunnel token, for ACTP_TUNNEL=named
  ACTP_NAME             server name (default: the hostname)
  ACTP_WORKSPACES       folder whose subfolders agents may use (default /workspaces)
  ACTP_LISTEN           server address (default 0.0.0.0:7860)
  ACTP_DASHBOARD        dashboard address (default 0.0.0.0:7861), or off
  ACTP_TERMINAL         on (default) or off: the shell in the dashboard

API keys for agents (ANTHROPIC_API_KEY, OPENAI_API_KEY, ...) are passed to
agents as they are. ACTP_* variables are not.
`

func cmdContainer(args []string) error {
	fs := flag.NewFlagSet("container", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, containerHelp) }
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	env := func(key, def string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		return def
	}
	cfgPath := config.DefaultPath()
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		return err
	}
	workspaces := containerWorkspaces(env("ACTP_WORKSPACES", "/workspaces"))
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := writeContainerConfig(cfgPath, env("ACTP_NAME", hostname()), workspaces); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "actp: wrote", cfgPath)
	} else if err := addWorkspaces(cfgPath, workspaces); err != nil {
		return err
	}

	in := &installer.Installer{}
	installed := in.Installed(context.Background())
	for _, preset := range splitList(os.Getenv("ACTP_AGENTS")) {
		r := installer.Find(preset)
		if r == nil {
			return fmt.Errorf("ACTP_AGENTS: actp cannot install %q (it can install: %s)", preset, recipeNames())
		}
		if _, ok := installed[r.Packages[0]]; !ok {
			fmt.Fprintf(os.Stderr, "actp: installing %s\n", r.Name)
			if err := in.Run(context.Background(), preset, installer.ActionInstall, os.Stderr); err != nil {
				return fmt.Errorf("installing %s: %w", preset, err)
			}
		}
		if _, err := config.SetPresetEnabled(cfgPath, preset, true); err != nil {
			return err
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if tok := os.Getenv("ACTP_TOKEN"); tok != "" {
		if err := setEnvToken(cfg.Server.TokensFile, strings.TrimSpace(tok)); err != nil {
			return err
		}
	}

	password, err := adminPassword()
	if err != nil {
		return err
	}
	mode := env("ACTP_TUNNEL", "quick")
	listen := env("ACTP_LISTEN", "0.0.0.0:7860")
	dashAddr := env("ACTP_DASHBOARD", "0.0.0.0:7861")
	term := env("ACTP_TERMINAL", "on") != "off"
	agentEnv := withoutActpVars(os.Environ())
	return runHost(context.Background(), hostOptions{
		configPath:    cfgPath,
		requireServer: true,
		dashboard:     dashAddr != "off",
		dashListen:    dashAddr,
		password:      password,
		terminal:      &term,
		termEnv:       agentEnv,
		baseEnv:       agentEnv,
		adjust: func(c *config.Config) {
			if c.Server == nil {
				return
			}
			c.Server.Listen = listen
			c.Server.InsecureListen = true // TLS comes from the tunnel or a proxy in front
			c.Server.Tunnel.Mode = config.TunnelMode(mode)
			if mode == "named" {
				c.Server.Tunnel.TokenEnv = "ACTP_TUNNEL_TOKEN"
			}
		},
		onReady: func(h *host) {
			if len(h.Server().Config().Tokens) == 0 {
				h.log.Warn("no client tokens yet: create one in the dashboard, or set ACTP_TOKEN")
			}
		},
	})
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "actp"
	}
	return h
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func recipeNames() string {
	var names []string
	for _, r := range installer.Recipes {
		names = append(names, r.Preset)
	}
	return strings.Join(names, ", ")
}

// containerWorkspaces are the subfolders of root, or $HOME/workspace when there are none.
func containerWorkspaces(root string) []config.Workspace {
	var out []config.Workspace
	used := map[string]bool{}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := wsNameFor(e.Name(), used)
		out = append(out, config.Workspace{Name: name, Path: filepath.Join(root, e.Name())})
	}
	if len(out) == 0 {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, "workspace")
		_ = os.MkdirAll(dir, 0o755)
		out = append(out, config.Workspace{Name: "workspace", Path: dir})
	}
	return out
}

func wsNameFor(base string, used map[string]bool) string {
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-_")
	if name == "" {
		name = "workspace"
	}
	for n, i := name, 2; used[name]; i++ {
		name = fmt.Sprintf("%s-%d", n, i)
	}
	used[name] = true
	return name
}

func writeContainerConfig(path, name string, workspaces []config.Workspace) error {
	type server struct {
		Name       string             `yaml:"name"`
		Workspaces []config.Workspace `yaml:"workspaces"`
	}
	block, err := yaml.Marshal(map[string]any{"server": server{Name: name, Workspaces: workspaces}})
	if err != nil {
		return err
	}
	head := "# Written by `actp container` on its first start. The dashboard edits it too.\n" +
		"# listen and tunnel come from ACTP_LISTEN and ACTP_TUNNEL, not from this file.\nversion: 1\n\n"
	if err := os.WriteFile(path, append([]byte(head), block...), 0o600); err != nil {
		return err
	}
	_, err = config.Load(path)
	return err
}

// addWorkspaces adds folders that appeared under the workspaces root since the last start.
func addWorkspaces(path string, found []config.Workspace) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Server == nil {
		return fmt.Errorf("%s has no server section", path)
	}
	list := append([]config.Workspace(nil), cfg.Server.Workspaces...)
	have, used := map[string]bool{}, map[string]bool{}
	for _, ws := range list {
		have[filepath.Clean(ws.Path)], used[ws.Name] = true, true
	}
	added := false
	for _, ws := range found {
		if have[filepath.Clean(ws.Path)] {
			continue
		}
		ws.Name = wsNameFor(ws.Name, used)
		list = append(list, ws)
		added = true
	}
	if !added {
		return nil
	}
	return config.SetServerList(path, "workspaces", list)
}

// setEnvToken makes the token from ACTP_TOKEN the one named "env" in the tokens file.
func setEnvToken(path, token string) error {
	if !strings.HasPrefix(token, config.TokenPrefix) || len(token) < len(config.TokenPrefix)+20 {
		return errors.New("ACTP_TOKEN does not look like an actp token: create one with `actp token generate`")
	}
	tf, err := config.ReadTokensFile(path)
	if err != nil {
		return err
	}
	hash := config.HashToken(token)
	kept := tf.Tokens[:0]
	for _, t := range tf.Tokens {
		if t.Name == "env" {
			if t.Hash == hash {
				return nil
			}
			continue
		}
		kept = append(kept, t)
	}
	tf.Tokens = append(kept, config.Token{Name: "env", Hash: hash, Agents: []string{"*"}, Workspaces: []string{"*"}})
	return config.WriteTokensFile(path, tf)
}

// adminPassword is ACTP_ADMIN_PASSWORD, or one saved on an earlier start, or a new one.
func adminPassword() (string, error) {
	if p := os.Getenv("ACTP_ADMIN_PASSWORD"); p != "" {
		return p, nil
	}
	file := filepath.Join(config.Dir(), "admin-password")
	if b, err := os.ReadFile(file); err == nil && strings.TrimSpace(string(b)) != "" {
		fmt.Fprintln(os.Stderr, "actp: the dashboard password is in", file)
		return strings.TrimSpace(string(b)), nil
	}
	p := rand.Text() // 26 base32 characters, 128 bits
	if err := os.WriteFile(file, []byte(p+"\n"), 0o600); err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "\nactp: dashboard password: %s\n      (saved in %s; set ACTP_ADMIN_PASSWORD to choose your own)\n\n", p, file)
	return p, nil
}

// withoutActpVars drops actp's own settings (secrets among them) from what agents see.
func withoutActpVars(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "ACTP_") {
			out = append(out, kv)
		}
	}
	return out
}

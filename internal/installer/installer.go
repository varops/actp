// Package installer installs agents with npm into actp's own prefix, so the
// dashboard can add an agent without a terminal (and without root in Docker).
package installer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
)

// Recipe is how to install one preset.
type Recipe struct {
	Preset string `json:"preset"`
	Name   string `json:"name"`
	// Packages are npm packages; the first one provides the preset's command.
	// The others are the agent's own CLI, which some agents need to log in.
	Packages []string `json:"packages"`
	// Login says how to log in after installing, if the agent needs it.
	Login string `json:"login,omitempty"`
}

// Recipes lists the presets actp can install, in display order.
var Recipes = []Recipe{
	{Preset: "claude-code", Name: "Claude Code", Packages: []string{"@agentclientprotocol/claude-agent-acp", "@anthropic-ai/claude-code"}, Login: "claude /login, or set ANTHROPIC_API_KEY"},
	{Preset: "codex", Name: "Codex", Packages: []string{"@agentclientprotocol/codex-acp", "@openai/codex"}, Login: "codex login, or set OPENAI_API_KEY"},
	{Preset: "droid", Name: "Droid", Packages: []string{"@factory/cli"}, Login: "droid, then /login, or set FACTORY_API_KEY"},
	{Preset: "gemini", Name: "Gemini CLI", Packages: []string{"@google/gemini-cli"}, Login: "gemini, or set GEMINI_API_KEY"},
	{Preset: "opencode", Name: "OpenCode", Packages: []string{"opencode-ai"}, Login: "opencode auth login"},
	{Preset: "pi", Name: "Pi", Packages: []string{"pi-acp", "@earendil-works/pi-coding-agent"}, Login: "pi, then /login"},
}

// Find returns the recipe for a preset, or nil.
func Find(preset string) *Recipe {
	for i := range Recipes {
		if Recipes[i].Preset == preset {
			return &Recipes[i]
		}
	}
	return nil
}

// Actions an installer job can run.
const (
	ActionInstall = "install" // also updates: npm installs the latest version
	ActionRemove  = "remove"
)

// Installer runs one npm job at a time.
type Installer struct {
	// Prefix is the npm prefix (config.AgentsPrefix() by default).
	Prefix string
	// Env returns the environment npm runs in; nil means the login shell's.
	Env func() []string
	// OnDone runs after a job that succeeded.
	OnDone func(preset, action string)

	mu     sync.Mutex
	job    *job
	nextID int
}

type job struct {
	id      int
	preset  string
	action  string
	started time.Time
	done    bool
	err     string
	out     bytes.Buffer
}

// JobView is a job's state with its output from a given offset.
type JobView struct {
	ID      int    `json:"id"`
	Preset  string `json:"preset"`
	Action  string `json:"action"`
	Started string `json:"started"`
	Done    bool   `json:"done"`
	Error   string `json:"error,omitempty"`
	Output  string `json:"output"`
	// Next is the offset to ask for next time.
	Next int `json:"next"`
}

const maxOutput = 256 << 10

func (in *Installer) prefix() string {
	if in.Prefix != "" {
		return in.Prefix
	}
	return config.AgentsPrefix()
}

func (in *Installer) env() []string {
	var env []string
	if in.Env != nil {
		env = in.Env()
	} else {
		env = agentproc.CachedLoginShellEnv()
	}
	return agentproc.AppendPath(env, config.AgentBinDir())
}

// NPM finds npm, or says why there is none.
func (in *Installer) NPM() (string, error) {
	path, err := agentproc.LookPath("npm", in.env())
	if err != nil {
		return "", errors.New("installing agents needs Node.js and npm on this machine")
	}
	return path, nil
}

// command is the npm command for an action on a preset.
func (in *Installer) command(preset, action string) (string, []string, error) {
	r := Find(preset)
	if r == nil {
		return "", nil, fmt.Errorf("actp cannot install %q", preset)
	}
	npm, err := in.NPM()
	if err != nil {
		return "", nil, err
	}
	switch action {
	case ActionInstall:
		args := []string{"install", "-g", "--prefix", in.prefix(), "--no-fund", "--no-audit", "--no-update-notifier"}
		for _, p := range r.Packages {
			args = append(args, p+"@latest")
		}
		return npm, args, nil
	case ActionRemove:
		return npm, append([]string{"uninstall", "-g", "--prefix", in.prefix()}, r.Packages...), nil
	}
	return "", nil, fmt.Errorf("unknown action %q", action)
}

// Run installs or removes a preset's packages and waits, writing npm's output
// to out. It does not call OnDone.
func (in *Installer) Run(ctx context.Context, preset, action string, out io.Writer) error {
	npm, args, err := in.command(preset, action)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "$ npm %s\n", joinArgs(args))
	return in.exec(ctx, npm, args, out)
}

func (in *Installer) exec(ctx context.Context, npm string, args []string, out io.Writer) error {
	if err := os.MkdirAll(in.prefix(), 0o755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, npm, args...)
	cmd.Env = in.env()
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

// Start begins installing (or updating) or removing a preset's packages in the background.
func (in *Installer) Start(preset, action string) (JobView, error) {
	npm, args, err := in.command(preset, action)
	if err != nil {
		return JobView{}, err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.job != nil && !in.job.done {
		return JobView{}, fmt.Errorf("already busy with %s %s", in.job.action, in.job.preset)
	}
	in.nextID++
	j := &job{id: in.nextID, preset: preset, action: action, started: time.Now()}
	fmt.Fprintf(&j.out, "$ npm %s\n", joinArgs(args))
	in.job = j
	go in.run(j, npm, args)
	return in.viewLocked(0), nil
}

func joinArgs(args []string) string {
	var b bytes.Buffer
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a)
	}
	return b.String()
}

func (in *Installer) run(j *job, npm string, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	err := in.exec(ctx, npm, args, jobWriter{in, j})
	if err == nil && in.OnDone != nil {
		in.OnDone(j.preset, j.action)
	}
	in.finish(j, err)
}

func (in *Installer) finish(j *job, err error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	j.done = true
	if err != nil {
		j.err = err.Error()
		fmt.Fprintf(&j.out, "\nFailed: %v\n", err)
	} else {
		j.out.WriteString("\nDone.\n")
	}
}

type jobWriter struct {
	in *Installer
	j  *job
}

func (w jobWriter) Write(p []byte) (int, error) {
	w.in.mu.Lock()
	defer w.in.mu.Unlock()
	if w.j.out.Len() < maxOutput {
		w.j.out.Write(p)
	}
	return len(p), nil
}

// Job returns the current or last job with output from offset on, or nil.
func (in *Installer) Job(offset int) *JobView {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.job == nil {
		return nil
	}
	v := in.viewLocked(offset)
	return &v
}

func (in *Installer) viewLocked(offset int) JobView {
	j := in.job
	out := j.out.Bytes()
	if offset < 0 || offset > len(out) {
		offset = 0
	}
	return JobView{ID: j.id, Preset: j.preset, Action: j.action, Started: j.started.UTC().Format(time.RFC3339),
		Done: j.done, Error: j.err, Output: string(out[offset:]), Next: len(out)}
}

// Installed returns the version of each package in the prefix.
func (in *Installer) Installed(ctx context.Context) map[string]string {
	npm, err := in.NPM()
	if err != nil {
		return nil
	}
	if _, err := os.Stat(in.prefix()); err != nil {
		return map[string]string{}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, npm, "ls", "-g", "--prefix", in.prefix(), "--depth=0", "--json")
	cmd.Env = in.env()
	out, _ := cmd.Output() // npm ls exits 1 on problems but still prints JSON
	var res struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	_ = json.Unmarshal(out, &res)
	versions := map[string]string{}
	for name, d := range res.Dependencies {
		versions[name] = d.Version
	}
	return versions
}

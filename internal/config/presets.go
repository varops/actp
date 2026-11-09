package config

import "fmt"

// Preset is a known ACP agent launch. See docs/agents.md.
type Preset struct {
	Name    string
	Command string
	Args    []string
}

// Presets are built from docs/agents.md. Keep both in step.
var Presets = map[string]Preset{
	"claude-code": {Name: "Claude Code", Command: "claude-code-acp"},
	"codex":       {Name: "Codex", Command: "codex-acp"},
	"droid":       {Name: "Droid", Command: "droid", Args: []string{"exec", "--output-format", "acp"}},
	"gemini":      {Name: "Gemini CLI", Command: "gemini", Args: []string{"--acp"}},
	"opencode":    {Name: "OpenCode", Command: "opencode", Args: []string{"acp"}},
	"grok":        {Name: "Grok", Command: "grok", Args: []string{"agent", "stdio"}},
	"pi":          {Name: "Pi", Command: "pi-acp"},
	"prime-agent": {Name: "Prime Agent", Command: "prime-agent", Args: []string{"--mode", "acp"}},
}

func applyPreset(a *Agent) error {
	if a.Preset == "" {
		return nil
	}
	p, ok := Presets[a.Preset]
	if !ok {
		return fmt.Errorf("agent %q: unknown preset %q", a.ID, a.Preset)
	}
	if a.Command == "" {
		a.Command = p.Command
		if a.Args == nil {
			a.Args = p.Args
		}
	}
	if a.Name == "" {
		a.Name = p.Name
	}
	return nil
}

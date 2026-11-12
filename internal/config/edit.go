package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"
)

// ReadServerList reads a list under server: (for example "agents") exactly as
// written, without defaults, keeping key order.
func ReadServerList(path, key string) ([]yaml.MapSlice, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := yaml.PathString("$.server." + key)
	if err != nil {
		return nil, err
	}
	var out []yaml.MapSlice
	if err := p.Read(bytes.NewReader(data), &out); err != nil && !errors.Is(err, yaml.ErrNotFoundNode) {
		return nil, err
	}
	return out, nil
}

// SetServerList replaces a list under server: in the config file and keeps the
// rest of the file, comments included, as it was. If the result does not load,
// the file is put back and the error returned.
func SetServerList(path, key string, value any) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := parser.ParseBytes(old, parser.ParseComments)
	if err != nil {
		return err
	}
	block, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	p, err := yaml.PathString("$.server." + key)
	if err != nil {
		return err
	}
	// ReplaceWithReader does nothing for a missing key, so look first.
	if _, err := p.FilterFile(f); err == nil {
		if err := p.ReplaceWithReader(f, bytes.NewReader(block)); err != nil {
			return err
		}
	} else if !errors.Is(err, yaml.ErrNotFoundNode) {
		return err
	} else {
		// The key is not there yet: merge it into the server section.
		merge, mErr := yaml.Marshal(map[string]any{key: value})
		if mErr != nil {
			return mErr
		}
		sp, _ := yaml.PathString("$.server")
		if err := sp.MergeFromReader(f, bytes.NewReader(merge)); err != nil {
			return err
		}
	}
	next := []byte(f.String())
	if len(next) > 0 && next[len(next)-1] != '\n' {
		next = append(next, '\n')
	}
	if err := os.WriteFile(path, next, 0o600); err != nil {
		return err
	}
	if _, err := Load(path); err != nil {
		_ = os.WriteFile(path, old, 0o600)
		return fmt.Errorf("the change would break the config, so nothing was changed: %w", err)
	}
	return nil
}

// presetIDs are agent ids for presets whose name is long, so bridge commands
// read naturally (claude@host).
var presetIDs = map[string]string{"claude-code": "claude"}

// PresetID is the agent id actp gives a preset it adds to the config.
func PresetID(preset string) string {
	if id, ok := presetIDs[preset]; ok {
		return id
	}
	return preset
}

// SetPresetEnabled adds an agent for the preset to the server section of the
// config file, or removes the agents using it. Agents without a preset are
// left alone. It reports whether the file changed.
func SetPresetEnabled(path, preset string, on bool) (bool, error) {
	cfg, err := Load(path)
	if err != nil {
		return false, err
	}
	if cfg.Server == nil {
		return false, errors.New("the config has no server section")
	}
	current, err := ReadServerList(path, "agents")
	if err != nil {
		return false, err
	}
	out := []yaml.MapSlice{}
	found := false
	for _, a := range current {
		if p, _ := mapValue(a, "preset").(string); p == preset {
			found = true
			if !on {
				continue
			}
		}
		out = append(out, a)
	}
	if on == found {
		return false, nil
	}
	if on {
		if cfg.Server.Agent(PresetID(preset)) != nil {
			return false, fmt.Errorf("an agent with id %q already exists", PresetID(preset))
		}
		out = append(out, yaml.MapSlice{{Key: "id", Value: PresetID(preset)}, {Key: "preset", Value: preset}})
	}
	return true, SetServerList(path, "agents", out)
}

func mapValue(m yaml.MapSlice, key string) any {
	for _, it := range m {
		if k, _ := it.Key.(string); k == key {
			return it.Value
		}
	}
	return nil
}

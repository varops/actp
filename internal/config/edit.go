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
	if err := p.ReplaceWithReader(f, bytes.NewReader(block)); err != nil {
		if !errors.Is(err, yaml.ErrNotFoundNode) {
			return err
		}
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

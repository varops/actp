package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// RemotesFile is the CLI-managed list of saved remotes.
type RemotesFile struct {
	Remotes []Remote `yaml:"remotes"`
}

func (c *Config) loadRemotesFile() error {
	rf, err := ReadRemotesFile(c.RemotesFile)
	if err != nil {
		return err
	}
	c.Remotes = append(c.Remotes, rf.Remotes...)
	return nil
}

// ReadRemotesFile reads a remotes file. A missing file is empty.
func ReadRemotesFile(path string) (*RemotesFile, error) {
	rf := &RemotesFile{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return rf, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.UnmarshalWithOptions(data, rf, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("%s: %s", path, yaml.FormatError(err, false, true))
	}
	for i := range rf.Remotes {
		rf.Remotes[i].TokenFile = ExpandHome(rf.Remotes[i].TokenFile)
	}
	return rf, nil
}

// WriteRemotesFile replaces a remotes file, readable only by the current user.
func WriteRemotesFile(path string, rf *RemotesFile) error {
	data, err := yaml.Marshal(rf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte("# Managed by `actp remote`.\n"), data...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

// TokenPrefix marks actp tokens so they are easy to spot in logs and secret scanners.
const TokenPrefix = "actp_"

// NewToken returns a fresh token and its stored hash.
func NewToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = TokenPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	return token, HashToken(token), nil
}

// HashToken is the form tokens are stored in.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FindToken returns the token entry matching a presented token, or nil.
func (s *Server) FindToken(presented string) *Token {
	if presented == "" {
		return nil
	}
	want := []byte(HashToken(presented))
	var found *Token
	for i := range s.Tokens {
		// Compare every entry so timing does not reveal which one matched.
		if subtle.ConstantTimeCompare([]byte(s.Tokens[i].Hash), want) == 1 {
			found = &s.Tokens[i]
		}
	}
	return found
}

// TokensFile is the CLI-managed list of tokens, kept apart from the hand-edited config.
type TokensFile struct {
	Tokens []Token `yaml:"tokens"`
}

func (c *Config) loadTokensFile() error {
	if c.Server == nil {
		return nil
	}
	tf, err := ReadTokensFile(c.Server.TokensFile)
	if err != nil {
		return err
	}
	for _, t := range tf.Tokens {
		defaultToken(&t)
		c.Server.Tokens = append(c.Server.Tokens, t)
	}
	return nil
}

// ReadTokensFile reads a tokens file. A missing file is empty.
func ReadTokensFile(path string) (*TokensFile, error) {
	tf := &TokensFile{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return tf, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.UnmarshalWithOptions(data, tf, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("%s: %s", path, yaml.FormatError(err, false, true))
	}
	return tf, nil
}

// WriteTokensFile replaces a tokens file, readable only by the current user.
func WriteTokensFile(path string, tf *TokensFile) error {
	data, err := yaml.Marshal(tf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte("# Managed by `actp token`. Hashes only; tokens are never stored.\n"), data...), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

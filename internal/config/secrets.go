package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const keyringService = "actp"

func keyringAccount(remote string) string { return "remote:" + remote }

// keyringTimeout bounds keychain calls: a locked or missing keyring daemon can hang.
const keyringTimeout = 3 * time.Second

func withTimeout[T any](f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() { v, err := f(); ch <- result{v, err} }()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(keyringTimeout):
		var zero T
		return zero, errors.New("the OS keychain did not answer")
	}
}

// SaveRemoteToken stores a remote's token in the OS keychain, or, when there is
// none, in a file only this user can read. It updates r to point at it.
func SaveRemoteToken(c *Config, r *Remote, token string) error {
	if _, err := withTimeout(func() (struct{}, error) {
		return struct{}{}, keyring.Set(keyringService, keyringAccount(r.Name), token)
	}); err == nil {
		r.TokenKeychain, r.TokenFile, r.TokenEnv = true, "", ""
		return nil
	}
	path := RemoteTokenPath(c, r.Name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	r.TokenKeychain, r.TokenFile, r.TokenEnv = false, path, ""
	return nil
}

// DeleteRemoteToken removes a token actp stored for a remote. Tokens the user
// pointed at (token_env, a token_file of their own) are left alone.
func DeleteRemoteToken(c *Config, r *Remote) {
	if r.TokenKeychain {
		_, _ = withTimeout(func() (struct{}, error) {
			return struct{}{}, keyring.Delete(keyringService, keyringAccount(r.Name))
		})
	}
	if r.TokenFile != "" && r.TokenFile == RemoteTokenPath(c, r.Name) {
		_ = os.Remove(r.TokenFile)
	}
}

// RemoteToken reads a remote's token from wherever it is kept.
func RemoteToken(r *Remote) (string, error) {
	switch {
	case r.TokenEnv != "":
		v := strings.TrimSpace(os.Getenv(r.TokenEnv))
		if v == "" {
			return "", errors.New("environment variable " + r.TokenEnv + " is empty")
		}
		return v, nil
	case r.TokenFile != "":
		data, err := os.ReadFile(ExpandHome(r.TokenFile))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	case r.TokenKeychain:
		v, err := withTimeout(func() (string, error) { return keyring.Get(keyringService, keyringAccount(r.Name)) })
		if err != nil {
			return "", errors.New("reading the token for " + r.Name + " from the OS keychain: " + err.Error())
		}
		return v, nil
	}
	return "", errors.New("remote " + r.Name + " has no token")
}

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestRemoteTokenInKeychain(t *testing.T) {
	keyring.MockInit()
	c := &Config{RemotesFile: filepath.Join(t.TempDir(), "remotes.yaml")}
	r := &Remote{Name: "box"}
	if err := SaveRemoteToken(c, r, "actp_secret"); err != nil {
		t.Fatal(err)
	}
	if !r.TokenKeychain || r.TokenFile != "" {
		t.Fatalf("remote %+v", r)
	}
	if tok, err := RemoteToken(r); err != nil || tok != "actp_secret" {
		t.Fatalf("read %q %v", tok, err)
	}
	DeleteRemoteToken(c, r)
	if _, err := RemoteToken(r); err == nil {
		t.Fatal("token still there after delete")
	}
}

func TestRemoteTokenFallsBackToAPrivateFile(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain here"))
	c := &Config{RemotesFile: filepath.Join(t.TempDir(), "remotes.yaml")}
	r := &Remote{Name: "box"}
	if err := SaveRemoteToken(c, r, "actp_secret"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(r.TokenFile)
	if r.TokenKeychain || err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("remote %+v, file %v %v", r, info, err)
	}
	if tok, _ := RemoteToken(r); tok != "actp_secret" {
		t.Fatalf("read %q", tok)
	}
	DeleteRemoteToken(c, r)
	if _, err := os.Stat(r.TokenFile); !os.IsNotExist(err) {
		t.Fatal("file kept after delete")
	}
}

package config

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const sample = `
version: 1
server:
  name: workstation
  idle_close: 5m
  spool_limit: 8MB
  tunnel:
    mode: off
  workspaces:
    - name: website
      path: WORKSPACE
  agents:
    - id: claude
      preset: claude-code
    - id: mine
      command: my-agent
      args: [--acp]
  tokens:
    - name: bot
      hash: "sha256:abc"
      agents: [claude]
      workspaces: [website]
      default_workspace: website
remotes:
  - name: workstation
    url: https://agents.example.com
`

// sampleConfig uses an absolute workspace path for this platform.
func sampleConfig(t *testing.T) string {
	return strings.ReplaceAll(sample, "WORKSPACE", strconv.Quote(t.TempDir()))
}

func TestParseAppliesDefaultsAndPresets(t *testing.T) {
	cfg, err := Parse([]byte(sampleConfig(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := cfg.Server
	if s.Listen != "127.0.0.1:7860" || s.IdleClose.D() != 5*time.Minute || s.PromptTimeout.D() != 24*time.Hour {
		t.Fatalf("defaults not applied: %+v", s)
	}
	if s.SpoolLimit != 8<<20 {
		t.Fatalf("spool_limit = %d", s.SpoolLimit)
	}
	if s.Tunnel.Mode != "off" {
		t.Fatalf("tunnel mode = %q", s.Tunnel.Mode)
	}
	claude := s.Agent("claude")
	if claude.Command != "claude-agent-acp" || claude.Name != "Claude Code" || claude.MaxLinks != 16 || claude.OnClientExit != "finish" {
		t.Fatalf("preset not applied: %+v", claude)
	}
	tok := &s.Tokens[0]
	if tok.MCPServers != "remote" || !tok.AllowsAgent("claude") || tok.AllowsAgent("mine") {
		t.Fatalf("token defaults: %+v", tok)
	}
	if cfg.Remote("workstation") == nil {
		t.Fatal("remote missing")
	}
}

func TestValidateCatchesBadReferences(t *testing.T) {
	bad := strings.ReplaceAll(sampleConfig(t), "agents: [claude]", "agents: [nope]")
	bad = strings.ReplaceAll(bad, "default_workspace: website", "default_workspace: other")
	cfg, err := Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), `unknown agent "nope"`) || !strings.Contains(err.Error(), `unknown default_workspace "other"`) {
		t.Fatalf("got %v", err)
	}
}

func TestStrictRejectsUnknownKeys(t *testing.T) {
	if _, err := Parse([]byte("server:\n  lisen: x\n")); err == nil {
		t.Fatal("expected unknown key error")
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) < 50 {
		t.Fatalf("token %q", tok)
	}
	s := &Server{Tokens: []Token{{Name: "a", Hash: "sha256:00"}, {Name: "b", Hash: hash}}}
	if got := s.FindToken(tok); got == nil || got.Name != "b" {
		t.Fatalf("FindToken = %v", got)
	}
	if s.FindToken("actp_wrong") != nil || s.FindToken("") != nil {
		t.Fatal("wrong token matched")
	}
}

func TestParseByteSize(t *testing.T) {
	for in, want := range map[string]int64{"512": 512, "8KB": 8 << 10, "8MB": 8 << 20, "1GB": 1 << 30, " 2 mb ": 2 << 20} {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("%q = %d, %v", in, got, err)
		}
	}
	if _, err := ParseByteSize("lots"); err == nil {
		t.Error("expected error")
	}
}

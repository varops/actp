// Package tunnel runs cloudflared next to the server, so machines without a
// public address can be reached (design 5.1).
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
)

// Options configure a tunnel.
type Options struct {
	Mode   string // quick or named
	Target string // local URL, for example http://127.0.0.1:7860
	// Token is the named tunnel token. It is passed in the environment, never on the command line.
	Token  string
	Binary string // cloudflared path; empty means PATH, then ~/.actp/bin
	Env    []string
	Logger *slog.Logger
	// OnURL is called with the public URL whenever it changes (quick tunnels only).
	OnURL func(string)
	// MaxBackoff caps the restart delay (60 s).
	MaxBackoff time.Duration
	// Output receives every line cloudflared writes (for a log file).
	Output io.Writer
	// ConfigFile is the (empty) cloudflared config actp uses; default ~/.actp/state/cloudflared.yml.
	ConfigFile string
}

// Tunnel is a supervised cloudflared process.
type Tunnel struct {
	opts    Options
	mu      sync.Mutex
	url     string
	lastErr string
	done    chan struct{}
}

// LastError is the last error line cloudflared printed, if any.
func (t *Tunnel) LastError() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

var (
	quickURL  = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)
	errorLine = regexp.MustCompile(`(?i)\b(ERR|error)\b`)
)

// FindBinary locates cloudflared on PATH or in ~/.actp/bin.
// A nil env means the login shell's environment: an app started from Finder or
// a service manager has a minimal PATH that misses Homebrew and similar.
func FindBinary(env []string) (string, error) {
	if env == nil {
		env = agentproc.CachedLoginShellEnv()
	}
	if p, err := agentproc.LookPath("cloudflared", env); err == nil {
		return p, nil
	}
	name := "cloudflared"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	local := filepath.Join(config.Dir(), "bin", name)
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	return "", errors.New("cloudflared was not found on PATH or in " + filepath.Dir(local) + "; install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
}

// Start launches cloudflared and keeps it running until ctx ends.
func Start(ctx context.Context, opts Options) (*Tunnel, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = time.Minute
	}
	if opts.Mode != "quick" && opts.Mode != "named" {
		return nil, fmt.Errorf("tunnel mode must be quick or named, got %q", opts.Mode)
	}
	if opts.Mode == "named" && opts.Token == "" {
		return nil, errors.New("a named tunnel needs a token (server.tunnel.token_env)")
	}
	if opts.Binary == "" {
		bin, err := FindBinary(opts.Env)
		if err != nil {
			return nil, err
		}
		opts.Binary = bin
	}
	if opts.ConfigFile == "" {
		opts.ConfigFile = filepath.Join(config.Dir(), "state", "cloudflared.yml")
	}
	if err := emptyConfig(opts.ConfigFile); err != nil {
		return nil, err
	}
	t := &Tunnel{opts: opts, done: make(chan struct{})}
	go t.supervise(ctx)
	return t, nil
}

// URL is the public URL of a quick tunnel, once known.
func (t *Tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.url
}

// Done is closed after cloudflared has stopped for good.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

func (t *Tunnel) args() []string {
	// Our own empty config: a ~/.cloudflared/config.yml with ingress rules would
	// otherwise route the tunnel's requests and answer them with 404.
	base := []string{"tunnel", "--config", t.opts.ConfigFile, "--no-autoupdate"}
	if t.opts.Mode == "quick" {
		return append(base, "--url", t.opts.Target)
	}
	return append(base, "run")
}

// emptyConfig writes the config file actp gives cloudflared: no settings, so
// only actp's command line counts.
func emptyConfig(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("# Written by actp. Kept empty so ~/.cloudflared/config.yml cannot change actp's tunnel.\n{}\n"), 0o600)
}

func (t *Tunnel) supervise(ctx context.Context) {
	defer close(t.done)
	delay := time.Second
	for {
		started := time.Now()
		err := t.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		t.opts.Logger.Warn("cloudflared stopped, restarting", "error", fmt.Sprint(err), "in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if time.Since(started) > 5*time.Minute {
			delay = time.Second
		} else {
			delay = min(delay*2, t.opts.MaxBackoff)
		}
	}
}

func (t *Tunnel) runOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, t.opts.Binary, t.args()...)
	env := t.opts.Env
	if env == nil {
		env = os.Environ()
	}
	if t.opts.Mode == "named" {
		env = append(append([]string(nil), env...), "TUNNEL_TOKEN="+t.opts.Token)
	}
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if u := quickURL.FindString(line); u != "" && t.opts.Mode == "quick" {
			t.mu.Lock()
			changed := u != t.url
			t.url = u
			t.mu.Unlock()
			if changed {
				t.opts.Logger.Info("tunnel is up", "url", u)
				if t.opts.OnURL != nil {
					t.opts.OnURL(u)
				}
			}
		}
		if t.opts.Output != nil {
			fmt.Fprintln(t.opts.Output, line)
		}
		if errorLine.MatchString(line) {
			t.opts.Logger.Warn("cloudflared: " + line)
			t.mu.Lock()
			t.lastErr = line
			t.mu.Unlock()
		}
	}
	return cmd.Wait()
}

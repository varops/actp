package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/varops/actp/internal/bridge"
	"github.com/varops/actp/internal/config"
)

type mapFlags []bridge.Map

func (m *mapFlags) String() string { return "" }
func (m *mapFlags) Set(v string) error {
	from, to, ok := strings.Cut(v, "=")
	if !ok || from == "" || to == "" {
		return fmt.Errorf("--map needs FROM=TO, got %q", v)
	}
	*m = append(*m, bridge.Map{From: from, To: to})
	return nil
}

func cmdBridge(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: actp <agent>@<server> [options]")
	}
	target, args := args[0], args[1:]
	fs := flag.NewFlagSet("bridge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tokenEnv := fs.String("token-env", "", "read the token from this environment variable")
	tokenFile := fs.String("token-file", "", "read the token from this file")
	cwd := fs.String("cwd", "", "replace every cwd the client sends, e.g. actp://website")
	name := fs.String("name", "", "client name shown on the server (default: host name)")
	logFile := fs.String("log-file", "", "write debug logs here (stdout is ACP)")
	cfgPath := fs.String("config", "", "config file with saved remotes")
	var maps mapFlags
	fs.Var(&maps, "map", "rewrite cwd values starting with FROM to TO (FROM=TO, repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}

	agent, server, ok := strings.Cut(target, "@")
	if !ok || agent == "" || server == "" {
		return fmt.Errorf("expected <agent>@<server>, got %q", target)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	baseURL, remote := resolveServer(cfg, server)
	token, err := resolveToken(*tokenEnv, *tokenFile, remote)
	if err != nil {
		return err
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		logger = slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	// A signal counts as the client leaving: close stdin's side and say bye.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stdin := newCancelableReader(ctx, os.Stdin)

	err = bridge.Run(context.Background(), bridge.Options{
		Agent: agent, BaseURL: baseURL, Token: token, ClientName: *name,
		Cwd: *cwd, Maps: maps, Logger: logger,
	}, stdin, os.Stdout)
	var lost *bridge.LostError
	if errors.As(err, &lost) {
		fmt.Fprintln(os.Stderr, "actp:", lost.Error())
		return exitError(1)
	}
	return err
}

// resolveServer turns the part after @ into a base URL, using saved remotes.
func resolveServer(cfg *config.Config, server string) (string, *config.Remote) {
	if strings.Contains(server, "://") {
		return server, nil
	}
	if r := cfg.Remote(server); r != nil {
		return r.URL, r
	}
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}
	if isLoopback(strings.Trim(host, "[]")) {
		return "http://" + server, nil
	}
	return "https://" + server, nil
}

// resolveToken never takes a token from the command line: other users can see it there.
func resolveToken(env, file string, remote *config.Remote) (string, error) {
	read := func(env, file string) (string, error) {
		switch {
		case env != "":
			v := strings.TrimSpace(os.Getenv(env))
			if v == "" {
				return "", fmt.Errorf("environment variable %s is empty", env)
			}
			return v, nil
		case file != "":
			data, err := os.ReadFile(config.ExpandHome(file))
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(data)), nil
		}
		return "", nil
	}
	if env != "" || file != "" {
		return read(env, file)
	}
	if v := strings.TrimSpace(os.Getenv("ACTP_TOKEN")); v != "" {
		return v, nil
	}
	if remote != nil && (remote.TokenEnv != "" || remote.TokenFile != "" || remote.TokenKeychain) {
		return config.RemoteToken(remote)
	}
	return "", errors.New("no token: use --token-env, --token-file, ACTP_TOKEN, or a saved remote with a token")
}

// cancelableReader returns EOF once ctx is done, so a signal ends the bridge like a closed stdin.
type cancelableReader struct {
	data chan []byte
	err  chan error
	ctx  context.Context
	buf  []byte
}

func newCancelableReader(ctx context.Context, r io.Reader) *cancelableReader {
	c := &cancelableReader{data: make(chan []byte), err: make(chan error, 1), ctx: ctx}
	go func() {
		for {
			buf := make([]byte, 64<<10)
			n, err := r.Read(buf)
			if n > 0 {
				select {
				case c.data <- buf[:n]:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				c.err <- err
				return
			}
		}
	}()
	return c
}

func (c *cancelableReader) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		select {
		case c.buf = <-c.data:
		case err := <-c.err:
			return 0, err
		case <-c.ctx.Done():
			return 0, io.EOF
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

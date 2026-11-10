package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/server"
)

func cmdAgents(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: actp agents <server> [--token-env NAME | --token-file PATH]")
	}
	target, args := args[0], args[1:]
	fs := flag.NewFlagSet("agents", flag.ContinueOnError)
	tokenEnv := fs.String("token-env", "", "read the token from this environment variable")
	tokenFile := fs.String("token-file", "", "read the token from this file")
	cfgPath := fs.String("config", "", "config file with saved remotes")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	baseURL, remote := resolveServer(cfg, target)
	token, err := resolveToken(*tokenEnv, *tokenFile, remote)
	if err != nil {
		return err
	}
	client, err := api.NewClientWithResponses(baseURL, api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client.ListAgentsWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("server answered HTTP %d: %s", resp.StatusCode(), strings.TrimSpace(string(resp.Body)))
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "AGENT\tSTATUS\tWORKSPACES\tBRIDGE COMMAND")
	for _, a := range resp.JSON200.Agents {
		var ws []string
		for _, x := range a.Workspaces {
			name := x.Name
			if x.Default != nil && *x.Default {
				name += "*"
			}
			ws = append(ws, name)
		}
		status := string(a.Status)
		if a.AuthHint != nil {
			status += " (" + *a.AuthHint + ")"
		}
		if a.Error != nil {
			status += " (" + *a.Error + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\tactp %s@%s\n", a.Id, status, strings.Join(ws, ","), a.Id, target)
	}
	return w.Flush()
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Println("config: FAIL:", err)
		return exitError(1)
	}
	fmt.Println("config: ok", cfg.Path())
	if cfg.Server == nil {
		fmt.Println("server: not configured")
		return nil
	}
	env := agentproc.LoginShellEnv(context.Background())
	fmt.Println("agent PATH:", agentproc.Getenv(env, "PATH"))
	fmt.Printf("tokens: %d\n", len(cfg.Server.Tokens))
	for _, w := range cfg.Server.Workspaces {
		if info, err := os.Stat(w.Path); err != nil || !info.IsDir() {
			fmt.Printf("workspace %s: FAIL: %s is not a folder\n", w.Name, w.Path)
		} else {
			fmt.Printf("workspace %s: ok %s\n", w.Name, w.Path)
		}
	}
	srv, err := server.New(cfg.Server, server.Options{Version: version, BaseEnv: env, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return err
	}
	failed := false
	for i := range cfg.Server.Agents {
		a := &cfg.Server.Agents[i]
		path, err := agentproc.LookPath(a.Command, env)
		if err != nil {
			fmt.Printf("agent %s: FAIL: %v\n", a.ID, err)
			failed = true
			continue
		}
		status, detail := srv.Probe(a)
		if detail != "" {
			detail = ": " + detail
		}
		fmt.Printf("agent %s: %s (%s)%s\n", a.ID, status, path, detail)
		if status == string(api.Unavailable) {
			failed = true
		}
	}
	if failed {
		return exitError(1)
	}
	return nil
}

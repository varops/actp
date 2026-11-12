package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/varops/actp/internal/config"
)

func cmdToken(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: actp token create|list|revoke|generate")
	}
	if args[0] == "generate" {
		token, _, err := config.NewToken()
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	}
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file")
	name := fs.String("name", "", "token name, usually the client's name")
	agents := fs.String("agents", "*", "agents this token may use (comma separated, * for all)")
	workspaces := fs.String("workspaces", "*", "workspaces this token may use (comma separated, * for all)")
	defWS := fs.String("default-workspace", "", "workspace agents start in")
	sub, rest := args[0], args[1:]
	if err := fs.Parse(rest); err != nil {
		return exitError(2)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Server == nil {
		return fmt.Errorf("%s has no server section; tokens belong to a server", cfg.Path())
	}
	path := cfg.Server.TokensFile
	tf, err := config.ReadTokensFile(path)
	if err != nil {
		return err
	}
	switch sub {
	case "create":
		if *name == "" {
			return errors.New("--name is required")
		}
		for _, t := range cfg.Server.Tokens {
			if t.Name == *name {
				return fmt.Errorf("a token named %q already exists", *name)
			}
		}
		token, hash, err := config.NewToken()
		if err != nil {
			return err
		}
		entry := config.Token{Name: *name, Hash: hash, Agents: split(*agents), Workspaces: split(*workspaces), DefaultWorkspace: *defWS}
		check, sc, withDefaults := *cfg, *cfg.Server, entry
		config.ApplyTokenDefaults(&withDefaults)
		sc.Tokens = append(append([]config.Token(nil), cfg.Server.Tokens...), withDefaults)
		check.Server = &sc
		if err := check.Validate(); err != nil {
			return err
		}
		tf.Tokens = append(tf.Tokens, entry)
		if err := config.WriteTokensFile(path, tf); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Created token %q (stored as a hash in %s).\n", *name, path)
		fmt.Fprintln(os.Stderr, "It is shown once. Anyone with it can make these agents do anything this user can on this machine.")
		fmt.Println(token)
		return nil
	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tAGENTS\tWORKSPACES\tSOURCE")
		for _, t := range cfg.Server.Tokens {
			source := "config"
			for _, ft := range tf.Tokens {
				if ft.Name == t.Name {
					source = "tokens file"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Name, strings.Join(t.Agents, ","), strings.Join(t.Workspaces, ","), source)
		}
		return w.Flush()
	case "revoke":
		if fs.NArg() != 1 {
			return errors.New("usage: actp token revoke NAME")
		}
		target := fs.Arg(0)
		kept := tf.Tokens[:0]
		found := false
		for _, t := range tf.Tokens {
			if t.Name == target {
				found = true
				continue
			}
			kept = append(kept, t)
		}
		if !found {
			return fmt.Errorf("no token %q in %s (tokens written in the config file are removed there)", target, path)
		}
		tf.Tokens = kept
		if err := config.WriteTokensFile(path, tf); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Revoked %q. A running server picks this up on restart.\n", target)
		return nil
	}
	return fmt.Errorf("unknown token command %q", sub)
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

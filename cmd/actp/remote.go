package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/varops/actp/internal/config"
)

var remoteName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func cmdRemote(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: actp remote add|list|remove")
	}
	fs := flag.NewFlagSet("remote", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file")
	tokenStdin := fs.Bool("token-stdin", false, "read the token from stdin and save it in a private file")
	tokenEnv := fs.String("token-env", "", "read the token from this environment variable when connecting")
	tokenFile := fs.String("token-file", "", "read the token from this file when connecting")
	sub, rest := args[0], args[1:]
	// Allow flags after the positional arguments: actp remote add NAME URL --token-stdin.
	var positional []string
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		positional, rest = append(positional, rest[0]), rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return exitError(2)
	}
	positional = append(positional, fs.Args()...)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	rf, err := config.ReadRemotesFile(cfg.RemotesFile)
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		if len(positional) != 2 {
			return errors.New("usage: actp remote add NAME URL [--token-stdin | --token-env NAME | --token-file PATH]")
		}
		name, rawURL := positional[0], positional[1]
		if !remoteName.MatchString(name) {
			return fmt.Errorf("remote name %q may only use letters, digits, - and _", name)
		}
		if cfg.Remote(name) != nil {
			return fmt.Errorf("a remote named %q already exists", name)
		}
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("URL must look like https://host[:port], got %q", rawURL)
		}
		r := config.Remote{Name: name, URL: strings.TrimSuffix(rawURL, "/"), TokenEnv: *tokenEnv, TokenFile: *tokenFile}
		if *tokenStdin {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			token := strings.TrimSpace(line)
			if token == "" {
				return fmt.Errorf("no token on stdin: %v", err)
			}
			if err := config.SaveRemoteToken(cfg, &r, token); err != nil {
				return err
			}
			if r.TokenKeychain {
				fmt.Fprintln(os.Stderr, "Token saved in the OS keychain.")
			} else {
				fmt.Fprintln(os.Stderr, "No OS keychain available; token saved in", r.TokenFile)
			}
		}
		rf.Remotes = append(rf.Remotes, r)
		if err := config.WriteRemotesFile(cfg.RemotesFile, rf); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Saved remote %q. Use it as: actp <agent>@%s\n", name, name)
		return nil
	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tURL\tTOKEN")
		for _, r := range cfg.Remotes {
			src := "ACTP_TOKEN"
			switch {
			case r.TokenEnv != "":
				src = "$" + r.TokenEnv
			case r.TokenFile != "":
				src = r.TokenFile
			case r.TokenKeychain:
				src = "OS keychain"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Name, r.URL, src)
		}
		return w.Flush()
	case "remove":
		if len(positional) != 1 {
			return errors.New("usage: actp remote remove NAME")
		}
		kept := rf.Remotes[:0]
		var removed *config.Remote
		for _, r := range rf.Remotes {
			if r.Name == positional[0] {
				removed = &r
				continue
			}
			kept = append(kept, r)
		}
		if removed == nil {
			return fmt.Errorf("no remote %q in %s (remotes written in the config file are removed there)", positional[0], cfg.RemotesFile)
		}
		rf.Remotes = kept
		if err := config.WriteRemotesFile(cfg.RemotesFile, rf); err != nil {
			return err
		}
		config.DeleteRemoteToken(cfg, removed)
		fmt.Fprintf(os.Stderr, "Removed remote %q.\n", positional[0])
		return nil
	}
	return fmt.Errorf("unknown remote command %q", sub)
}

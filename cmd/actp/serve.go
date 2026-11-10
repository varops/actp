package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/server"
	"github.com/varops/actp/internal/tunnel"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file (default "+config.DefaultPath()+")")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Server == nil {
		return fmt.Errorf("%s has no server section", cfg.Path())
	}
	sc := cfg.Server
	if err := checkListen(sc); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(sc.Tokens) == 0 {
		log.Warn("no tokens configured: nobody can connect. Create one with `actp token create --name NAME`.")
	}
	if len(sc.Agents) == 0 {
		log.Warn("no agents configured")
	}

	srv, err := server.New(sc, server.Options{Version: version, Logger: log, ProbeOnStart: true})
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Addr:              sc.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errs := make(chan error, 1)
	go func() {
		log.Info("actp server listening", "addr", sc.Listen, "version", version, "agents", len(sc.Agents))
		if sc.TLSCert != "" {
			errs <- httpSrv.ListenAndServeTLS(sc.TLSCert, sc.TLSKey)
		} else {
			errs <- httpSrv.ListenAndServe()
		}
	}()

	ctx, stopTunnel := context.WithCancel(context.Background())
	defer stopTunnel()
	if mode := string(sc.Tunnel.Mode); mode != "off" {
		if sc.TLSCert != "" {
			return fmt.Errorf("the tunnel needs the server on plain HTTP on loopback; remove tls_cert and tls_key")
		}
		token := ""
		if mode == "named" {
			token = os.Getenv(sc.Tunnel.TokenEnv)
		}
		tun, err := tunnel.Start(ctx, tunnel.Options{
			Mode: mode, Target: "http://" + sc.Listen, Token: token, Logger: log,
			OnURL: func(u string) {
				srv.SetPublicURL(u)
				log.Info("clients can connect with: actp <agent>@" + u)
			},
		})
		if err != nil {
			return fmt.Errorf("tunnel: %w", err)
		}
		defer func() { stopTunnel(); <-tun.Done() }()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
loop:
	for {
		select {
		case err := <-errs:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			break loop
		case <-hup:
			reloadConfig(log, srv, cfg.Path(), sc)
		case s := <-sig:
			log.Info("stopping: waiting up to 30 s for running turns", "signal", s.String())
			break loop
		}
	}
	srv.Close(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(ctx)
}

// reloadConfig applies a changed config file. Listen address and TLS need a restart.
func reloadConfig(log *slog.Logger, srv *server.Server, path string, running *config.Server) {
	cfg, err := config.Load(path)
	if err != nil {
		log.Error("config reload failed, keeping the old config", "error", err)
		return
	}
	if cfg.Server == nil {
		log.Error("config reload failed: no server section, keeping the old config")
		return
	}
	if cfg.Server.Listen != running.Listen || cfg.Server.TLSCert != running.TLSCert {
		log.Warn("listen and TLS changes need a restart; other changes apply now")
	}
	srv.Reload(cfg.Server)
}

// checkListen refuses plain HTTP on a public address unless told it sits behind a TLS proxy.
func checkListen(sc *config.Server) error {
	host, _, err := net.SplitHostPort(sc.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", sc.Listen, err)
	}
	if isLoopback(host) || sc.TLSCert != "" || sc.InsecureListen {
		return nil
	}
	return fmt.Errorf("listen %q is not a loopback address: set tls_cert and tls_key, or insecure_listen: true behind a TLS proxy", sc.Listen)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

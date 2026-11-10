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
	"sync"
	"syscall"
	"time"

	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/dashboard"
	"github.com/varops/actp/internal/server"
	"github.com/varops/actp/internal/tunnel"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file (default "+config.DefaultPath()+")")
	dash := fs.Bool("dashboard", false, "also serve the local dashboard and print its one-time link")
	if err := fs.Parse(args); err != nil {
		return exitError(2)
	}
	return runHost(context.Background(), hostOptions{configPath: *cfgPath, dashboard: *dash, requireServer: true})
}

type hostOptions struct {
	configPath    string
	dashboard     bool
	requireServer bool
	// onReady is called once the server and dashboard are up (dash may be nil).
	onReady func(h *host)
}

// host is what `actp serve` and `actp tray` run: the server, its tunnel and the dashboard.
type host struct {
	log  *slog.Logger
	srv  *server.Server // nil when the config has no server section
	dash *dashboard.Dashboard
	stop context.CancelFunc
	// tunnelLaunch starts the configured tunnel; nil when the tunnel is off.
	tunnelLaunch func() (<-chan struct{}, error)
	tunnelMu     sync.Mutex
	tunnelDone   <-chan struct{}
}

// startTunnel starts the tunnel once; later calls are no-ops while it runs.
func (h *host) startTunnel() error {
	h.tunnelMu.Lock()
	defer h.tunnelMu.Unlock()
	if h.tunnelLaunch == nil {
		return errors.New("the tunnel is off in the config")
	}
	if h.tunnelDone != nil {
		return nil
	}
	done, err := h.tunnelLaunch()
	if err == nil {
		h.tunnelDone = done
	}
	return err
}

func (h *host) waitTunnel() {
	h.tunnelMu.Lock()
	done := h.tunnelDone
	h.tunnelMu.Unlock()
	if done != nil {
		<-done
	}
}

// Quit asks the host to stop, like a signal does.
func (h *host) Quit() { h.stop() }

func runHost(parent context.Context, opts hostOptions) error {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	if cfg.Server == nil && opts.requireServer {
		return fmt.Errorf("%s has no server section", cfg.Path())
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := context.WithCancel(parent)
	defer stop()
	h := &host{log: log, stop: stop}

	var httpSrv *http.Server
	errs := make(chan error, 1)
	if sc := cfg.Server; sc != nil {
		if err := checkListen(sc); err != nil {
			return err
		}
		if len(sc.Tokens) == 0 {
			log.Warn("no tokens configured: nobody can connect. Create one with `actp token create --name NAME` or the dashboard.")
		}
		if len(sc.Agents) == 0 {
			log.Warn("no agents configured")
		}
		h.srv, err = server.New(sc, server.Options{Version: version, Logger: log, ProbeOnStart: true})
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", sc.Listen)
		if err != nil {
			return err
		}
		httpSrv = &http.Server{Handler: h.srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("actp server listening", "addr", sc.Listen, "version", version, "agents", len(sc.Agents))
			if sc.TLSCert != "" {
				errs <- httpSrv.ServeTLS(ln, sc.TLSCert, sc.TLSKey)
			} else {
				errs <- httpSrv.Serve(ln)
			}
		}()
		if mode := string(sc.Tunnel.Mode); mode != "off" {
			if sc.TLSCert != "" {
				return fmt.Errorf("the tunnel needs the server on plain HTTP on loopback; remove tls_cert and tls_key")
			}
			h.tunnelLaunch = func() (<-chan struct{}, error) {
				token := ""
				if mode == "named" {
					token = os.Getenv(sc.Tunnel.TokenEnv)
				}
				srv := h.srv
				tun, err := tunnel.Start(ctx, tunnel.Options{
					Mode: mode, Target: "http://" + sc.Listen, Token: token, Logger: log,
					OnURL: func(u string) {
						srv.SetPublicURL(u)
						log.Info("clients can connect with: actp <agent>@" + u)
					},
				})
				if err != nil {
					return nil, err
				}
				return tun.Done(), nil
			}
			if err := h.startTunnel(); err != nil {
				// A missing cloudflared should not stop the server: it can be installed from the dashboard.
				log.Warn("tunnel not started: "+err.Error(), "fix", "actp tunnel install, or the dashboard")
			}
			defer func() {
				stop()
				h.waitTunnel()
			}()
		}
	}

	if opts.dashboard {
		srv := h.srv
		path := cfg.Path()
		h.dash, err = dashboard.Listen(dashboard.Options{Server: srv, ConfigPath: path, Version: version, StartTunnel: h.startTunnel, Reload: func() error {
			if srv == nil {
				return nil
			}
			c, err := config.Load(path)
			if err != nil {
				return err
			}
			if c.Server == nil {
				return errors.New("the server section is gone from the config")
			}
			srv.Reload(c.Server)
			return nil
		}})
		if err != nil {
			return err
		}
		defer h.dash.Close()
		log.Info("dashboard (one-time link, local only): " + h.dash.URL())
	}
	if opts.onReady != nil {
		go opts.onReady(h)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(sig)
	defer signal.Stop(hup)
loop:
	for {
		select {
		case err := <-errs:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			break loop
		case <-hup:
			if h.srv != nil {
				reloadConfig(log, h.srv, cfg.Path(), cfg.Server)
			}
		case s := <-sig:
			log.Info("stopping: waiting up to 30 s for running turns", "signal", s.String())
			break loop
		case <-ctx.Done():
			log.Info("stopping: waiting up to 30 s for running turns")
			break loop
		}
	}
	if h.srv != nil {
		h.srv.Close(30 * time.Second)
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(sctx)
	}
	return nil
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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/dashboard"
	"github.com/varops/actp/internal/logfile"
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
	logFile       bool // also log to ~/.actp/logs/actp.log
	// onReady is called once the host and dashboard are up (dash may be nil).
	onReady func(h *host)
}

// host is what `actp serve` and `actp tray` run: the server, its tunnel and the
// dashboard. The server can also start later, once the dashboard has set it up.
type host struct {
	log        *slog.Logger
	configPath string // as given; "" means the default path
	ctx        context.Context
	stop       context.CancelFunc
	errs       chan error
	dash       *dashboard.Dashboard

	mu         sync.Mutex
	srv        *server.Server
	httpSrv    *http.Server
	running    *config.Server
	tunnelDone <-chan struct{}
	tunnel     *tunnel.Tunnel
	tunnelFn   func() (<-chan struct{}, error)
}

// Quit asks the host to stop, like a signal does.
func (h *host) Quit() { h.stop() }

// Server is the running server, or nil when this machine runs none (yet).
func (h *host) Server() *server.Server {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.srv
}

func (h *host) configFile() string {
	if h.configPath != "" {
		return h.configPath
	}
	return config.DefaultPath()
}

// startServer reads the config and starts the server if it has a server section
// and none is running. It returns (false, nil) when there is nothing to start.
func (h *host) startServer() (bool, error) {
	cfg, err := config.Load(h.configPath)
	if err != nil {
		return false, err
	}
	sc := cfg.Server
	if sc == nil {
		return false, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		return true, nil
	}
	if err := checkListen(sc); err != nil {
		return false, err
	}
	if sc.Tunnel.Mode != "off" && sc.TLSCert != "" {
		return false, errors.New("the tunnel needs the server on plain HTTP on loopback; remove tls_cert and tls_key")
	}
	if len(sc.Tokens) == 0 {
		h.log.Warn("no tokens configured: nobody can connect. Create one with `actp token create --name NAME` or the dashboard.")
	}
	if len(sc.Agents) == 0 {
		h.log.Warn("no agents configured")
	}
	ln, err := net.Listen("tcp", sc.Listen)
	if err != nil {
		return false, err
	}
	srv, err := server.New(sc, server.Options{Version: version, Logger: h.log, ProbeOnStart: true})
	if err != nil {
		ln.Close()
		return false, err
	}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		h.log.Info("actp server listening", "addr", sc.Listen, "version", version, "agents", len(sc.Agents))
		var err error
		if sc.TLSCert != "" {
			err = httpSrv.ServeTLS(ln, sc.TLSCert, sc.TLSKey)
		} else {
			err = httpSrv.Serve(ln)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			h.errs <- err
		}
	}()
	h.srv, h.httpSrv, h.running = srv, httpSrv, sc

	if mode := string(sc.Tunnel.Mode); mode != "off" {
		h.tunnelFn = func() (<-chan struct{}, error) {
			token := ""
			if mode == "named" {
				token = os.Getenv(sc.Tunnel.TokenEnv)
			}
			var out io.Writer
			if f, err := logfile.Open(sc.LogDir, "cloudflared.log"); err == nil {
				out = f
				go func() { <-h.ctx.Done(); f.Close() }()
			}
			checkCtx, stopCheck := context.WithCancel(h.ctx)
			tun, err := tunnel.Start(h.ctx, tunnel.Options{
				Mode: mode, Target: "http://" + sc.Listen, Token: token, Logger: h.log, Output: out,
				OnURL: func(u string) {
					srv.SetPublicURL(u)
					h.log.Info("clients can connect with: actp <agent>@" + u)
					stopCheck()
					checkCtx, stopCheck = context.WithCancel(h.ctx)
					go checkPublicURL(checkCtx, h.log, srv, u)
				},
			})
			if err != nil {
				stopCheck()
				return nil, err
			}
			h.tunnel = tun
			return tun.Done(), nil
		}
		if err := h.startTunnelLocked(); err != nil {
			// A missing cloudflared should not stop the server: it can be installed from the dashboard.
			h.log.Warn("tunnel not started: "+err.Error(), "fix", "actp tunnel install, or the dashboard")
		}
	}
	return true, nil
}

// checkPublicURL asks the public URL for /health every 30 s, so the dashboard
// can say whether the tunnel really reaches this server.
func checkPublicURL(ctx context.Context, log *slog.Logger, srv *server.Server, url string) {
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialViaPublicDNS,
	}}
	// A new quick tunnel takes 10-60 s to appear in DNS. Asking too early makes
	// caches remember "no such host", so wait before the first check.
	select {
	case <-ctx.Done():
		return
	case <-time.After(firstCheckDelay):
	}
	wasOK := false
	for {
		check := server.PublicCheck{At: time.Now()}
		resp, err := client.Get(url + "/health")
		switch {
		case err != nil:
			check.Detail = err.Error()
			if strings.Contains(err.Error(), "no such host") {
				check.Detail = "Cloudflare has not published this address yet. If this machine looked it up too early it may remember \"not found\" for a while; clear the cache with: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder"
			}
		default:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			check.OK = resp.StatusCode == http.StatusOK && strings.Contains(string(body), `"ok"`)
			if !check.OK {
				check.Detail = fmt.Sprintf("HTTP %d from %s, not from actp", resp.StatusCode, url)
			}
		}
		if check.OK != wasOK {
			if check.OK {
				log.Info("tunnel is reachable", "url", url)
			} else if wasOK {
				log.Warn("tunnel stopped answering", "url", url, "detail", check.Detail)
			}
			wasOK = check.OK
		}
		srv.SetPublicCheck(check)
		delay := 30 * time.Second
		if !check.OK {
			delay = 10 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// firstCheckDelay is how long checkPublicURL waits before its first request.
var firstCheckDelay = 20 * time.Second

// publicResolver asks Cloudflare's DNS directly, so the check neither depends on
// nor fills this machine's DNS cache. It falls back to the system resolver.
func publicResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		if c, err := d.DialContext(ctx, network, "1.1.1.1:53"); err == nil {
			return c, nil
		}
		return d.DialContext(ctx, network, "1.0.0.1:53")
	}}
}

// dialViaPublicDNS resolves with Cloudflare's DNS and falls back to the system
// resolver when that is blocked.
func dialViaPublicDNS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, addr)
	}
	ips, err := publicResolver().LookupHost(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, err // a real answer: the name does not exist (yet)
		}
		return d.DialContext(ctx, network, addr) // public DNS unreachable: use the system's
	}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// TunnelError is cloudflared's last error line, if any.
func (h *host) TunnelError() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tunnel == nil {
		return ""
	}
	return h.tunnel.LastError()
}

// startTunnel starts the tunnel once; later calls are no-ops while it runs.
func (h *host) startTunnel() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.startTunnelLocked()
}

func (h *host) startTunnelLocked() error {
	if h.tunnelFn == nil {
		return errors.New("the tunnel is off in the config")
	}
	if h.tunnelDone != nil {
		return nil
	}
	done, err := h.tunnelFn()
	if err == nil {
		h.tunnelDone = done
	}
	return err
}

// reload re-reads the config into the running server.
func (h *host) reload() error {
	srv := h.Server()
	if srv == nil {
		return nil
	}
	c, err := config.Load(h.configPath)
	if err != nil {
		return err
	}
	if c.Server == nil {
		return errors.New("the server section is gone from the config")
	}
	h.mu.Lock()
	running := h.running
	h.mu.Unlock()
	if c.Server.Listen != running.Listen || c.Server.TLSCert != running.TLSCert {
		h.log.Warn("listen and TLS changes need a restart; other changes apply now")
	}
	srv.Reload(c.Server)
	return nil
}

func (h *host) shutdown() error {
	h.stop()
	h.mu.Lock()
	srv, httpSrv, tunnelDone := h.srv, h.httpSrv, h.tunnelDone
	h.mu.Unlock()
	if tunnelDone != nil {
		<-tunnelDone
	}
	if srv == nil {
		return nil
	}
	srv.Close(30 * time.Second)
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(sctx)
}

func runHost(parent context.Context, opts hostOptions) error {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	if cfg.Server == nil && opts.requireServer {
		return fmt.Errorf("%s has no server section", cfg.Path())
	}
	ctx, stop := context.WithCancel(parent)
	defer stop()
	var logOut io.Writer = os.Stderr
	if opts.logFile {
		// An app started from Finder has no terminal: keep its log where people can find it.
		dir := filepath.Join(config.Dir(), "logs")
		if cfg.Server != nil {
			dir = cfg.Server.LogDir
		}
		if f, err := logfile.Open(dir, "actp.log"); err == nil {
			defer f.Close()
			logOut = io.MultiWriter(os.Stderr, f)
		}
	}
	h := &host{log: slog.New(slog.NewTextHandler(logOut, nil)), configPath: opts.configPath, ctx: ctx, stop: stop, errs: make(chan error, 1)}
	if _, err := h.startServer(); err != nil {
		return err
	}

	if opts.dashboard {
		h.dash, err = dashboard.Listen(dashboard.Options{
			Server:      h.Server,
			ConfigPath:  opts.configPath,
			ConfigFile:  h.configFile(),
			Version:     version,
			StartTunnel: h.startTunnel,
			TunnelError: h.TunnelError,
			Reload:      h.reload,
			StartServer: func() error {
				started, err := h.startServer()
				if err == nil && !started {
					err = errors.New("the config has no server section")
				}
				return err
			},
		})
		if err != nil {
			return err
		}
		defer h.dash.Close()
		h.log.Info("dashboard (one-time link, local only): " + h.dash.URL())
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
	for {
		select {
		case err := <-h.errs:
			_ = h.shutdown()
			return err
		case <-hup:
			if err := h.reload(); err != nil {
				h.log.Error("config reload failed, keeping the old config", "error", err)
			}
		case s := <-sig:
			h.log.Info("stopping: waiting up to 30 s for running turns", "signal", s.String())
			return h.shutdown()
		case <-ctx.Done():
			h.log.Info("stopping: waiting up to 30 s for running turns")
			return h.shutdown()
		}
	}
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

// Package terminal serves a shell over a WebSocket for the dashboard. Binary
// messages carry terminal bytes both ways; text messages from the browser are
// JSON resize requests: {"cols":80,"rows":24}.
package terminal

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
)

// Options configure a terminal session.
type Options struct {
	Shell  string   // default $SHELL, then /bin/bash, then /bin/sh
	Dir    string   // default the home folder
	Env    []string // default os.Environ()
	Logger *slog.Logger
	// Who names the session in the log, for example the remote address.
	Who string
}

type resize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// Serve upgrades the request and runs a shell until either side closes. The
// WebSocket handshake refuses other origins than the page's own.
func Serve(w http.ResponseWriter, r *http.Request, opts Options) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Env == nil {
		opts.Env = os.Environ()
	}
	if opts.Dir == "" {
		opts.Dir, _ = os.UserHomeDir()
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sh, err := start(opts)
	if err != nil {
		_ = c.Write(ctx, websocket.MessageBinary, []byte("could not start a shell: "+err.Error()+"\r\n"))
		c.Close(websocket.StatusInternalError, "no shell")
		return
	}
	began := time.Now()
	opts.Logger.Info("dashboard terminal opened", "who", opts.Who, "shell", sh.name)
	defer func() {
		sh.close()
		opts.Logger.Info("dashboard terminal closed", "who", opts.Who, "after", time.Since(began).Round(time.Second).String())
	}()

	go func() { // shell → browser
		defer cancel()
		buf := make([]byte, 32<<10)
		for {
			n, err := sh.Read(buf)
			if n > 0 {
				if c.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				c.Close(websocket.StatusNormalClosure, "shell exited")
				return
			}
		}
	}()
	for { // browser → shell
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if typ == websocket.MessageText {
			var rs resize
			if json.Unmarshal(data, &rs) == nil && rs.Cols > 0 && rs.Rows > 0 {
				sh.resize(rs.Cols, rs.Rows)
			}
			continue
		}
		if _, err := sh.Write(data); err != nil {
			return
		}
	}
}

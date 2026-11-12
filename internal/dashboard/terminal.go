package dashboard

import (
	"errors"
	"net/http"

	"github.com/varops/actp/internal/terminal"
)

func (d *Dashboard) terminal(w http.ResponseWriter, r *http.Request) {
	if !d.opts.Terminal || !terminal.Supported {
		writeErr(w, http.StatusNotFound, errors.New("the terminal is off: set dashboard.terminal: true in the config"))
		return
	}
	terminal.Serve(w, r, terminal.Options{Env: d.opts.Env, Logger: d.opts.Logger, Who: r.RemoteAddr})
}

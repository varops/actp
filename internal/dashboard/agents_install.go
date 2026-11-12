package dashboard

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/varops/actp/internal/agentproc"
	"github.com/varops/actp/internal/config"
	"github.com/varops/actp/internal/installer"
)

type recipeView struct {
	installer.Recipe
	// Versions of the recipe's packages installed by actp, by package.
	Versions map[string]string `json:"versions,omitempty"`
	// Elsewhere is the command found outside actp's prefix, if any.
	Elsewhere string `json:"elsewhere,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// installerInfo lists the agents the dashboard can install, and their state.
func (d *Dashboard) installerInfo(w http.ResponseWriter, r *http.Request) {
	in := d.opts.Installer
	if in == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	resp := map[string]any{"available": true, "prefix": config.AgentsPrefix()}
	if _, err := in.NPM(); err != nil {
		resp["available"], resp["reason"] = false, err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	enabled := map[string]bool{}
	if cfg, err := config.LoadOrEmpty(d.opts.ConfigPath); err == nil && cfg.Server != nil {
		for _, a := range cfg.Server.Agents {
			enabled[a.Preset] = true
		}
	}
	versions := in.Installed(r.Context())
	shellEnv := agentproc.CachedLoginShellEnv()
	var out []recipeView
	for _, rc := range installer.Recipes {
		v := recipeView{Recipe: rc, Versions: map[string]string{}, Enabled: enabled[rc.Preset]}
		for _, p := range rc.Packages {
			if ver, ok := versions[p]; ok {
				v.Versions[p] = ver
			}
		}
		if len(v.Versions) == 0 {
			if path, err := agentproc.LookPath(config.Presets[rc.Preset].Command, shellEnv); err == nil {
				v.Elsewhere = path
			}
		}
		out = append(out, v)
	}
	resp["recipes"] = out
	resp["job"] = in.Job(0)
	writeJSON(w, http.StatusOK, resp)
}

func (d *Dashboard) installerJob(w http.ResponseWriter, r *http.Request) {
	if d.opts.Installer == nil {
		writeErr(w, http.StatusNotFound, errors.New("no installer"))
		return
	}
	from, _ := strconv.Atoi(r.URL.Query().Get("from"))
	writeJSON(w, http.StatusOK, map[string]any{"job": d.opts.Installer.Job(from)})
}

func (d *Dashboard) installerStart(w http.ResponseWriter, r *http.Request) {
	if d.opts.Installer == nil {
		writeErr(w, http.StatusNotFound, errors.New("no installer"))
		return
	}
	job, err := d.opts.Installer.Start(r.PathValue("preset"), r.PathValue("action"))
	if err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	d.opts.Logger.Info("agent "+job.Action+" started", "agent", job.Preset)
	writeJSON(w, http.StatusOK, map[string]any{"job": job})
}

// AfterInstall turns a preset on in the server config once it is installed,
// and off once it is removed. Agents written by hand are left alone.
func (d *Dashboard) AfterInstall(preset, action string) {
	if err := d.togglePreset(preset, action == installer.ActionInstall); err != nil {
		d.opts.Logger.Warn("could not update the agents in the config", "agent", preset, "error", err)
		return
	}
	if d.opts.Reload != nil {
		if err := d.opts.Reload(); err != nil {
			d.opts.Logger.Warn("reload after install failed", "error", err)
			return
		}
	}
	if srv := d.server(); srv != nil && action == installer.ActionInstall {
		if a := srv.Config().Agent(setupID(preset)); a != nil {
			go srv.Probe(a)
		}
	}
}

func (d *Dashboard) togglePreset(preset string, on bool) error {
	cfg, err := config.LoadOrEmpty(d.opts.ConfigPath)
	if err != nil || cfg.Server == nil {
		return err // no server yet: the setup form offers the agent
	}
	_, err = config.SetPresetEnabled(d.opts.ConfigFile, preset, on)
	return err
}

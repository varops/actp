package server

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/varops/actp/internal/config"
)

// Session modes (design 3.3). An agent mode can turn permission prompts off
// (Claude's bypassPermissions), which would make the permission policy and the
// human approval step meaningless. So the server lets a client switch only to
// allowed modes: an agent's allowed_modes, or by default the modes that keep
// prompts or only narrow what runs. Unknown mode ids are refused.
var defaultSafeModes = []string{"default", "plan", "dontAsk", "acceptEdits", "auto"}

// promptSkippingModes approve some actions without asking. A token whose
// permissions are auto_deny never gets them: they would allow what actp denies.
var promptSkippingModes = map[string]bool{"acceptEdits": true, "auto": true, "bypassPermissions": true}

// modeAllowed reports whether a client may switch a session to mode.
func modeAllowed(agent *config.Agent, tok *config.Token, mode string) bool {
	if tok.EffectivePermissions(agent) == "auto_deny" && promptSkippingModes[mode] {
		return false
	}
	allowed := agent.AllowedModes
	if len(allowed) == 0 {
		allowed = defaultSafeModes
	}
	return slices.Contains(allowed, mode)
}

var errUnreadableMode = errors.New("mode not allowed: the requested mode is not a string")

// requestedModes lists the modes a client request would switch a session to:
// session/set_mode, session/set_config_option on a mode option, and mode entries
// in the configOptions of session setup requests. isModeOption tells which
// config options select the mode.
func requestedModes(method string, p map[string]json.RawMessage, isModeOption func(string) bool) ([]string, error) {
	str := func(raw json.RawMessage) (string, bool) {
		var s string
		return s, raw != nil && json.Unmarshal(raw, &s) == nil
	}
	switch {
	case method == "session/set_mode":
		mode, ok := str(p["modeId"])
		if !ok {
			return nil, errUnreadableMode
		}
		return []string{mode}, nil
	case method == "session/set_config_option":
		id, _ := str(p["configId"])
		if !isModeOption(id) {
			return nil, nil
		}
		mode, ok := str(p["value"])
		if !ok {
			return nil, errUnreadableMode
		}
		return []string{mode}, nil
	case sessionCwdRequired[method] || sessionCwdOptional[method]:
		var entries []map[string]json.RawMessage
		if raw, ok := p["configOptions"]; !ok || json.Unmarshal(raw, &entries) != nil {
			return nil, nil
		}
		var modes []string
		for _, e := range entries {
			id, _ := str(e["configId"])
			if !isModeOption(id) {
				continue
			}
			mode, ok := str(e["value"])
			if !ok {
				return nil, errUnreadableMode
			}
			modes = append(modes, mode)
		}
		return modes, nil
	}
	return nil, nil
}

// learnModes records, from a session response, which config options select the
// mode and which mode ids the agent offers.
func learnModes(result json.RawMessage, modeOptions, offered map[string]bool) {
	var r struct {
		Modes *struct {
			AvailableModes []struct {
				ID string `json:"id"`
			} `json:"availableModes"`
		} `json:"modes"`
		ConfigOptions []struct {
			ID       string            `json:"id"`
			Category string            `json:"category"`
			Options  []json.RawMessage `json:"options"`
		} `json:"configOptions"`
	}
	_ = json.Unmarshal(result, &r)
	if r.Modes != nil {
		for _, m := range r.Modes.AvailableModes {
			if m.ID != "" {
				offered[m.ID] = true
			}
		}
	}
	for _, o := range r.ConfigOptions {
		if o.Category != "mode" && o.ID != "mode" {
			continue
		}
		modeOptions[o.ID] = true
		for _, raw := range o.Options {
			var v struct {
				Value   string `json:"value"`
				Options []struct {
					Value string `json:"value"`
				} `json:"options"`
			}
			_ = json.Unmarshal(raw, &v)
			if v.Value != "" {
				offered[v.Value] = true
			}
			for _, g := range v.Options {
				if g.Value != "" {
					offered[g.Value] = true
				}
			}
		}
	}
}

// permissionPicksMode returns the mode a client's answer to a permission request
// selects, when that option is one of the agent's modes (Claude's plan-mode exit
// offers "Yes, and bypass permissions" as option bypassPermissions).
func permissionPicksMode(result json.RawMessage, offered map[string]bool) string {
	var r struct {
		Outcome struct {
			Outcome  string `json:"outcome"`
			OptionID string `json:"optionId"`
		} `json:"outcome"`
	}
	if json.Unmarshal(result, &r) != nil || r.Outcome.Outcome != "selected" {
		return ""
	}
	if offered[r.Outcome.OptionID] || r.Outcome.OptionID == "bypassPermissions" {
		return r.Outcome.OptionID
	}
	return ""
}

// startingModes reads a session response: the session's current mode values
// (modes.currentModeId and the currentValue of mode config options) and the
// modes it offers, in the agent's order.
func startingModes(result json.RawMessage) (current, offered []string) {
	var r struct {
		Modes *struct {
			CurrentModeID  string `json:"currentModeId"`
			AvailableModes []struct {
				ID string `json:"id"`
			} `json:"availableModes"`
		} `json:"modes"`
		ConfigOptions []struct {
			ID           string            `json:"id"`
			Category     string            `json:"category"`
			CurrentValue json.RawMessage   `json:"currentValue"`
			Options      []json.RawMessage `json:"options"`
		} `json:"configOptions"`
	}
	_ = json.Unmarshal(result, &r)
	add := func(list *[]string, v string) {
		if v != "" && !slices.Contains(*list, v) {
			*list = append(*list, v)
		}
	}
	if r.Modes != nil {
		add(&current, r.Modes.CurrentModeID)
		for _, m := range r.Modes.AvailableModes {
			add(&offered, m.ID)
		}
	}
	for _, o := range r.ConfigOptions {
		if o.Category != "mode" && o.ID != "mode" {
			continue
		}
		var v string
		if json.Unmarshal(o.CurrentValue, &v) == nil {
			add(&current, v)
		}
		for _, raw := range o.Options {
			var opt struct {
				Value string `json:"value"`
			}
			_ = json.Unmarshal(raw, &opt)
			add(&offered, opt.Value)
		}
	}
	return current, offered
}

// resetTarget picks the mode a session that starts in a refused mode is switched
// to: the agent's "default" when offered and allowed, else the first allowed mode
// it offers, else "" (none).
func resetTarget(offered []string, allowed func(string) bool) string {
	if slices.Contains(offered, "default") && allowed("default") {
		return "default"
	}
	for _, m := range offered {
		if allowed(m) {
			return m
		}
	}
	return ""
}

// rewriteStartingMode shows mode as the session's current mode in a session
// response: modes.currentModeId and the currentValue of mode config options.
func rewriteStartingMode(result json.RawMessage, mode string) (json.RawMessage, error) {
	var r map[string]json.RawMessage
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, err
	}
	enc, _ := json.Marshal(mode)
	if raw, ok := r["modes"]; ok {
		var modes map[string]json.RawMessage
		if json.Unmarshal(raw, &modes) == nil && modes != nil {
			modes["currentModeId"] = enc
			r["modes"], _ = json.Marshal(modes)
		}
	}
	if raw, ok := r["configOptions"]; ok {
		var opts []map[string]json.RawMessage
		if json.Unmarshal(raw, &opts) == nil {
			for _, o := range opts {
				var id, category string
				_ = json.Unmarshal(o["id"], &id)
				_ = json.Unmarshal(o["category"], &category)
				if o != nil && (category == "mode" || id == "mode") {
					o["currentValue"] = enc
				}
			}
			r["configOptions"], _ = json.Marshal(opts)
		}
	}
	return json.Marshal(r)
}

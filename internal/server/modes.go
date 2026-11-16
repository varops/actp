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

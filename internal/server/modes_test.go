package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/varops/actp/internal/config"
)

func TestModeAllowed(t *testing.T) {
	agent := &config.Agent{Permissions: "forward"}
	tok := &config.Token{}
	for mode, want := range map[string]bool{"default": true, "plan": true, "acceptEdits": true, "auto": true, "dontAsk": true, "bypassPermissions": false, "somethingNew": false} {
		if got := modeAllowed(agent, tok, mode); got != want {
			t.Errorf("forward, %s: %v", mode, got)
		}
	}
	deny := &config.Token{Permissions: "auto_deny"}
	for mode, want := range map[string]bool{"default": true, "plan": true, "acceptEdits": false, "auto": false, "bypassPermissions": false} {
		if got := modeAllowed(agent, deny, mode); got != want {
			t.Errorf("auto_deny, %s: %v", mode, got)
		}
	}
	listed := &config.Agent{Permissions: "forward", AllowedModes: []string{"read-only", "bypassPermissions"}}
	if !modeAllowed(listed, tok, "read-only") || !modeAllowed(listed, tok, "bypassPermissions") || modeAllowed(listed, tok, "default") {
		t.Error("allowed_modes is the whole list")
	}
	if modeAllowed(listed, deny, "bypassPermissions") {
		t.Error("auto_deny must refuse prompt-skipping modes even when listed")
	}
}

func TestRequestedModes(t *testing.T) {
	isMode := func(id string) bool { return id == "mode" || id == "_perm" }
	p := func(raw string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &m)
		return m
	}
	cases := []struct {
		method, params string
		want           []string
		err            bool
	}{
		{"session/set_mode", `{"sessionId":"s","modeId":"bypassPermissions"}`, []string{"bypassPermissions"}, false},
		{"session/set_mode", `{"sessionId":"s","modeId":1}`, nil, true},
		{"session/set_config_option", `{"sessionId":"s","configId":"mode","value":"plan"}`, []string{"plan"}, false},
		{"session/set_config_option", `{"sessionId":"s","configId":"_perm","value":"x"}`, []string{"x"}, false},
		{"session/set_config_option", `{"sessionId":"s","configId":"mode","type":"boolean","value":true}`, nil, true},
		{"session/set_config_option", `{"sessionId":"s","configId":"model","value":"opus"}`, nil, false},
		{"session/new", `{"cwd":"/w","configOptions":[{"configId":"model","value":"x"},{"configId":"mode","value":"bypassPermissions"}]}`, []string{"bypassPermissions"}, false},
		{"session/fork", `{"cwd":"/w","configOptions":[{"configId":"mode","value":"auto"}]}`, []string{"auto"}, false},
		{"session/prompt", `{"sessionId":"s","configOptions":[{"configId":"mode","value":"x"}]}`, nil, false},
	}
	for _, c := range cases {
		got, err := requestedModes(c.method, p(c.params), isMode)
		if (err != nil) != c.err || len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
			t.Errorf("%s %s: %v %v", c.method, c.params, got, err)
		}
	}
}

func TestLearnModesAndPermissionAnswers(t *testing.T) {
	options, offered := map[string]bool{}, map[string]bool{}
	learnModes(json.RawMessage(`{"sessionId":"s","modes":{"currentModeId":"default","availableModes":[{"id":"default"},{"id":"plan"}]},
		"configOptions":[{"id":"perm","category":"mode","options":[{"value":"acceptEdits"},{"name":"g","options":[{"value":"auto"}]}]},{"id":"model","category":"model","options":[{"value":"opus"}]}]}`), options, offered)
	if !options["perm"] || options["model"] || !offered["plan"] || !offered["acceptEdits"] || !offered["auto"] || offered["opus"] {
		t.Fatalf("options %v offered %v", options, offered)
	}
	if got := permissionPicksMode(json.RawMessage(`{"outcome":{"outcome":"selected","optionId":"plan"}}`), offered); got != "plan" {
		t.Errorf("mode option: %q", got)
	}
	if got := permissionPicksMode(json.RawMessage(`{"outcome":{"outcome":"selected","optionId":"allow"}}`), offered); got != "" {
		t.Errorf("plain option: %q", got)
	}
	if got := permissionPicksMode(json.RawMessage(`{"outcome":{"outcome":"selected","optionId":"bypassPermissions"}}`), nil); got != "bypassPermissions" {
		t.Errorf("bypass is always a mode: %q", got)
	}
}

func TestStartingModes(t *testing.T) {
	result := json.RawMessage(`{"sessionId":"s","modes":{"currentModeId":"bypassPermissions","availableModes":[{"id":"bypassPermissions"},{"id":"acceptEdits"},{"id":"default"}]},"configOptions":[{"id":"mode","category":"mode","type":"select","currentValue":"bypassPermissions","options":[{"value":"bypassPermissions"},{"value":"plan"}]},{"id":"model","currentValue":"opus"}]}`)
	current, offered := startingModes(result)
	if strings.Join(current, ",") != "bypassPermissions" || strings.Join(offered, ",") != "bypassPermissions,acceptEdits,default,plan" {
		t.Fatalf("current %v offered %v", current, offered)
	}
	agent, tok := &config.Agent{Permissions: "forward"}, &config.Token{}
	allowed := func(m string) bool { return modeAllowed(agent, tok, m) }
	if got := resetTarget(offered, allowed); got != "default" {
		t.Errorf("target %q", got)
	}
	if got := resetTarget([]string{"bypassPermissions", "plan"}, allowed); got != "plan" {
		t.Errorf("first allowed: %q", got)
	}
	if got := resetTarget([]string{"bypassPermissions"}, allowed); got != "" {
		t.Errorf("none allowed: %q", got)
	}
	out, err := rewriteStartingMode(result, "default")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"configOptions":[{"category":"mode","currentValue":"default","id":"mode","options":[{"value":"bypassPermissions"},{"value":"plan"}],"type":"select"},{"currentValue":"opus","id":"model"}],"modes":{"availableModes":[{"id":"bypassPermissions"},{"id":"acceptEdits"},{"id":"default"}],"currentModeId":"default"},"sessionId":"s"}`
	if string(out) != want {
		t.Errorf("rewrite:\n%s\nwant\n%s", out, want)
	}
}

func TestOnlyPendingRequestsAreAbandoned(t *testing.T) {
	reqs := map[string]clientReq{"7": {method: "session/load"}}
	abandoned := map[string]bool{}
	if !abandonPending(reqs, abandoned, "7") || !abandoned["7"] || len(reqs) != 0 {
		t.Fatalf("pending request: %v %v", reqs, abandoned)
	}
	// The agent's answer was taken just before the timeout: nothing is recorded,
	// so a later request reusing the id still gets its answer.
	abandoned = map[string]bool{}
	if abandonPending(reqs, abandoned, "7") || len(abandoned) != 0 {
		t.Fatalf("taken answer recorded: %v", abandoned)
	}
}

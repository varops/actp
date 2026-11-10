package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/varops/actp/api"
	"github.com/varops/actp/internal/bridge"
	"github.com/varops/actp/internal/jsonrpc"
)

// promptOptions is a one-shot prompt: `actp <agent>@<server> -p "text"`.
type promptOptions struct {
	target, agent, baseURL, token, text, cwd string
	yes, no                                  bool
}

// runPrompt sends one prompt through the bridge, like a minimal ACP client, and
// prints the answer. For trying a setup from a terminal, like `claude -p`.
func runPrompt(o promptOptions) error {
	agent, baseURL, token, text, target := o.agent, o.baseURL, o.token, o.text, o.target
	cwd, yes, no := &o.cwd, &o.yes, &o.no
	var err error
	if *cwd == "" {
		if *cwd, err = defaultFolder(baseURL, token, agent); err != nil {
			return err
		}
	}

	// The bridge runs in-process; we talk ACP to it over pipes.
	toBridgeR, toBridge := io.Pipe()
	fromBridge, fromBridgeW := io.Pipe()
	bridgeDone := make(chan error, 1)
	go func() {
		host, _ := os.Hostname()
		err := bridge.Run(context.Background(), bridge.Options{Agent: agent, BaseURL: baseURL, Token: token, ClientName: host + " (actp prompt)"}, toBridgeR, fromBridgeW)
		fromBridgeW.Close()
		bridgeDone <- err
	}()
	out := jsonrpc.NewWriter(toBridge)
	in := jsonrpc.NewReader(fromBridge)
	msgs := make(chan *jsonrpc.Message, 64)
	go func() {
		defer close(msgs)
		for {
			m, raw, err := in.Read()
			if err != nil {
				if m == nil && raw != nil {
					continue
				}
				return
			}
			msgs <- m
		}
	}()
	nextID := 0
	call := func(method string, params any) (json.RawMessage, error) {
		nextID++
		id := json.RawMessage(fmt.Sprint(nextID))
		m, _ := jsonrpc.NewRequest(id, method, params)
		if err := out.Write(m); err != nil {
			return nil, err
		}
		return id, nil
	}
	finish := func() error {
		toBridge.Close()
		select {
		case err := <-bridgeDone:
			return err
		case <-time.After(5 * time.Second):
			return nil
		}
	}
	tty := bufio.NewReader(os.Stdin)
	answer := func(m *jsonrpc.Message) *jsonrpc.Message { return answerAgentRequest(m, *yes, *no, tty) }
	wait := func(id json.RawMessage) (*jsonrpc.Message, error) {
		for m := range msgs {
			switch m.Kind() {
			case jsonrpc.KindResponse:
				if m.IDKey() == string(id) {
					if m.Error != nil {
						return nil, fmt.Errorf("%s (%d)", m.Error.Message, m.Error.Code)
					}
					return m, nil
				}
			case jsonrpc.KindRequest:
				_ = out.Write(answer(m))
			case jsonrpc.KindNotification:
				printUpdate(m)
			}
		}
		return nil, errors.New("the connection closed")
	}

	id, _ := call("initialize", map[string]any{
		"protocolVersion":    1,
		"clientCapabilities": map[string]any{},
		"clientInfo":         map[string]any{"name": "actp-prompt", "version": version},
	})
	if _, err := wait(id); err != nil {
		finish()
		return fmt.Errorf("initialize: %w", err)
	}
	id, _ = call("session/new", map[string]any{"cwd": *cwd, "mcpServers": []any{}})
	resp, err := wait(id)
	if err != nil {
		finish()
		return fmt.Errorf("session/new: %w", err)
	}
	var sess struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal(resp.Result, &sess)
	fmt.Fprintf(os.Stderr, "── %s in %s (session %s)\n", target, *cwd, sess.SessionID)

	// Ctrl-C cancels the turn instead of killing the bridge.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n── cancelling…")
		n, _ := jsonrpc.NewNotification("session/cancel", map[string]any{"sessionId": sess.SessionID})
		_ = out.Write(n)
	}()

	start := time.Now()
	id, _ = call("session/prompt", map[string]any{"sessionId": sess.SessionID, "prompt": []any{map[string]any{"type": "text", "text": text}}})
	resp, err = wait(id)
	if err != nil {
		finish()
		return fmt.Errorf("prompt: %w", err)
	}
	var res struct {
		StopReason string `json:"stopReason"`
	}
	_ = json.Unmarshal(resp.Result, &res)
	fmt.Fprintf(os.Stderr, "\n── %s after %s\n", res.StopReason, time.Since(start).Round(100*time.Millisecond))
	return finish()
}

// defaultFolder asks the server which folder this token starts in.
func defaultFolder(baseURL, token, agent string) (string, error) {
	client, err := api.NewClientWithResponses(baseURL, api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := client.ListAgentsWithResponse(ctx)
	if err != nil {
		return "", err
	}
	if resp.JSON200 == nil {
		if resp.StatusCode() == http.StatusNotFound {
			return "", errors.New(bridge.NoServerHint(baseURL))
		}
		return "", fmt.Errorf("server answered HTTP %d: %s", resp.StatusCode(), strings.TrimSpace(string(resp.Body)))
	}
	for _, a := range resp.JSON200.Agents {
		if a.Id != agent {
			continue
		}
		for _, w := range a.Workspaces {
			if w.Default != nil && *w.Default {
				return "actp://" + w.Name, nil
			}
		}
		if len(a.Workspaces) > 0 {
			return "actp://" + a.Workspaces[0].Name, nil
		}
		return "", errors.New("this token may use no folders on the server; pass --cwd")
	}
	return "", fmt.Errorf("the server offers no agent %q to this token", agent)
}

// lastKind is the previous update kind, so a new kind of output starts on its own line.
var lastKind string

// printUpdate shows the parts of a session/update a person wants to see.
func printUpdate(m *jsonrpc.Message) {
	if m.Method != "session/update" {
		return
	}
	var p struct {
		Update struct {
			Kind    string `json:"sessionUpdate"`
			Content struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Title  string `json:"title"`
			Status string `json:"status"`
		} `json:"update"`
	}
	if json.Unmarshal(m.Params, &p) != nil {
		return
	}
	u := p.Update
	if lastKind == "agent_thought_chunk" && u.Kind != lastKind {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr)
	}
	lastKind = u.Kind
	switch u.Kind {
	case "agent_message_chunk":
		fmt.Print(u.Content.Text)
	case "agent_thought_chunk":
		fmt.Fprint(os.Stderr, "\033[2m"+u.Content.Text+"\033[0m")
	case "tool_call":
		fmt.Fprintf(os.Stderr, "\n\033[36m▸ %s\033[0m\n", u.Title)
	case "tool_call_update":
		if u.Status == "failed" {
			fmt.Fprintf(os.Stderr, "\033[31m✗ tool failed\033[0m\n")
		}
	}
}

// answerAgentRequest answers permission prompts (asking on the terminal unless
// --yes or --no) and declines anything else.
func answerAgentRequest(m *jsonrpc.Message, yes, no bool, tty *bufio.Reader) *jsonrpc.Message {
	if m.Method != "session/request_permission" {
		if m.Method == "elicitation/create" || m.Method == "session/elicitation" {
			return jsonrpc.NewResult(m.ID, map[string]any{"action": "decline"})
		}
		return jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "Method not found", nil)
	}
	var p struct {
		ToolCall struct {
			Title string `json:"title"`
		} `json:"toolCall"`
		Options []struct {
			OptionID string `json:"optionId"`
			Name     string `json:"name"`
			Kind     string `json:"kind"`
		} `json:"options"`
	}
	_ = json.Unmarshal(m.Params, &p)
	pick := func(kind string) string {
		for _, o := range p.Options {
			if o.Kind == kind {
				return o.OptionID
			}
		}
		return ""
	}
	selected := func(id string) *jsonrpc.Message {
		if id == "" {
			return jsonrpc.NewResult(m.ID, map[string]any{"outcome": map[string]any{"outcome": "cancelled"}})
		}
		return jsonrpc.NewResult(m.ID, map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": id}})
	}
	switch {
	case yes:
		return selected(pick("allow_once"))
	case no:
		return selected(pick("reject_once"))
	}
	fmt.Fprintf(os.Stderr, "\n\033[33m? Allow: %s\033[0m\n", p.ToolCall.Title)
	for i, o := range p.Options {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, o.Name)
	}
	fmt.Fprint(os.Stderr, "Choose a number (Enter cancels): ")
	line, _ := tty.ReadString('\n')
	var n int
	if _, err := fmt.Sscan(strings.TrimSpace(line), &n); err == nil && n >= 1 && n <= len(p.Options) {
		return selected(p.Options[n-1].OptionID)
	}
	return selected("")
}

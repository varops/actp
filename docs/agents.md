# Agents

What is known about real ACP agents: how to start them, and how they behave in ways the ACP spec does not say. actp presets are built from this file.

Agents change between releases. Each entry should say which version it was checked against. Re-check anything marked as a quirk before relying on it.

## Presets

| Preset | Command | Notes |
| --- | --- | --- |
| `claude-code` | `claude-code-acp` | Zed's ACP adapter. Login with `claude /login`. |
| `codex` | `codex-acp` | |
| `gemini` | `gemini --acp` | `--experimental-acp` is deprecated. |
| `opencode` | `opencode acp` | Modes and models also appear as duplicate config options. |
| `droid` | `droid exec --output-format acp` | Needs `elicitation.form` from the client for its AskUser tool. |
| `grok` | `grok agent stdio` | Sends many `_x.ai/*` notifications. |
| `pi` | to be confirmed | |

## Quirks the server handles

From experience driving these agents over ACP:

- **Process folder.** Agents find their session store relative to the folder they run in. The server starts each agent in the link's default workspace, so `session/list` and `session/load` find the right sessions.
- **Ambient keys.** An API key in the server's environment can override an agent's own login. `env_remove` drops such variables for one agent.
- **Windows.** npm-installed agents are `.cmd` shims. Stopping the shim leaves the real agent running, so the server kills the whole process tree.
- **Startup failures.** An agent that exits or hangs during `initialize` must not block the link. The server races `initialize` against process exit and a timeout, and reports the exit code and stderr tail.
- **Errors.** Agents often wrap the real reason in `data.details` of a JSON-RPC "Internal error". actp forwards errors unchanged and uses `data.details` in its own messages and logs.
- **Unknown requests from the agent.** They carry an id and the agent waits for the reply. If nobody can answer one (for example while settling a link), the server replies `methodNotFound` instead of dropping it.
- **Request cancellation from the agent.** Some agents cancel an open question with `$/cancel_request` when a turn ends. This must reach the client so it can remove the prompt from its UI.
- **Late answers.** A permission answer can race a cancel. The server ignores answers for requests it already settled.

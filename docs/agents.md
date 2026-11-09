# Agents

What is known about real ACP agents: how to start them, and how they behave in ways the ACP spec does not say. actp presets are built from this file.

Agents change between releases. Each entry should say which version it was checked against. Re-check anything marked as a quirk before relying on it.

## Presets

"Verified" means the agent was checked over a live ACP handshake (November 2026). Capabilities are what the agent advertised, not what its vendor claims.

| Preset | Command | Verified | Capabilities and notes |
| --- | --- | --- | --- |
| `claude-code` | `claude-code-acp` (npm `@zed-industries/claude-code-acp`, or `node <pkg>/dist/index.js`) | yes | `loadSession`, list, resume, fork, HTTP and SSE MCP, images. Claude Code only speaks ACP through this adapter. Login rides on the user's Claude Code login (`claude /login`). |
| `codex` | `codex-acp` (Zed's adapter binary, built per platform) | yes | Full capability set. Plain `codex` does not speak ACP; use the adapter. Reasoning effort may need special handling. |
| `droid` | `droid exec --output-format acp` | yes | `loadSession`, list, resume, close, fork, images, embedded context, HTTP and SSE MCP, modes, ~49 models, config options. Needs `elicitation.form` from the client for its AskUser tool. Many quirks. |
| `gemini` | `gemini --acp` | yes | `loadSession`, HTTP and SSE MCP, image and audio prompts. Modes `default`, `autoEdit`, `yolo`, `plan`. Default model `auto`. `--experimental-acp` is deprecated. |
| `opencode` | `opencode acp` | yes | `loadSession`, fork, resume, close, HTTP and SSE MCP, images. Modes `build` and `plan`. Modes and models also appear as duplicate config options. |
| `grok` | `grok agent stdio` (a subcommand, not a flag) | yes | 12 models, `loadSession`, resume, close, HTTP and SSE MCP. No modes and no config options, so it cannot be steered mid-session. Sends many `_x.ai/*` notifications. |
| `prime-agent` | `prime-agent --mode acp` | no | Seen as a documented `--mode` value. Not checked over a live handshake. |

### Not available over ACP (yet)

- **Pi** (`pi`) – runs only as a terminal app. No ACP mode is known. It can be added as a preset once an ACP mode or adapter exists and passes a live handshake.
- **OMP**, **Mimo Code**, **Copilot** – terminal agents with no verified ACP launch.

A custom agent is any command that speaks ACP over stdio. Use `command` and `args` in the config instead of `preset`.

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

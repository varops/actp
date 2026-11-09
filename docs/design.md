# actp design

Status: draft 3 (2026-11-09)

`actp` (Agent Client Transport Protocol) is a tool that runs ACP agents on one machine and lets ACP clients use them from another. It is ACP over HTTP, packaged as one Go binary.

ACTP is a **tool, not a protocol standard**. Its promises are its public API (section 2) and its behaviour (section 3). How the bridge and the server talk to each other is internal (`docs/wire.md`) and will change when something better comes along, such as a stable official ACP web transport.

## 1. Roles

| Role | Command | What it is |
| --- | --- | --- |
| Server | `actp serve` | Runs ACP agents on this machine and serves them over the network. |
| Bridge | `actp <agent>@<server> [options]` | Looks like a local stdio ACP agent to any ACP client. Talks to a server on the other side. |
| Tray | `actp tray` | Desktop menu bar app (macOS, Windows, Linux) for the server, saved remotes and tunnels. |

```
 Any ACP client (app, bot, editor)
      │ spawns: actp claude@https://agents.example.com     ← plain ACP over stdio
      ▼
 actp bridge  ── internal wire (WebSocket over TLS) ──►  actp server  (agent machine)
                                                            │ plain ACP over stdio
                                                            ▼
                                                 Claude Code · Codex · Pi · ...
```

Both ends are plain ACP. No client and no agent needs to know actp exists.

## 2. Public API

These are the stable surfaces. Changes here follow semantic versioning: no breaking change without a major version.

### 2.1 ACP on both ends

- To clients, the bridge is an ACP agent over stdio.
- To agents, the server is an ACP client over stdio.
- ACP messages pass through unchanged, except for the rewrites in section 3.3.

### 2.2 Bridge command

```bash
actp claude@https://agents.example.com --token-env ACTP_TOKEN
```

In a client's agent config:

```json
{ "command": "actp", "args": ["claude@https://agents.example.com", "--token-env", "ACTP_TOKEN"] }
```

Server forms:

| Form | Meaning |
| --- | --- |
| `claude@https://agents.example.com` | Agent `claude` at that base URL. |
| `claude@agents.example.com` | Same, `https://` assumed. |
| `claude@localhost:7860` | `http://` assumed, loopback only. |
| `claude@workstation` | `workstation` is a saved remote (config or tray). |

`actp bridge <agent>@<server>` is the long form. The short form is any first argument with `@` that is not a subcommand.

Options:

| Option | Meaning |
| --- | --- |
| `--token-env NAME` | Token from env var `NAME`. |
| `--token-file PATH` | Token from a file. |
| (none) | `ACTP_TOKEN`, then the saved remote's token. |
| `--cwd VALUE` | Replace every `cwd` the client sends, for example `actp://website`. |
| `--map FROM=TO` | Rewrite `cwd` values starting with `FROM`. Repeatable. |
| `--name NAME` | Client name shown on the server. Default: hostname. |
| `--state-dir PATH` | Save link state so a restarted bridge can resume its session. |
| `--log-file PATH` | Debug log. stdout is ACP, so logs never go there. |

Tokens are never accepted as a plain argument, because command lines are visible to other users.

Exit codes: `0` when the client closed stdin, `1` on failure (reason on stderr).

### 2.3 Other CLI commands

```
actp serve
actp tray
actp token create --name N [--agents a,b] [--workspaces w]   prints the token once
actp token list | revoke <name>
actp remote add <name> <url> [--token-stdin]
actp remote list | remove <name>
actp agents <server>                     list agents on a server
actp doctor                              check agent commands, probe agents, check remotes
actp version
```

### 2.4 Configuration file

YAML at `~/.actp/actp.yaml` (Windows `%APPDATA%\actp\actp.yaml`), or `--config`. Every section is optional. The file has a `version: 1` key; old versions are migrated on load.

```yaml
version: 1

server:
  name: workstation
  listen: 127.0.0.1:7860
  grace_period: 10m
  replay_buffer: 8MB
  log_dir: ~/.actp/logs

  tunnel:
    provider: cloudflare
    mode: off                     # off | quick | named
    token_env: CF_TUNNEL_TOKEN    # named only

  workspaces:
    - name: website
      path: ~/code/website

  agents:
    - id: claude
      preset: claude-code         # fills in command and quirks (section 3.6)
      permissions: forward        # forward | auto_allow | auto_deny
      max_links: 4
    - id: codex
      preset: codex
    - id: my-agent
      name: My Agent
      command: my-agent
      args: [--acp]
      env: {}
      env_remove: [ANTHROPIC_API_KEY]   # drop ambient keys so the agent uses its own login

  tokens:
    - name: bot-vps
      hash: "sha256:9f2c..."
      agents: [claude, codex]     # "*" for all
      workspaces: [website]       # "*" for all
      default_workspace: website
      mcp_servers: remote         # none | remote | all
      max_links: 8
      map:
        /srv/bot/repo: website

# Saved remotes, for the bridge short form and the tray
remotes:
  - name: workstation
    url: https://agents.example.com
    token_env: ACTP_WORKSTATION_TOKEN   # or token_file, or keychain (tray)
```

### 2.5 Management endpoints

Served by `actp serve`, JSON, versioned by path.

| Endpoint | Auth | Returns |
| --- | --- | --- |
| `GET /health` | no | `{"ok": true}` |
| `GET /api/v1/info` | no | `name`, actp `version`, supported wire versions, `gracePeriodSeconds` |
| `GET /api/v1/agents` | token | Agents this token may use |

`/api/v1/agents` example:

```json
{
  "agents": [
    {
      "id": "claude",
      "name": "Claude Code",
      "status": "ready",
      "workspaces": [{ "name": "website", "default": true }],
      "agentInfo": { "name": "claude-code-acp", "version": "0.12.0" },
      "agentCapabilities": { "loadSession": true }
    }
  ]
}
```

`status` is `ready`, `auth_required` (with `authHint` from the agent's `authMethods[].description`, for example "Run `claude /login` on the agent host"), or `unavailable` (with `error`).

Auth everywhere: `Authorization: Bearer <token>`. Fields can be added at any time; clients ignore unknown fields.

## 3. Behaviour

These are promises to users, whatever the wire looks like.

### 3.1 Dropped connections

- A network drop does not end the agent's work. The agent keeps running on the server and its output is kept.
- The bridge reconnects in the background (backoff 0.5 s up to 15 s, with jitter) and catches up. The client sees a slow agent, nothing more.
- Requests from the agent to the client (permission prompts, questions) stay open while the bridge is away. The agent waits, as it would for a slow human.
- This lasts for the **grace period**: how long the server keeps the agent running after it loses contact with the bridge (default 10 min). It covers a laptop lid closing, Wi-Fi switching, or a tunnel restarting. If the bridge comes back in time, nothing is lost. If not, the server ends the link (3.2), so no agent waits forever for a client that is gone.
- If the session is lost, the bridge answers every request the client is waiting on with JSON-RPC error `-32000` and a message starting with `remote session lost:`, prints the reason to stderr, and exits 1. Clients that support ACP `session/load` can start a new agent and reload.
- When the client closes the bridge's stdin, the bridge ends the link at once. No grace period.

### 3.2 Ending a link cleanly

When the server ends a link with a live agent process, it settles the agent in this order:

1. Answer pending `session/request_permission` with `cancelled`.
2. Answer other pending agent requests: elicitations with `{"action": "cancel"}`, the rest with a JSON-RPC error.
3. Send `session/cancel` for every session with a running turn.
4. Send `session/close` for every open session, if the agent supports it.
5. Stop the process: SIGTERM, 2 s, SIGKILL. On Windows, kill the process tree.

Errors in steps 3 and 4 are ignored. The agent never waits forever.

### 3.3 Rewrites on the server

The server reads the ACP traffic and changes only these things.

**Files and terminals stay on the agent host.**

- In `initialize`, the server removes `clientCapabilities.fs` and `clientCapabilities.terminal`. The agent then reads files and runs commands itself, where its working folder is. Clients still see every tool call, command and output through normal `session/update` messages.
- If an agent sends `fs/*` or `terminal/*` anyway, the server answers `methodNotFound` and does not forward it.
- Every other client capability passes through, because they change agent behaviour (some agents only ask structured questions when `elicitation.form` is present).
- This matches where ACP is going: the ACP v2 draft removes the client file and terminal methods completely.

**Working folder (`cwd`).** A client's `cwd` is a path on the client machine and usually means nothing on the server. In `session/new`, `session/load`, `session/resume` and `session/list`, the server resolves it in this order:

1. `actp://<workspace>/<sub/path>` → that workspace's path plus the sub path (which may not leave the workspace).
2. An absolute path inside a workspace the token may use → unchanged.
3. The token's `map` table → mapped.
4. The token's `default_workspace` → used.
5. Otherwise → JSON-RPC `invalidParams` with `cwd not allowed: <path>`.

Paths are cleaned and symlinks resolved before the check. Responses carry the client's original `cwd` back.

**MCP servers.** A `stdio` entry in `mcpServers` would run a command on the server machine. Per token: `none`, `remote` (default: keep `http` and `sse`, drop `stdio`), or `all`. Dropped entries are logged.

**Permissions.** Per agent, overridable per token: `forward` (default), `auto_allow` (first `allow_once` option, else forward), `auto_deny` (first `reject_once`, else `cancelled`). Forwarded requests never time out; only the grace period ends them.

Everything else passes through untouched: ids, unknown methods and fields, extension methods (`elicitation/create`, `_x.ai/*`), and request cancellation in both directions. Message order is kept.

### 3.4 Probing

At start and on demand (`actp doctor`, tray), the server runs `initialize` without a session against each agent, with a 10 s timeout, then stops it. The result feeds `/api/v1/agents`. An "authentication required" error (code -32000 or matching message) sets `auth_required` with the agent's own hint.

### 3.5 Limits

Per agent and per token `max_links`. Over the limit, the bridge gets an error it prints as "server busy, try later".

### 3.6 Prompts during a turn

actp does not queue or reorder prompts. A `session/prompt` sent while a turn is running goes straight to the agent, and the agent decides what to do with it.

- **ACP v1:** one turn per session. Most agents reject a second prompt while one runs, so clients queue on their side.
- **ACP v2 (draft):** clients may send a prompt at any time. The agent either inserts it at once or holds it and inserts held prompts in order. Whether that **steers** the current turn or **queues** the next one is up to the agent. Explicit queue and steer capabilities are planned for a later ACP change.

Because actp passes prompts, cancellations and `$/cancel_request` through unchanged and in order, both styles work as soon as the agent supports them. When ACP adds explicit queue and steer options, they pass through too.

### 3.7 Agent presets and quirks

Each agent runs as a child process with its own login on the server machine. Presets fill in the command and known quirks so users do not have to.

| Preset | Command | Notes |
| --- | --- | --- |
| `claude-code` | `claude-code-acp` | Zed's ACP adapter. Login with `claude /login`. |
| `codex` | `codex-acp` | |
| `gemini` | `gemini --acp` | `--experimental-acp` is deprecated. |
| `opencode` | `opencode acp` | Modes and models also appear as duplicate config options. |
| `droid` | `droid exec --output-format acp` | Needs `elicitation.form` from the client for its AskUser tool. |
| `grok` | `grok agent stdio` | Sends many `_x.ai/*` notifications. |
| `pi` | to be confirmed | |

Quirks the server must handle, from experience driving these agents over ACP:

- **Process folder.** Agents find their session store relative to the folder they run in. The server starts each agent in the link's default workspace, so `session/list` and `session/load` find the right sessions.
- **Ambient keys.** An API key in the server's environment can override an agent's own login. `env_remove` drops such variables for one agent.
- **Windows.** npm-installed agents are `.cmd` shims. Stopping the shim leaves the real agent running, so the server kills the whole process tree.
- **Startup failures.** An agent that exits or hangs during `initialize` must not block the link. The server races `initialize` against process exit and a timeout, and reports the exit code and stderr tail.
- **Errors.** Agents often wrap the real reason in `data.details` of a JSON-RPC "Internal error". actp forwards errors unchanged and uses `data.details` in its own messages and logs.
- **Unknown requests from the agent.** They carry an id and the agent waits for the reply. If nobody can answer one (for example while settling a link), the server replies `methodNotFound` instead of dropping it.
- **Request cancellation from the agent.** Some agents cancel an open question with `$/cancel_request` when a turn ends. This must reach the client so it can remove the prompt from its UI.
- **Late answers.** A permission answer can race a cancel. The server ignores answers for requests it already settled.

## 4. Server internals

- One agent process per link.
- Keep the last 8 KB of each agent's stderr for error messages.
- Tokens: `actp_` + 32 random bytes in base32, stored as SHA-256 hashes, compared in constant time, shown once.
- Audit log (JSON lines): link opened, resumed, ended (with reason), session created, permission answered (by client or policy), cwd rejected. Prompts only with `audit.log_prompts = true`.
- Plain HTTP on loopback by default. A non-loopback `listen` needs `tls_cert` and `tls_key`, or `insecure_listen = true` behind a TLS proxy.
- Config reload on `SIGHUP` or from the tray. New links use the new config.

## 5. Tray

One app with a server section and a remotes section.

- **Server:** status and tunnel URL; agents with status dots and "Probe again"; active links (agent, client name, age, connected or "detached, 7 min left", "End"); tunnel off / quick / named, "Copy URL"; "Add client…" (creates a token and shows URL and token once).
- **Remotes:** saved remotes with status dots; "Add remote…" (URL and token, stored in the OS keychain); "Copy bridge command" for each agent.
- **Shared:** open config, open logs, start at login, quit.

`fyne.io/systray` for the menu. Input dialogs are small pages on loopback with a one-time token, so there is no native GUI toolkit to maintain.

### 5.1 Cloudflare tunnel

- `cloudflared` runs as a child process pointed at `listen`.
- `quick`: `cloudflared tunnel --url http://<listen>`. URL read from its output. Changes on restart. No account needed.
- `named`: `cloudflared tunnel run --token <token>`. Stable hostname, needs a Cloudflare account.
- Found on PATH or in `~/.actp/bin`. If missing, the tray offers to download the official release and checks its SHA-256.
- Restarted with backoff if it exits.

## 6. Security

- Agents run with the rights of the server's OS user. A token for an agent lets its holder make that agent do anything that user can. Workspaces set the starting point, not a sandbox. Issue tokens with that in mind.
- TLS off loopback. Tokens hashed at rest, shown once, never on a command line.
- File, terminal and `stdio` MCP rewrites stop clients from using ACP itself as a remote shell. They do not limit the agent.
- Link ids are secrets tied to a token. Resume checks both.

## 7. Room for later

- **Official ACP web transport** as an extra door on the server, so third-party clients connect without the bridge. Possibly also as the internal wire, once stable.
- **Go client package** for apps that want actp in-process instead of spawning the bridge. Public only once its API is settled.
- **Load balancing and failover** in the bridge: a saved remote can list several servers.
- **Server-to-server session sync**, so `session/load` works on another server.
- **Shared bridge daemon**, so links survive a client restart without `--state-dir`.

## 8. Code layout

Module `github.com/varops/actp`, Go 1.24+. Libraries: `github.com/coder/websocket`, `github.com/goccy/go-yaml`, `fyne.io/systray`. No ACP SDK: messages stay `json.RawMessage`, and only routed or rewritten fields are parsed, so unknown fields survive.

```
cmd/actp/            CLI entry
internal/wire/       envelope, seq/ack, replay buffer, version negotiation
internal/link/       link client: open, resume, reconnect
internal/jsonrpc/    ndjson framing, peek/patch helpers
internal/server/     routes, auth, links, rewrites, policy
internal/agentproc/  spawn, stderr tail, stop (POSIX + Windows)
internal/bridge/     stdio ↔ link client
internal/config/
internal/tunnel/
internal/tray/
testdata/agent/      scripted ACP agent
```

Everything is `internal/` until a public Go API is worth promising.

## 9. Testing

- **Scripted ACP agent** with scenarios `stream`, `permission`, `ask-user`, `cancel`, `resume`, `auth-required`, `needs-fs`, `crash`, `slow-start`, `late-commands`.
- **End to end:** a stdio ACP test client → bridge → server → scripted agent, on Linux, macOS and Windows in CI. These tests check the public API and the behaviour in section 3, not the wire.
- **Disconnect tests:** drop during a permission request, resume, answer, turn completes. Drop longer than the grace period → `remote session lost`.
- **Mixed versions:** current bridge against previous server and the other way round.
- **Real agents:** `claude-code-acp` and `codex-acp` smoke tests behind a build tag.

## 10. Milestones

1. **M1 – Relay.** Server with tokens, workspaces and rewrites; bridge with the URL form; management endpoints. A stdio client can use a remote Claude Code.
2. **M2 – Durable links.** Resume, grace period, lost-session handling, disconnect tests.
3. **M3 – Polish the CLI.** Saved remotes, `actp doctor`, `actp agents`, `--state-dir`, mixed-version tests.
4. **M4 – Tray and tunnel.** Tray, keychain, cloudflared.
5. **M5 – Release.** Signed builds, installers, docs site.

## 11. Open points

1. **Pi** – which command starts Pi in ACP mode?
2. **Default grace period** – 10 min.
3. **ACP v2** – when v2 ships, check that the rewrites in 3.3 and the settle order in 3.2 still match (for example, held prompts are answered with `-32800` on cancel).

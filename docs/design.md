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
| `--log-file PATH` | Debug log. stdout is ACP, so logs never go there. |

Tokens are never accepted as a plain argument, because command lines are visible to other users.

Exit codes: `0` when the client closed stdin (the link is detached, not stopped; see 3.1), `1` on failure (reason on stderr).

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
  idle_timeout: 24h               # how long a detached, idle agent is kept (section 3.1)
  spool_limit: 1GB                # disk space for output kept while detached
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
| `GET /api/v1/info` | no | `name`, actp `version`, supported wire versions, `idleTimeoutSeconds` |
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

**Rule: a dropped connection never interrupts the agent.** The server does not cancel a turn because the bridge went away. The agent finishes what it is doing, and the bridge reconnects when it can.

How a drop is noticed:

- **Clean drops** (the bridge process or the tunnel closes the socket) are seen at once.
- **Silent drops** (laptop sleeps, Wi-Fi changes, a NAT forgets the connection) send no signal, and server writes keep succeeding. So the bridge sends a heartbeat (an ack of what it has received) every 10 s. No heartbeat for 25 s → detached. The server also stops sending once too much is unacked (`docs/wire.md` 4.2).
- Either way, the server only marks the link **detached**. It does not touch the agent.

While detached:

- The agent keeps running. Its output is kept in memory and spilled to disk (`spool_limit`, default 1 GB), so long turns do not lose anything.
- A turn that does not need the client runs to the end, as normal.
- A turn that asks the client something (permission prompt, question) waits for the answer, as it would for a slow human.
- The bridge keeps trying to reconnect (backoff 0.5 s up to 30 s, with jitter) for as long as its own client is running.
- A session has exactly one client. A new connection for the same link replaces the old one. When it gets through, it catches up on everything it missed, including open prompts. The client sees a slow agent, nothing more.

When the server finally lets go:

- Only when the link has been detached **and idle** for `idle_timeout` (default 24 h). Idle means no turn running, or a turn waiting on the client.
- Then the server closes the link (3.2). An agent waiting on a permission prompt gets `cancelled`; that is the only time a drop leads to anything being cancelled, and only after a day with nobody there.
- The server also ends a link if the spool is full, the agent exits, or an admin ends it.

When the client quits:

A client closes the bridge's stdin both when the user stops an agent and when the app just quits, restarts or updates. actp cannot tell these apart, so it never treats a closed stdin as "stop".

- The bridge tells the server the client left, then exits. The server detaches the link, as for a drop.
- The agent finishes its turn. Then, once the link is idle (no turn running, nothing waiting on the client), the server closes the sessions and stops the agent (3.2). Nothing is cancelled, because nothing is running. The work is saved in the agent's own session store.
- A request waiting on the client (permission prompt, question) waits until `idle_timeout`, then gets `cancelled`.
- When the client starts again, it opens a new link and uses ACP `session/load` (or `session/resume`) to get the session back, including what the agent did while it was away.
- If it asks for a session that is still running on its old, detached link, the server answers `-32000` with `session still running on the agent host`, and the client can retry later. One client per session, always.

To really stop work, the client sends ACP `session/cancel` (stops the turn) or `session/close` (ends the session). These pass through as usual.

- If a link is gone when the bridge reconnects, the bridge answers every request its client is waiting on with JSON-RPC error `-32000` and a message starting with `remote session lost:`, prints the reason to stderr, and exits 1. Clients that support ACP `session/load` can start a new agent and reload.

### 3.2 Ending a link cleanly

When the server ends a link with a live agent process, it settles the agent in this order:

1. Answer pending `session/request_permission` with `cancelled`.
2. Answer other pending agent requests: elicitations with `{"action": "cancel"}`, the rest with a JSON-RPC error.
3. Send `session/cancel` for every session with a running turn.
4. Send `session/close` for every open session, if the agent supports it.
5. Stop the process: SIGTERM, 2 s, SIGKILL. On Windows, kill the process tree.

Errors in steps 3 and 4 are ignored. The agent never waits forever.

This runs only when a link ends (3.1): never just because a connection dropped.

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

**Permissions.** Per agent, overridable per token: `forward` (default), `auto_allow` (first `allow_once` option, else forward), `auto_deny` (first `reject_once`, else `cancelled`). Forwarded requests never time out; only the idle timeout ends them (3.1).

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

Clients can already offer both on ACP v1, on their own side, with plain ACP calls:

- **Queue** – hold the prompt and send it when the current `session/prompt` returns. Pause the queue if a turn fails or the user stops it.
- **Steer** ("send now") – send `session/cancel`, wait for the running prompt to return with `stopReason: cancelled`, then send the new prompt as the very next message.

Both work through actp unchanged: actp keeps message order on a link, and each link has one client, so nothing can slip in between the cancel and the new prompt. actp does not need its own queue.

### 3.7 Agent presets and quirks

Each agent runs as a child process with its own login on the server machine. `preset` in the config fills in the command and known quirks. The list of presets and everything known about how real agents behave over ACP lives in `docs/agents.md`, so it can grow on its own.

## 4. Server internals

- One agent process per link.
- Keep the last 8 KB of each agent's stderr for error messages.
- Tokens: `actp_` + 32 random bytes in base32, stored as SHA-256 hashes, compared in constant time, shown once.
- Audit log (JSON lines): link opened, resumed, ended (with reason), session created, permission answered (by client or policy), cwd rejected. Prompts only with `audit.log_prompts = true`.
- Plain HTTP on loopback by default. A non-loopback `listen` needs `tls_cert` and `tls_key`, or `insecure_listen = true` behind a TLS proxy.
- Config reload on `SIGHUP` or from the tray. New links use the new config.
- **Restart and upgrade.** Agents are child processes of `actp serve`, so stopping the server stops them. `actp serve` refuses to stop or restart while any turn is running, unless `--force` is given. It waits for running turns when asked to stop gracefully. After a restart, clients get `remote session lost` and reload with ACP `session/load`.

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

- Agents run with the rights of the server's OS user. A token for an agent lets its holder make that agent do anything that user can. Workspaces set the starting point, not a sandbox.
- **v1 is for trusted clients only.** All tokens share the same OS user, the same agent logins, and the same files outside the workspaces. Give tokens only to clients you would give a shell on that machine. The docs and the tray's "Add client" dialog say this plainly.
- TLS off loopback. Tokens hashed at rest, shown once, never on a command line.
- File, terminal and `stdio` MCP rewrites stop clients from using ACP itself as a remote shell. They do not limit the agent.
- Link ids are secrets tied to a token. Resume checks both.

## 7. Room for later

- **Official ACP web transport** as an extra door on the server, so third-party clients connect without the bridge. Possibly also as the internal wire, once stable.
- **Go client package** for apps that want actp in-process instead of spawning the bridge. Public only once its API is settled.
- **Load balancing and failover** in the bridge: a saved remote can list several servers.
- **Server-to-server session sync**, so `session/load` works on another server.
- **Live reattach after a client restart**, so a returning client takes over a session that is still running instead of waiting for it to finish.
- **Agent host process** separate from `actp serve`, so agents survive a server upgrade.
- **Stable public address.** Quick tunnels change URL on every restart; named tunnels need a Cloudflare account. A hosted relay with stable names could fix this.
- **Per-client isolation**: a separate OS user or container per token, for shared family or business setups.
- **Per-client limits** beyond agents and workspaces: forced modes, allowed models, spending caps.

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
- **Client quit tests:** client closes stdin mid-turn → turn finishes, session closes, `session/load` on a new link shows the finished turn. Load while still running → `session still running`.
- **Disconnect tests:** drop during a permission request, resume, answer, turn completes. Drop during a long turn: the turn finishes while detached and the bridge receives all of it on resume. Link idle past `idle_timeout` → `remote session lost`.
- **Mixed versions:** current bridge against previous server and the other way round.
- **Real agents:** `claude-code-acp` and `codex-acp` smoke tests behind a build tag.

## 10. Milestones

1. **M1 – Relay.** Server with tokens, workspaces and rewrites; bridge with the URL form; management endpoints. A stdio client can use a remote Claude Code.
2. **M2 – Durable links.** Resume, disk spool, idle timeout, lost-session handling, disconnect tests.
3. **M3 – Polish the CLI.** Saved remotes, `actp doctor`, `actp agents`, mixed-version tests.
4. **M4 – Tray and tunnel.** Tray, keychain, cloudflared.
5. **M5 – Release.** Signed builds, installers, docs site.

## 11. Open points

1. **Pi** – no ACP mode is known yet (`docs/agents.md`). Add a preset once one exists.
2. **ACP v2** – when v2 ships, check that the rewrites in 3.3 and the settle order in 3.2 still match (for example, held prompts are answered with `-32800` on cancel).

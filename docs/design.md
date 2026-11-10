# actp design

Status: draft 5 (2026-11-10). Section 12 lists what the code does today.

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

### 1.1 Scope of v1: chat-style clients

actp moves the agent to another machine, and **the files move with it**. The agent reads, edits and runs code on the agent host. v1 is built for clients that talk to an agent and show what it does: chat apps, bots, assistants, automations.

Clients that also work on the files themselves (an IDE showing its own file tree, diffs or git status) will see their local disk, not the one the agent works on. Known limits for those clients in v1:

- File paths in tool calls and diffs are paths on the agent host. The client cannot open them locally.
- File links in prompts (`resource_link` with a client path) do not resolve on the agent host. Embedded content (text, images sent inline) works.
- Client features that read the agent's local files, such as session history folders, see nothing.
- "Log in through a terminal" flows offered by an agent would run on the client machine. Logins must be done on the agent host.

Making IDE-style clients work (shared checkouts, path mapping, file access through the link) is out of scope for v1.

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
actp token create --name N [--agents a,b] [--workspaces w] [--default-workspace w]   prints the token once
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
  idle_close: 10m                 # close a detached link with nothing running (section 3.1)
  prompt_timeout: 24h             # how long an unanswered prompt waits for a dropped client
  spool_limit: 1GB                # disk space for output kept while detached
  log_dir: ~/.actp/logs
  state_dir: ~/.actp/state        # agent process ids, for cleanup after a crash
  tokens_file: ~/.actp/tokens.yaml  # tokens managed by `actp token`
  shell_env: true                 # start agents with the login shell's environment

  tunnel:
    provider: cloudflare
    mode: off                     # off | quick | named
    token_env: CF_TUNNEL_TOKEN    # named only

  workspaces:
    - name: website
      path: ~/code/website

  agents:
    - id: claude
      preset: claude-code         # fills in command and quirks (section 3.8)
      permissions: forward        # forward | auto_allow | auto_deny
      max_links: 16
      on_client_exit: finish      # finish | cancel (section 3.1)
      max_unattended: 1h          # longest a turn may run after its client left
    - id: codex
      preset: codex
    - id: my-agent
      name: My Agent
      command: my-agent
      args: [--acp]
      env: {}
      env_remove: [ANTHROPIC_API_KEY]   # drop ambient keys so the agent uses its own login

  tokens:                         # hand-written tokens; `actp token` writes to tokens_file instead
    - name: bot-vps
      hash: "sha256:9f2c..."
      agents: [claude, codex]     # "*" for all
      workspaces: [website]       # "*" for all
      default_workspace: website
      cwd_fallback: false         # true: unknown folders silently use default_workspace
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
| `GET /api/v1/info` | token | `name`, actp `version`, supported wire versions, `promptTimeoutSeconds` |
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
      "agentInfo": { "name": "claude-agent-acp", "version": "0.102.0" },
      "agentCapabilities": { "loadSession": true }
    }
  ]
}
```

`status` is `ready`, `auth_required` (with `authHint` from the agent's `authMethods[].description`, for example "Run `claude /login` on the agent host"), or `unavailable` (with `error`).

Auth: `Authorization: Bearer <token>` on everything except `/health`. There is no exception for local connections: a tunnel or reverse proxy on the same machine makes all internet traffic look local. Fields can be added at any time; clients ignore unknown fields.

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
- The bridge keeps trying to reconnect (backoff 0.5 s up to 30 s, with jitter). When it gets through, it catches up on everything it missed, including open prompts. The client sees a slow agent, nothing more.
- A session has exactly one client. A new connection for the same link replaces the old one.
- If the bridge cannot reach the server for 10 minutes of awake time (sleep does not count), it stops trying: it answers its client's open requests with `-32000 remote session lost: server unreachable`, prints the reason to stderr and exits 1. The client is not left with an endless spinner. Work on the server is not lost; see "Getting a session back".

A link is in one of three states:

| State | Meaning | What the server does |
| --- | --- | --- |
| **Attached** | Bridge connected. | Normal. |
| **Detached** | Connection dropped. The bridge may come back. | Agent keeps running. Output is kept. Prompts wait. |
| **Unattended** | The client has left. Nobody will come back to this link. | Agent finishes its turn. Output is dropped. Prompts are cancelled. Then the link closes. |

When a detached link is closed:

- **Nothing running and nothing waiting** for `idle_close` (default 10 min) → the server closes the link (3.2). Nothing is lost: the session is in the agent's own store and the client can load it again. Closing early matters, because every open link holds an agent process and counts against `max_links`.
- **A turn waiting on the client** (permission prompt, question) for `prompt_timeout` (default 24 h) → the prompt gets `cancelled` and the link closes.
- **A turn running** → never closed for being detached.
- Also when the spool is full, the agent exits, or an admin ends it.

When the client quits:

A client closes the bridge's stdin both when the user stops an agent and when the app quits, restarts or updates. Many clients also just kill the process. actp cannot tell these apart.

- On a closed stdin or a termination signal, the bridge tells the server the client left, then exits. The link becomes **unattended**.
- By default (`on_client_exit: finish`) the agent finishes its turn. With `on_client_exit: cancel`, the server cancels the turn at once, for users who expect "close" to mean "stop".
- A prompt for the client (permission, question) is answered `cancelled` at once, now and for the rest of the turn. Nobody is there to answer, and waiting would lock the session.
- A turn may run unattended for at most `max_unattended` (default 1 h). Then the server cancels it. An agent nobody is watching does not run forever.
- When the turn ends, the server closes the sessions and stops the agent (3.2). The work is saved in the agent's own session store.
- The tray lists unattended links with an "End" button.
- If the bridge is killed hard and cannot say goodbye, the link is only detached. The rules above for detached links then apply, and "Getting a session back" covers the rest.

To stop work for certain, the client sends ACP `session/cancel` (stops the turn) or `session/close` (ends the session) before it goes. These pass through as usual.

Getting a session back:

- The client opens a new link and uses ACP `session/load` (or `session/resume`). It gets the session including what the agent did while it was away. This needs an agent that supports loading sessions; all presets do.
- If that session is still live on an older link of the same token, the server marks the old link unattended (the client has clearly moved on), which cancels any waiting prompt. Until the old turn has ended, the new request gets `-32000` with `session still running on the agent host`, and the client retries.
- If a link is gone when a bridge reconnects, the bridge answers every request its client is waiting on with `-32000` and a message starting with `remote session lost:`, prints the reason to stderr, and exits 1.

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
4. Only if the token has `cwd_fallback: true`: the token's `default_workspace`. Off by default, because a silent fallback can send two different client projects into the same folder.
5. Otherwise → JSON-RPC `invalidParams` with `cwd not allowed: <path>`.

Paths are cleaned and symlinks resolved before the check. Responses carry the client's original `cwd` back.

**MCP servers.** A `stdio` entry in `mcpServers` would run a command on the server machine. Per token: `none`, `remote` (default: keep `http` and `sse`, drop `stdio`), or `all`. Entries whose URL points at `localhost` or a loopback address are dropped as well: they meant the client's machine, not the agent host. Dropped entries are logged.

**Permissions.** Per agent, overridable per token: `forward` (default), `auto_allow` (first `allow_once` option, else forward), `auto_deny` (first `reject_once`, else `cancelled`). Forwarded requests never time out while a client is attached; `prompt_timeout` and the unattended rules end them (3.1).

**Login hints.** In the `initialize` response, the server removes terminal-login metadata from `authMethods` (for example `_meta.terminal-auth`), because the client would run that login on its own machine. Descriptions stay, so the user still sees what to do on the agent host.

**Requests the server sends itself** (for example `session/close` when a link ends) use ids in their own namespace (`actp-1`, `actp-2`, ...), so they cannot clash with the client's ids. Their replies are not forwarded.

Everything else passes through untouched: ids, unknown methods and fields, extension methods (`elicitation/create`, `_x.ai/*`), and request cancellation in both directions. Message order is kept.

### 3.4 Probing

At start and on demand (`actp doctor`, tray), the server runs `initialize` without a session against each agent, with a 10 s timeout, then stops it. The result feeds `/api/v1/agents`. An "authentication required" error (code -32000 or matching message) sets `auth_required` with the agent's own hint.

The probe is only a first guess. Most agents pass `initialize` and report a missing login on the first `session/new` or `session/prompt`. So the server also watches real traffic: an authentication error on a link sets `auth_required`, and a successful session sets `ready`.

### 3.5 Limits

Per agent and per token `max_links`. Over the limit, the bridge gets an error it prints as "server busy, try later".

### 3.6 Prompts during a turn

actp does not queue or reorder prompts. A `session/prompt` sent while a turn is running goes straight to the agent, and the agent decides what to do with it.

- **ACP v1:** one turn per session. Most agents reject a second prompt while one runs, so clients queue on their side.
- **ACP v2 (draft):** clients may send a prompt at any time. The agent either inserts it at once or holds it and inserts held prompts in order. Whether that **steers** the current turn or **queues** the next one is up to the agent. Explicit queue and steer capabilities are planned for a later ACP change.

Because actp passes prompts, cancellations and `$/cancel_request` through unchanged and in order, both styles work as soon as the agent supports them. When ACP adds explicit queue and steer options, they pass through too.

Some agents already queue on their own: Claude's adapter advertises `_meta.claudeCode.promptQueueing: true`. actp passes that through like any other capability.

Clients can already offer both on ACP v1, on their own side, with plain ACP calls:

- **Queue** – hold the prompt and send it when the current `session/prompt` returns. Pause the queue if a turn fails or the user stops it.
- **Steer** ("send now") – send `session/cancel`, wait for the running prompt to return with `stopReason: cancelled`, then send the new prompt as the very next message.

Both work through actp unchanged: actp keeps message order on a link, and each link has one client, so nothing can slip in between the cancel and the new prompt. actp does not need its own queue.

### 3.7 Knowing when a turn is running

The rules in 3.1 need to know whether a session has a turn running. The server works this out from the traffic, and how depends on the ACP version agreed in `initialize`:

- **ACP v1:** a turn runs from a `session/prompt` request until its response.
- **ACP v2 (draft):** the prompt response only confirms the message was accepted. The server follows the session status updates instead.
- **Unknown version:** the server assumes a turn is running whenever it has seen agent output in the last few minutes, and never cancels on a guess.

### 3.8 Agent presets and quirks

Each agent runs as a child process with its own login on the server machine. `preset` in the config fills in the command and known quirks. The list of presets and everything known about how real agents behave over ACP lives in `docs/agents.md`, so it can grow on its own.

## 4. Server internals

- One agent process per link.
- Keep the last 8 KB of each agent's stderr for error messages.
- Tokens: `actp_` + 32 random bytes in base32, stored as SHA-256 hashes, compared in constant time, shown once. `actp token` keeps its tokens in a separate `tokens_file` (mode 0600), so it never rewrites the hand-edited config. Both sources are loaded.
- Audit log (JSON lines): link opened, resumed, ended (with reason), session created, permission answered (by client or policy), cwd rejected. Prompts only with `audit.log_prompts: true`.
- **Environment.** Desktop apps and system services start with a minimal PATH, so agent commands are often not found. At start the server reads the user's login-shell environment (as editors do) and uses it for agents. `actp doctor` shows the PATH agents will get.
- **Process groups.** Each agent runs in its own process group (Windows: job object), so stopping it stops its children. The server records agent process ids, and on start it stops any left over from a crash.
- **Spool files** hold agent output, which can include code and secrets. They are readable only by the server's user, deleted when the link ends, and purged at start.
- Plain HTTP on loopback by default. A non-loopback `listen` needs `tls_cert` and `tls_key`, or `insecure_listen: true` behind a TLS proxy.
- Config reload on `SIGHUP` or from the tray. New links use the new config.
- **Restart and upgrade.** Agents are child processes of `actp serve`, so stopping the server stops them. A restart that actp starts itself (tray menu, upgrade) is refused while any turn is running, unless forced. On a stop signal from the system, the server waits up to 30 s for turns, then settles the links (3.2). After a restart, clients get `remote session lost` and reload with ACP `session/load`.

## 5. Tray

One app with a server section and a remotes section.

- **Server:** status and tunnel URL; agents with status dots and "Probe again"; active links (agent, client name, age, connected or "detached, 7 min left", "End"); tunnel off / quick / named, "Copy URL"; "Add client…" (creates a token and shows URL and token once).
- **Remotes:** saved remotes with status dots; "Add remote…" (URL and token, stored in the OS keychain); "Copy bridge command" for each agent.
- **Shared:** open config, open logs, start at login, quit.

`fyne.io/systray` for the menu. The tray needs native code on macOS, so desktop builds are made per platform, and the tray sits behind a build tag: server and CI builds stay pure Go. On Linux desktops without a tray area (stock GNOME), `actp tray` opens the same local page instead. Input dialogs are small pages on loopback with a one-time token, so there is no native GUI toolkit to maintain.

### 5.1 Cloudflare tunnel

- `cloudflared` runs as a child process pointed at `listen`.
- `quick`: `cloudflared tunnel --url http://<listen>`. URL read from its output. Changes on restart. No account needed.
- `named`: `cloudflared tunnel run --token <token>`. Stable hostname, needs a Cloudflare account.
- Found on PATH or in `~/.actp/bin`. If missing, the tray offers to download one fixed `cloudflared` version. Its SHA-256 is built into the actp release, not fetched with the download.
- Restarted with backoff if it exits.

## 6. Security

- Agents run with the rights of the server's OS user. A token for an agent lets its holder make that agent do anything that user can. Workspaces set the starting point, not a sandbox.
- **v1 is for trusted clients only.** All tokens share the same OS user, the same agent logins, and the same files outside the workspaces. Give tokens only to clients you would give a shell on that machine. The docs and the tray's "Add client" dialog say this plainly.
- A token is always required. There is no "local connections are trusted" rule, because tunnels and proxies make remote traffic look local.
- TLS off loopback. Tokens hashed at rest, shown once, never on a command line.
- The tray's local pages check the `Host` header and a one-time token, so other websites cannot drive them.
- File, terminal and `stdio` MCP rewrites stop clients from using ACP itself as a remote shell. They do not limit the agent.
- Link ids are secrets tied to a token. Resume checks both.

## 7. Room for later

- **Official ACP web transport** as an extra door on the server, so third-party clients connect without the bridge. Possibly also as the internal wire, once stable.
- **Go client package** for apps that want actp in-process instead of spawning the bridge. Public only once its API is settled.
- **Load balancing and failover** in the bridge: a saved remote can list several servers.
- **Server-to-server session sync**, so `session/load` works on another server.
- **Live reattach after a client restart**, so a returning client takes over a session that is still running instead of waiting for it to finish.
- **Agent host process** separate from `actp serve`, so agents survive a server upgrade.
- **IDE-style clients** (1.1): path mapping, file access through the link, client-side MCP servers reachable from the agent.
- **Seamless recovery in the bridge**: when a link was closed while the client slept, reopen and reload the session without the client noticing.
- **Stable public address.** Quick tunnels change URL on every restart; named tunnels need a Cloudflare account. A hosted relay with stable names could fix this.
- **Per-client isolation**: a separate OS user or container per token, for shared family or business setups.
- **Per-client limits** beyond agents and workspaces: forced modes, allowed models, spending caps.

## 8. Code layout

Module `github.com/varops/actp`, Go 1.25+. Libraries: `github.com/coder/websocket`, `github.com/goccy/go-yaml`, `fyne.io/systray`. No ACP SDK: messages stay `json.RawMessage`, and only routed or rewritten fields are parsed, so unknown fields survive.

```
api/                 openapi.yaml and the code generated from it (go generate ./api/)
cmd/actp/            CLI: serve, bridge, token, agents, doctor, version
cmd/actp-testagent/  scripted ACP agent for tests
internal/config/     YAML config, presets, tokens
internal/jsonrpc/    ndjson framing, peek/patch helpers
internal/wire/       envelope, seq/ack, heartbeat, send window, replay
internal/server/     HTTP API, auth, links and their states, rewrites, probing, audit
internal/bridge/     stdio ↔ link, reconnect, bye, lost-session handling
internal/agentproc/  spawn, environment, stderr tail, process groups (POSIX + Windows)
internal/testagent/  the scripted agent's logic
internal/e2e/        end-to-end tests: stdio client → bridge → server → scripted agent
internal/tunnel/     (planned) cloudflared manager
internal/tray/       (planned) tray app
```

The OpenAPI file is the source of truth for the HTTP API. CI fails if the generated code is stale.

Everything is `internal/` until a public Go API is worth promising.

## 9. Testing

- **Scripted ACP agent** with scenarios `stream`, `permission`, `ask-user`, `cancel`, `resume`, `auth-required`, `needs-fs`, `crash`, `slow-start`, `late-commands`.
- **End to end:** a stdio ACP test client → bridge → server → scripted agent, on Linux, macOS and Windows in CI. These tests check the public API and the behaviour in section 3, not the wire.
- **Client quit tests:** client closes stdin mid-turn → turn finishes, session closes, `session/load` on a new link shows the finished turn. Load while still running → `session still running`. Permission asked while unattended → cancelled at once. `on_client_exit: cancel` and `max_unattended` → turn cancelled. Bridge killed hard, then a new link loads the session → old link becomes unattended.
- **Auth tests:** every endpoint except `/health` rejects a missing token, also from loopback.
- **Disconnect tests:** drop during a permission request, resume, answer, turn completes. Drop during a long turn: the turn finishes while detached and the bridge receives all of it on resume. Detached with nothing running past `idle_close` → link closed, later `session/load` works. Prompt unanswered past `prompt_timeout` → cancelled.
- **Mixed versions:** current bridge against previous server and the other way round.
- **Real agents:** `claude-agent-acp` and `codex-acp` smoke tests behind a build tag.

## 10. Milestones

0. **M0 – Spike (about a day).** Check the riskiest assumptions with real agents before building: WebSockets and large messages through a quick tunnel; whether agents exit when stdin closes; whether `session/load` returns a turn that finished with nobody connected; what each agent does when a permission is cancelled.
1. **M1 – Relay.** Server with tokens, workspaces and rewrites; bridge with the URL form; management endpoints. A stdio client can use a remote Claude Code.
2. **M2 – Durable links.** Resume, disk spool, link states and timers (3.1), turn tracking (3.7), lost-session handling, disconnect and client-quit tests.
3. **M3 – Polish the CLI.** Saved remotes, `actp doctor`, `actp agents`, mixed-version tests.
4. **M4 – Tray and tunnel.** Tray, keychain, cloudflared.
5. **M5 – Release.** Signed builds, installers, docs site.

## 11. Open points

1. **Pi** – preset uses the community `pi-acp` adapter. Verify it over a live handshake before release.
2. **ACP v2** – when v2 ships, check that the rewrites in 3.3 and the settle order in 3.2 still match (for example, held prompts are answered with `-32800` on cancel).

## 12. Implementation status

What the code does today (M1 done, most of M2):

- **Done:** server, bridge (`actp <agent>@<server>`), `token`, `agents`, `doctor`, `version`. Token auth with no local exception. Management endpoints. Wire format with acks, heartbeats, send window, resume and `bye`. Link states (attached, detached, unattended) with `idle_close`, `prompt_timeout`, `max_unattended` and `on_client_exit`. Settle order on link end. Rewrites: fs/terminal stripping, cwd resolution (`actp://`, workspace paths, `map`, opt-in fallback), MCP filtering, permission policies, terminal-auth hints. Session takeover on `session/load`. Replay buffer spilled to a private spool file. Config reload on `SIGHUP` (a revoked token cannot open or resume links; open links run on until they drop). Probing and login status from traffic. Audit log. Agent process groups and cleanup after a crash. Login-shell environment for agents. CI on Linux, macOS and Windows.
- **Not yet:** turn tracking for ACP v2 beyond the "recent output" rule, saved-remote commands (`actp remote ...`; edit `remotes:` in the config for now), tray, tunnel, release builds.
- **Real agents, partly (M0):** Claude and OpenCode adapters pass `initialize`, `session/new`, updates and extension notifications through actp, and exit cleanly when stdin closes (`docs/agents.md`). Not yet checked: real prompts, a drop mid-turn, `session/load` after an unattended turn, cancelled permissions, and anything through a tunnel.

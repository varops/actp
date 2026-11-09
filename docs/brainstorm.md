# ACTP brainstorm

ACTP is ACP over HTTP. It is a small gateway that runs next to local ACP agents (Claude Code, Codex, Droid, Pi, ...) and exposes them to remote ACP clients over HTTPS or WebSocket.

This is the brainstorm stage. It lists ideas, options and open questions. The spec comes next and will pick one option per question.

## Goal in one line

Point any ACP client at `https://my-box/acp/claude` and get a real Claude Code session running on that box – with auth, safe defaults, and sessions that survive a dropped connection.

## Why it matters

- **Distributed agents** – agents stay on a strong workstation, the client app runs on a small VPS.
- **Personal agents** – an assistant on your Mac joins a family or business space.
- **Own infrastructure** – organizations connect agents from machines they already own.
- **Portable** – any ACP client can talk to remote agents, no special install needed.

## What already exists

The ACP Python SDK ships an experimental remote transport (based on the transport RFD). ACTP should speak it exactly, so standard clients work out of the box.

| Profile | Shape |
| --- | --- |
| Streamable HTTP | `POST` for client→agent messages. `initialize` returns `200` with JSON, every other POST returns `202`. Server→client messages go out on long-lived SSE `GET` streams: one per connection, one per session. `DELETE` ends the connection. Requires HTTP/2. |
| WebSocket | `GET` upgrade on the same path. One JSON-RPC message per text frame. Binary frames are ignored. |

Identity: `Acp-Connection-Id` (header, returned by `initialize`), `Acp-Session-Id` (header on session-scoped requests and streams), and `sessionId` inside the JSON-RPC payload.

Routing rules for HTTP: the `initialize` response goes in the POST body. Responses with a new `sessionId`, plus `session/load` replay and `session/resume` responses, go on the connection stream. Everything else goes on the session stream when known.

Not in the RFD yet: `Last-Event-ID` resume, sequencing, client auto-reconnect, batch requests, `Acp-Protocol-Version` enforcement. **These gaps are where ACTP adds the most value.**

## The core idea

```
ACP client (any app, editor or SDK)
        │  HTTPS / WSS + auth
        ▼
ACTP gateway  ── auth · routing · session lifecycle · buffering · policy
        │  stdio (ndjson)
        ▼
Local agent processes (claude-code-acp, codex-acp, droid exec, pi, ...)
```

The gateway is mostly a smart relay. It does not need to understand every ACP message. It must understand a few: `initialize`, `session/new|load|resume|close`, `session/prompt`, `session/cancel`, and agent→client requests (to hold and cancel them).

## Key insight: "client callbacks" change meaning when the client is remote

In ACP, `fs/*` and `terminal/*` are requests from the agent **to the client**. Over stdio that is fine – client and agent share a machine. Over ACTP they do not. If a client on a VPS answers `fs/read_text_file`, it reads the VPS disk, not the workstation where the agent works. Same for `cwd`: it must be a path on the agent host.

Options:

1. **Gateway handles fs and terminals locally** (on the agent host), and does not forward them. The gateway advertises these capabilities itself. Safest default for "remote agent".
2. **Forward to the client.** Only correct when the client really owns the files (rare, but valid for "agent as a service" over a client's own workspace).
3. **Advertise nothing.** Most CLIs (Claude Code, Codex, Droid) use their own built-in tools anyway.

Proposal: per-agent setting `client_callbacks: local | forward | none`, default `local` with path limits to allowed workspaces.

Related:

- **cwd** – validate against an allowlist of workspaces in config. Optionally let clients use a workspace alias (`cwd: "@my-repo"`) that the gateway maps to a real path.
- **mcpServers** – a stdio MCP server in `session/new` means "run this command on the agent host". That is remote code execution. Default: strip stdio MCP servers, allow HTTP/SSE ones, or allow none.

## Sessions that outlive connections

The reference doc says a human may take minutes to answer a permission prompt, and an agent blocks until someone answers. Networks drop. So:

- **Detach, don't kill.** When the client disconnects, keep the agent process and session alive for a grace period (for example 10 min, configurable).
- **Event log per session.** Number every outgoing message (`id:` in SSE). On reconnect, the client sends `Last-Event-ID` and gets what it missed. On WebSocket, an ACTP extension does the same (`_actp/resume` with a sequence number).
- **Pending agent requests** (permissions, elicitations) stay open on the gateway. A reconnecting client gets them again.
- **After grace period** – cancel pending requests, send `session/cancel`, close the session, stop the process.
- **One turn at a time** – optional server-side prompt queue.

This is an extension to the RFD. A plain RFD client still works; it just does not get resume.

## Process model

| Option | Pros | Cons |
| --- | --- | --- |
| One agent process per connection (the SDK default) | Simple, isolated | Reconnect means a new process; detached sessions are hard |
| One process per session | Detach and resume is easy; matches "session = unit of work" | Many processes |
| One shared process per agent, many sessions | Cheap, matches how Droid works (`multi-session`) | One crash kills all sessions; harder to isolate users |

Leaning: **process per connection on the agent side, but owned by the gateway, not by the HTTP connection.** A "gateway connection" can be re-attached by a new HTTP connection. Configurable `max_processes` per agent.

## Auth

- **Bearer tokens** in config (hashed). Each token has a name and a list of agents it may use. Simple and works with every client (`Authorization: Bearer ...`).
- **Pairing flow** for the desktop app: "Add client" shows a one-time code / QR, the client exchanges it for a token.
- **Cloudflare Access** in front of the tunnel as an optional second layer (service tokens).
- **mTLS** – later, for orgs.
- No auth → only allowed on `127.0.0.1`.

## Discovery

The RFD serves one agent per endpoint. ACTP hosts several. Proposal:

- `/acp/{agent}` – standard ACP endpoint per agent. Any RFD client just uses this URL.
- `GET /agents` – ACTP extension: list agents the token may use, with name, description, and cached capabilities.
- `GET /health` – liveness for tunnels and monitoring.

## Policy layer (optional, per agent and per token)

- Permission policy: `forward` (default), `auto_allow`, `auto_deny`, `allow_reads_only`.
- Mode lock: force a mode (for example Droid `spec`, or never `auto-high`).
- Capability narrowing: hide `terminal` or `elicitation` from the agent.
- Rate limits and max concurrent sessions.
- Audit log: who started which session, prompts, permission answers.

## Packaging

The ask: one executable, one config file, plus a menu bar app for macOS, Windows and Linux that can open a Cloudflare tunnel for people without a server.

### Language

| Option | Fit |
| --- | --- |
| **Go** | Single static binary, easy cross-compile, good HTTP/2, SSE and WebSocket. Tray via `fyne.io/systray`. cloudflared is Go too. No official ACP SDK, but the gateway only needs JSON-RPC framing. |
| Rust | Single binary, official ACP Rust crate. Tray via Tauri or `tray-icon`. Slower to build and iterate. |
| TypeScript (Node/Bun) | Official SDK. `bun build --compile` gives a binary, but it is large, and tray support is weak. |
| Python | Reuse the SDK's ASGI server directly. Packaging a single binary plus tray is painful. |

Leaning: **Go.** The gateway is a relay, not an agent, so the SDK matters less than a small, boring binary.

### Shape

- `actp serve` – headless daemon. Reads `actp.toml` (or YAML). For servers and Docker.
- `actp tray` (or `ACTP.app`) – same binary, starts the daemon plus a tray icon.
- `actp token add|list|revoke`, `actp agents`, `actp doctor` (checks agent CLIs on PATH and does an `initialize` probe).

### Tray menu (first version)

- Status: running / tunnel up / N active sessions
- Agents: list with a green/red dot (probe result)
- Active sessions: agent, client name, started, "stop"
- Pending permissions: notification + approve/deny from the tray? (nice, maybe later)
- Tunnel: on/off, copy public URL
- Add client: show URL + token (or QR)
- Open config, open logs, quit

### Cloudflare tunnels

| Option | Notes |
| --- | --- |
| Quick tunnel (`trycloudflare.com`) | No account. Random URL that changes on restart. Fine for trying it out. |
| Named tunnel (token) | Stable hostname, needs a Cloudflare account. User pastes a tunnel token. |
| Bundle cloudflared binary and run it as a child process | Simple, official, auto-update possible. Adds ~30 MB. |
| Embed cloudflared as a Go library | Smaller distribution but not a supported API; risky. |

Leaning: download or bundle `cloudflared` and run it as a child process. Support both quick and named tunnels.

Note: Cloudflare tunnels support WebSocket and HTTP/2 to the edge, and SSE works if buffering is off. Long idle SSE streams need keepalives (the SDK already sends them).

### Alternative to tunnels: reverse connect

Instead of exposing the workstation, the workstation **dials out** to a hub (for example to the client app on the VPS) and keeps a WebSocket open. The hub then sends ACP traffic down it. No tunnel, no public URL, works behind any NAT. This is how many "remote runner" systems work. It needs a hub side, though, so it is not a pure "any ACP client" story. Maybe phase 2: `actp serve --connect wss://hub/...`.

## Config sketch

```toml
[server]
listen = "127.0.0.1:7860"
public_url = ""            # set by tunnel when on
grace_period = "10m"

[tunnel]
provider = "cloudflare"
mode = "quick"             # quick | named
token_env = "CF_TUNNEL_TOKEN"

[[workspaces]]
name = "website"
path = "~/code/website"

[[agents]]
id = "claude"
command = "claude-code-acp"
args = []
env = {}
client_callbacks = "local" # local | forward | none
mcp_servers = "http-only"  # none | http-only | all
permissions = "forward"    # forward | auto_allow | auto_deny
max_sessions = 4
workspaces = ["website"]

[[agents]]
id = "codex"
command = "codex-acp"

[[tokens]]
name = "bot-vps"
hash = "argon2id$..."
agents = ["claude", "codex"]
```

## Lessons from existing ACP client work that shape the gateway

- **Forward the client's real capabilities**, minus what the gateway takes over (fs, terminal) or the policy hides. Advertising `elicitation.form` changes Droid's behavior.
- **Unknown agent→client requests** must get `methodNotFound`, never silence – the agent blocks on them.
- **Extension methods** (`elicitation/create`, `_x.ai/*`) pass through untouched.
- **JSON-RPC `$/cancel_request`** from the agent (Droid cancels an elicitation when a turn aborts) must reach the client.
- **Ordering**: updates before the `session/prompt` response; `session/load` replay before its response.
- **Errors** – keep `data.details` intact when forwarding.
- **Process cleanup** – SIGTERM, wait ~2 s, SIGKILL. On Windows, kill the process tree.
- **Auth required** – surface the agent's `authMethods[].description` (for example "run `claude /login`") in `actp doctor` and the tray.
- **One turn per session** – queue or reject a second prompt.

## Testing ideas

- Scripted ACP agent fixture (scenarios: stream, permission, ask-user, cancel, resume, late-commands, auth-required).
- Conformance tests against the Python SDK's HTTP and WS clients – proves "any compatible client".
- Disconnect tests: drop the socket mid-permission, reconnect with `Last-Event-ID`, answer, finish the turn.
- Real-agent smoke tests (Claude Code, Codex) behind a flag.

## Rough phases

1. **Core relay** – WebSocket + Streamable HTTP, one agent per path, bearer token, config file, process per connection. Passes SDK client tests.
2. **Durable sessions** – detach/grace period, event log, `Last-Event-ID`, pending request replay, prompt queue.
3. **Safety** – workspaces allowlist, local fs/terminal handling, MCP filtering, permission policies, audit log.
4. **Desktop** – tray app, cloudflared management, pairing, installers (dmg, msi, AppImage/deb).
5. **Later** – reverse connect to a hub, multi-user, mTLS, metrics.

## Decisions (round 1)

1. **Name** – ACTP.
2. **Language** – independent of any client app. Go or Rust (pick in spec).
3. **fs/terminal default** – open. Proposal below.
4. **Topology** – ACTP is a client/server protocol. ACP clients keep speaking plain ACP; they never learn about ACTP.
5. **Session survival** – v1.
6. **Users** – configurable per client and per server.
7. **Upstream** – no. ACTP is its own protocol (but stays compatible with the RFD transport where cheap).
8. **License** – open source from day one.
9. **Later** – server-to-server session sync, and client-side load balancing across servers.

## Decisions (round 3)

- **Tool, not protocol.** Building on the experimental ACP web transport is risky, and a competing standard is worse. ACTP is a tool: its stable API is the CLI, the config file, a small management API and its behaviour. The bridge-to-server wire is internal (`docs/wire.md`) and can change, for example to the official web transport once it is stable.
- The spec became `docs/wire.md`. The implementation doc became `docs/design.md`.

## Decisions (round 2, superseded by round 3)

- **Protocol first.** ACTP is a standard (`spec/actp-v1.md`), not one program. `actp` is the reference implementation (`docs/implementation.md`).
- **Native clients are just clients.** Apps, bots, editors – any of them can speak ACTP directly. None get special treatment.
- **The translator is now the "bridge"**, an ordinary ACTP client for unchanged stdio ACP clients. No daemon needed: `actp claude@https://host --token-env X`.

## Architecture: server + translator (round 1, superseded by the spec)

```
 Any stdio ACP client (app, editor)          Client that speaks ACTP natively
            │ stdio ACP (spawns a "local agent")           │
            ▼                                              │
 actp translator  (same machine as the client)             │
   config: remotes, tokens, agent aliases                  │
            │ ACTP (HTTPS / WSS)                           │
            └──────────────────────┬───────────────────────┘
                                   ▼
                 actp server (where the agents live)
                   config: agents, workspaces, tokens, policy
                                   │ stdio ACP
                                   ▼
                 claude-code-acp · codex-acp · droid · pi
```

- **actp server** – the standard proxy next to the agents. Owns processes, sessions, event logs, auth and policy.
- **actp translator** – runs next to the client. To the client it looks like any local ACP agent: the client spawns `actp translate claude@workstation` like it spawns `claude-code-acp` today. On the other side it speaks ACTP to the server. Same idea as `mcp-remote` for MCP.
- **Native clients** – talk ACTP directly. They only need the server URL, a token, and the agent list (from `GET /agents`).

Why this split works well:

- **Session survival is invisible to the client.** The translator holds the stdio side open while it reconnects and resumes with `Last-Event-ID`. The client never sees the drop.
- **Client-side features live in the translator** – retries, load balancing across servers, failover, later session sync.
- **Server-side features live in the server** – processes, policy, workspaces, audit.
- **One binary, two modes**: `actp serve` and `actp translate`. The tray app wraps either one.

## fs/terminal proposal (decision 3)

With the translator, forwarding `fs/*` and `terminal/*` to the client is now easy to build. But the agent's `cwd` and files are on the server, so forwarding usually reads the wrong disk. Proposal:

- **Default `local`** – the server answers fs and terminal requests on the agent host, limited to allowed workspaces. The client never sees them.
- **`forward`** – opt-in per agent, for the rare case where the client really owns the files.
- **`none`** – advertise nothing; the agent uses its own built-in tools.

## Remaining open questions

1. ~~Go or Rust?~~ **Decided: Go.**
2. fs/terminal: accept the proposal above?
3. ~~Agent selection in the translator~~ **Decided: one translator process (daemon) for many agents.** Clients spawn a thin `actp agent <alias>` shim. See spec.
4. ~~Tray app: server only or also translator?~~ **Decided: both.** One tray app that can run the server, the translator, or both.

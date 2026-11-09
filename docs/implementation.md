# actp – reference implementation

Status: draft 2 (2026-11-09)

This describes `actp`, the reference implementation of the ACTP protocol. The protocol itself is in `spec/actp-v1.md`. Where they disagree, the spec wins.

`actp` is one Go binary with three roles:

| Role | Command | What it is |
| --- | --- | --- |
| Server | `actp serve` | An ACTP server. Runs ACP agents on this machine and serves them. |
| Bridge | `actp <agent>@<server> [options]` | An ACTP client that looks like a local stdio ACP agent. For ACP clients that do not speak ACTP. |
| Tray | `actp tray` | Desktop menu bar app for the server, saved remotes, and tunnels. |

Clients that speak ACTP natively do not need any of this except a server.

## 1. Bridge

### 1.1 Usage

The bridge is what an unchanged ACP client spawns instead of a local agent:

```bash
actp claude@https://agents.example.com --token-env ACTP_TOKEN
```

Any stdio ACP client config works the same way:

```json
{ "command": "actp", "args": ["claude@https://agents.example.com", "--token-env", "ACTP_TOKEN"] }
```

Forms:

| Form | Meaning |
| --- | --- |
| `claude@https://agents.example.com` | Agent `claude` on that base URL. |
| `claude@agents.example.com` | Same, `https://` assumed. |
| `claude@localhost:7860` | `http://` assumed for loopback only. |
| `claude@workstation` | `workstation` is a saved remote (section 4). URL and token come from config or keychain. |

`actp bridge <agent>@<server>` is the long form. The short form is any first argument that contains `@` and is not a subcommand.

### 1.2 Options

| Option | Meaning |
| --- | --- |
| `--token-env NAME` | Read the token from env var `NAME`. |
| `--token-file PATH` | Read the token from a file. |
| (none) | Use `ACTP_TOKEN`, then the saved remote's token. |
| `--cwd VALUE` | Replace every `cwd` the client sends with `VALUE`, for example `actp://website`. For clients that always send their own local path. |
| `--map FROM=TO` | Rewrite `cwd` values starting with `FROM` to `TO`. Repeatable. Example: `--map /srv/bot/repo=actp://website`. |
| `--name NAME` | Sent as `Actp-Client-Name`. Default: hostname. |
| `--state-dir PATH` | Store link id and last seq here, so a restarted bridge can resume (spec 7.2). Off by default. |
| `--log-file PATH` | Debug log. stdout is ACP, so logs never go there. |

Tokens are never accepted as a plain command-line value, because command lines are visible to other users on the machine.

### 1.3 Behaviour

1. Open a link (spec 7.1). If that fails before any ACP traffic, print the reason to stderr and exit 1. The client sees an agent that failed to start, which ACP clients already handle.
2. Strip `fs` and `terminal` from the client's `initialize` (spec 8.1 says clients SHOULD NOT send them).
3. Apply `--cwd` and `--map` rewrites, and reverse them on the way back.
4. Wrap ACP messages in envelopes and pipe them both ways.
5. On a drop, reconnect and resume (spec 7.5). Keep reading from stdin meanwhile.
6. On a lost link, answer waiting requests with `-32000 remote session lost: <reason>`, print the reason to stderr, exit 1.
7. When stdin closes, send `close` and exit 0.

One bridge process serves one link. Each time a client spawns an agent, it gets its own bridge.

## 2. Server

### 2.1 Behaviour beyond the spec

- One agent process per link.
- Probe each agent at start and on demand: `initialize` without a session, 10 s timeout. The result feeds `GET /actp/v1/agents`.
- Process stop: SIGTERM, 2 s, SIGKILL. On Windows, kill the process tree.
- Keep the last 8 KB of each agent's stderr for `agent_exited` errors.
- Permission policy per agent and per token: `forward` (default), `auto_allow` (first `allow_once` option), `auto_deny` (first `reject_once`, else `cancelled`). Spec 8.4.
- MCP policy per token: `none`, `remote` (default, drop `stdio`), `all`. Spec 8.3.
- cwd mapping table per token, used in spec 8.2 rule 3.
- Audit log as JSON lines: link opened, resumed, ended (with reason), session created, permission answered (by client or policy), cwd rejected. Prompts only with `audit.log_prompts = true`.
- Plain HTTP on loopback by default. A non-loopback `listen` needs `tls_cert` and `tls_key`, or `insecure_listen = true` behind a TLS proxy.
- Reload config on `SIGHUP` or from the tray. Applies to new links.

### 2.2 Tokens

Format `actp_` + 32 random bytes in base32. Stored as SHA-256 hashes, compared in constant time, shown once at creation.

## 3. Configuration

One TOML file. Default `~/.actp/actp.toml` (Windows `%APPDATA%\actp\actp.toml`). Override with `--config`. Every section is optional.

```toml
[server]
name = "workstation"
listen = "127.0.0.1:7860"
grace_period = "10m"
replay_buffer = "8MB"
log_dir = "~/.actp/logs"

[server.tunnel]
provider = "cloudflare"
mode = "off"                      # off | quick | named
token_env = "CF_TUNNEL_TOKEN"     # named only

[[server.workspaces]]
name = "website"
path = "~/code/website"

[[server.agents]]
id = "claude"
name = "Claude Code"
command = "claude-code-acp"
args = []
env = {}
permissions = "forward"
max_links = 4

[[server.agents]]
id = "codex"
command = "codex-acp"

[[server.tokens]]
name = "bot-vps"
hash = "sha256:9f2c..."
agents = ["claude", "codex"]      # "*" for all
workspaces = ["website"]          # "*" for all
default_workspace = "website"
mcp_servers = "remote"
max_links = 8
map = { "/srv/bot/repo" = "website" }

# Saved remotes, used by the bridge short form and the tray
[[remotes]]
name = "workstation"
url = "https://agents.example.com"
token_env = "ACTP_WORKSTATION_TOKEN"   # or token_file, or keychain (tray)
```

## 4. CLI

```
actp serve
actp <agent>@<server> [options]          bridge (short form)
actp bridge <agent>@<server> [options]   bridge (long form)
actp tray
actp token create --name N [--agents a,b] [--workspaces w]
actp token list | revoke <name>
actp remote add <name> <url> [--token-stdin]
actp remote list | remove <name>
actp agents <server>                     list agents on a server (GET /actp/v1/agents)
actp doctor                              check agent commands, probe agents, check remotes
actp version
```

## 5. Tray

One app with a server section and a remotes section.

Server: status and tunnel URL, agents with status dots and "Probe again", active links (agent, client name, age, connected or "detached, 7 min left", "End"), tunnel off/quick/named with "Copy URL", "Add client…" (creates a token, shows URL and token once).

Remotes: saved remotes with status dots, "Add remote…" (URL and token, token stored in the OS keychain), "Copy bridge command" for each agent.

Shared: open config, open logs, start at login, quit.

`fyne.io/systray` for the menu. Input dialogs are small pages served on loopback with a one-time token, so there is no native GUI toolkit to maintain.

### 5.1 Cloudflare tunnel

- `cloudflared` runs as a child process pointed at `listen`.
- `quick`: `cloudflared tunnel --url http://<listen>`. The URL is read from cloudflared's output. It changes on restart.
- `named`: `cloudflared tunnel run --token <token>`. Stable hostname, needs a Cloudflare account.
- Found on PATH or in `~/.actp/bin`. If missing, the tray offers to download the official release and checks its SHA-256.
- Restart with backoff if it exits.

## 6. Code layout

Module `github.com/varops/actp`, Go 1.24+. Libraries: `github.com/coder/websocket`, `github.com/BurntSushi/toml`, `fyne.io/systray`. No ACP SDK: messages stay `json.RawMessage`, and only routed or rewritten fields are parsed, so unknown fields survive.

```
cmd/actp/            CLI entry
pkg/envelope/        ACTP envelope, seq/ack, replay buffer   (public, reusable by other Go clients)
pkg/client/          ACTP client library: open, resume, reconnect   (public)
internal/jsonrpc/    ndjson framing, peek/patch helpers
internal/server/     routes, auth, links, rewrites, policy
internal/agentproc/  spawn, stderr tail, stop (POSIX + Windows)
internal/bridge/     stdio ↔ pkg/client
internal/config/
internal/tunnel/
internal/tray/
conformance/         protocol conformance suite + scripted ACP agent
```

`pkg/client` and `pkg/envelope` are public so other Go programs can be native ACTP clients without the bridge.

## 7. Testing

- **Conformance suite** (`conformance/`): language-neutral test cases driven by a Go runner. It can test any server by URL, and any client through a fake server. This is what makes ACTP a standard and not one program.
- **Scripted ACP agent** with scenarios `stream`, `permission`, `ask-user`, `cancel`, `resume`, `auth-required`, `needs-fs`, `crash`, `slow-start`, `late-commands`.
- **Disconnect tests**: drop during a permission request, resume, answer, turn completes. Drop longer than the grace period → `remote session lost`.
- **End to end**: stdio ACP test client → bridge → server → scripted agent, on Linux, macOS and Windows in CI.
- **Real agents**: `claude-code-acp` and `codex-acp` smoke tests behind a build tag.

## 8. Milestones

1. **M1 – Protocol core.** Spec envelope and links (no resume yet), server with tokens, workspaces and rewrites, bridge with URL form. A stdio client can use a remote Claude Code.
2. **M2 – Durable links.** seq/ack, replay, grace period, resume, lost-link handling, disconnect tests.
3. **M3 – Conformance suite.** Runner, cases for every MUST in the spec, `pkg/client` documented for native clients.
4. **M4 – Tray and tunnel.** Tray, saved remotes, keychain, cloudflared.
5. **M5 – Release.** Signed builds, installers, docs site.

## 9. Open points

1. **Pi** – which command starts Pi in ACP mode?
2. **Default grace period** – 10 min.
3. **Second prompt during a turn** – pass through and let the agent reject it. Queuing is a client concern.
4. **Shared bridge daemon** – one background process that holds all links, so links survive a client restart without `--state-dir`. Not in v1; `--state-dir` covers the main case.

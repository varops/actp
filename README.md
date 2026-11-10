# ACTP – Agent Client Transport Protocol

**ACP over HTTP.** Run coding agents on one machine, use them from anywhere.

> Status: early. The server and bridge work and are tested against a scripted agent. Checked with real Claude and OpenCode adapters for handshakes and sessions. The tray icon has not been tried on a real desktop yet. See [`docs/design.md`](docs/design.md) section 12.

## Mission

Agents should run where the power, the code and the credentials are. Apps that use them should run wherever suits them. ACTP connects the two, so any ACP client can use any ACP agent on any machine, as if it were local.

## Objective

The [Agent Client Protocol (ACP)](https://agentclientprotocol.com) connects clients to coding agents such as Claude Code, Codex and Pi. Today it runs over stdio, so the client and the agent must live on the same machine.

ACTP is a tool that removes that limit. It is one binary, `actp`, with:

- **A server** that runs next to your agents and serves them over the network.
- **A bridge** that any ACP client spawns instead of a local agent. To the client it is just another ACP agent.
- **A tray app** for macOS, Windows and Linux, with built-in Cloudflare tunnels for machines without a public address.

What you get:

- **Nothing to change in clients or agents** – both sides speak plain ACP.
- **Durable connections** – a dropped network does not end the agent's work. The bridge reconnects and picks up where it left off.
- **Authentication** – tokens, scoped per client to agents and workspaces.
- **Safe defaults** – files, terminals and processes stay on the agent's machine, inside allowed workspaces.

v1 is built for chat-style clients: apps, bots and assistants that talk to an agent and show what it does. The files live on the agent's machine, so clients that edit files themselves (IDEs) are out of scope for now.

ACTP is a tool, not a new standard. Its promises are the CLI, the config file, a small management API and its behaviour. The wire between bridge and server is internal, so it can follow ACP's own web transport as that matures.

## Why

- **Distributed agents** – keep agents on a strong workstation while your app runs on a small VPS.
- **Personal agents** – connect an assistant running on your Mac to a family or business space.
- **Own infrastructure** – connect agents from machines you already own.
- **Portable integrations** – any ACP client can talk to remote agents.

## How it fits together

```
 Any ACP client (app, bot, editor)
      │ spawns: actp claude@https://agents.example.com
      ▼
 actp bridge ──── HTTPS / WebSocket ────► actp server  (agent machine)
                                               │ ACP (stdio)
                                               ▼
                                    Claude Code · Codex · Pi · ...
```

In a client's agent config:

```json
{ "command": "actp", "args": ["claude@https://agents.example.com", "--token-env", "ACTP_TOKEN"] }
```

## Quickstart

Build it (Go 1.25+):

```bash
go install github.com/varops/actp/cmd/actp@latest
```

On the machine with the agents, create `~/.actp/actp.yaml`:

```yaml
server:
  listen: 127.0.0.1:7860
  workspaces:
    - name: website
      path: ~/code/website
  agents:
    - id: claude
      preset: claude-code      # needs claude-agent-acp on PATH and `claude /login` done
```

Create a token for each client. It is printed once:

```bash
actp token create --name my-bot --default-workspace website
```

Check the setup, then start the server:

```bash
actp doctor
```

```bash
actp serve
```

The server listens on loopback. To reach it from another machine, put it behind a TLS reverse proxy, or let actp run a Cloudflare tunnel (needs `cloudflared` on PATH):

```yaml
server:
  tunnel:
    mode: quick        # a random https://….trycloudflare.com URL, new on each restart
```

`mode: named` with `token_env` gives a stable hostname from your Cloudflare account. If `cloudflared` is missing, `actp tunnel install` (or a button in the dashboard) downloads a version whose checksum is pinned in actp.

On the client machine, point any ACP client at the bridge instead of a local agent:

```json
{ "command": "actp", "args": ["claude@https://agents.example.com", "--token-env", "ACTP_TOKEN", "--cwd", "actp://website"] }
```

`--cwd actp://website` sends every session to the `website` workspace on the server, whatever folder the client is in. List what a server offers:

```bash
actp agents https://agents.example.com --token-env ACTP_TOKEN
```

### Dashboard and tray

`actp serve --dashboard` prints a one-time link to a local page with the server status, agents, open connections, and buttons to add clients and remotes. `actp tray` starts the server and opens that page; built with `-tags tray`, it also shows a menu bar icon (macOS builds need a Mac).

## Development

```bash
go test -race ./...
```

```bash
go generate ./api/
```

The second command regenerates the HTTP code after a change to `api/openapi.yaml`.

## Documents

- [`api/openapi.yaml`](api/openapi.yaml) – the HTTP API.
- [`docs/design.md`](docs/design.md) – the design: public API, behaviour, milestones.
- [`docs/agents.md`](docs/agents.md) – known ACP agents: how to start them and their quirks.
- [`docs/wire.md`](docs/wire.md) – the internal bridge-to-server format (subject to change).
- [`docs/brainstorm.md`](docs/brainstorm.md) – early notes and decisions.

## License

[Apache 2.0](LICENSE).

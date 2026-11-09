# ACTP – Agent Client Transport Protocol

**ACP over HTTP.** Run coding agents on one machine, use them from anywhere.

> Status: early design. No code yet.

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

## Documents

- [`docs/design.md`](docs/design.md) – the design: public API, behaviour, milestones.
- [`docs/wire.md`](docs/wire.md) – the internal bridge-to-server format (subject to change).
- [`docs/brainstorm.md`](docs/brainstorm.md) – early notes and decisions.

## License

[Apache 2.0](LICENSE).

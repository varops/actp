# ACTP – Agent Client Transport Protocol

**ACP over HTTP.** Run coding agents on one machine, use them from anywhere.

> Status: early design. The spec is a draft and there is no code yet.

## Mission

Agents should run where the power, the code and the credentials are. Apps that use them should run wherever suits them. ACTP is an open standard that connects the two, so any ACP client can use any ACP agent on any machine, as if it were local.

## Objective

The [Agent Client Protocol (ACP)](https://agentclientprotocol.com) connects clients to coding agents such as Claude Code, Codex and Pi. Today it runs over stdio, so the client and the agent must live on the same machine.

ACTP removes that limit. It defines how ACP travels over the network, with:

- **Discovery** – ask a server which agents and workspaces you may use.
- **Authentication** – token-based, scoped per client.
- **Durable connections** – a dropped network does not end the agent's work. The client reconnects and picks up where it left off.
- **Safe defaults** – files, terminals and processes stay on the agent's machine, inside allowed workspaces.

ACTP does not change ACP. Messages pass through as they are.

## Why

- **Distributed agents** – keep agents on a strong workstation while your app runs on a small VPS.
- **Personal agents** – connect an assistant running on your Mac to a family or business space.
- **Own infrastructure** – connect agents from machines you already own.
- **Portable integrations** – any ACP client can talk to remote agents, with no extra install on the client side.

## How it fits together

```
 ACP client that speaks ACTP ─────────────┐
                                          │ ACTP (WebSocket over TLS)
 Any stdio ACP client                     │
   └─ spawns: actp claude@host ───────────┤
              (bridge)                    ▼
                                    actp server  (agent machine)
                                          │ ACP (stdio)
                                          ▼
                              Claude Code · Codex · Pi · ...
```

- **Server** – runs next to the agents and serves them over the network.
- **Native clients** – speak ACTP directly.
- **Bridge** – for clients that only speak stdio ACP. Spawn `actp claude@https://agents.example.com` instead of a local agent and nothing else changes.
- **Tray app** – menu bar app for macOS, Windows and Linux. Manages the server and saved remotes, and can open a Cloudflare tunnel for machines without a public address.

## Documents

- [`spec/actp-v1.md`](spec/actp-v1.md) – the protocol standard (draft).
- [`docs/implementation.md`](docs/implementation.md) – `actp`, the reference implementation in Go.
- [`docs/brainstorm.md`](docs/brainstorm.md) – early design notes and decisions.

## License

Open source. License to be chosen before the first release.

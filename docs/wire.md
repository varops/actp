# actp wire format (internal)

Status: draft 2 (2026-11-09)

> **Internal and subject to change.** This is how the `actp` bridge and server talk to each other today. It is not a public protocol. Users and apps depend on the public API in `docs/design.md` (CLI, config, management endpoints, and plain ACP on both ends), never on this. We will change or replace this format when there is a good reason, for example to adopt the official ACP web transport once it is stable.

## 1. Rules for changing it

- The bridge and the server update separately. A laptop bridge and a workstation server will often run different versions.
- Every wire format has a version (`actp.v1`, `actp.v2`, ...). The bridge offers the versions it knows. The server picks the highest one both sides know.
- A server supports its current wire version and the previous one. A new bridge supports the current and previous one too.
- Changing this file is fine. Breaking the rule above is not.

## 2. Transport

- WebSocket. Every frame is a UTF-8 text frame with one JSON object. Binary frames are ignored.
- TLS (`wss://`) off loopback.
- WebSocket subprotocol names the wire version: `actp.v1`.

## 3. Opening a link

A **link** is one ACP connection to one agent process. It starts with ACP `initialize`, can carry many ACP sessions, and can outlive many WebSocket connections.

The bridge sends a WebSocket upgrade to `GET /actp/v1/agents/{agentId}/link`:

| Header | When | Meaning |
| --- | --- | --- |
| `Sec-WebSocket-Protocol` | always | Wire versions offered, for example `actp.v1`. |
| `Authorization` | always* | `Bearer <token>` (*not needed on loopback if the server allows it). |
| `Actp-Client-Name` | optional | Name for logs and the tray, for example `bot-vps`. |
| `Actp-Link-Id` | resume | The link to resume. |
| `Actp-Last-Seq` | resume | Highest server `seq` the bridge has processed. |

New link: the server starts an agent process and answers `101` with `Actp-Link-Id` (random, at least 128 bits, a secret bound to the token) and `Actp-Idle-Timeout` (seconds). The first message on a new link is ACP `initialize`.

Upgrade failures:

| Status | Meaning |
| --- | --- |
| `401` / `403` | Bad token / token may not use this agent. |
| `404` | Unknown agent. |
| `409` | Resume refused: link belongs to another token. |
| `410` | Resume refused: link unknown, ended, or replay no longer covers `Actp-Last-Seq`. |
| `426` | No common wire version. |
| `429` | Too many links. `Retry-After` included. |
| `503` | Agent failed to start. Body `{"error": "..."}`. |

## 4. Envelope

Every frame is an object with a type field `t`:

| `t` | Fields | Meaning |
| --- | --- | --- |
| `msg` | `seq`, `ack`, `msg` | One ACP JSON-RPC message, unchanged. |
| `ack` | `ack` | Acknowledgement without a message. |
| `ping` / `pong` | – | Keepalive. |
| `close` | `reason` | The sender ends the link on purpose. The server settles the agent at once. |
| `error` | `code`, `message`, `data` | Link-level failure, then the socket closes. |

```json
{ "t": "msg", "seq": 42, "ack": 17, "msg": { "jsonrpc": "2.0", "method": "session/update", "params": {} } }
```

Unknown fields and unknown `t` values are ignored.

### 4.1 Sequencing and acks

- Each side numbers its own `msg` frames from 1, increasing by 1, across sockets for the life of the link.
- `ack` = highest `seq` received from the other side and processed. `0` = none.
- Acks are **cumulative**: `ack: 120` confirms messages 1 to 120. So the bridge does not need one reply per message. It acks within 1 s of receiving, or after every 50 messages, whichever comes first.
- Each side keeps sent messages until acked and resends unacked ones after a resume.
- A `seq` already processed is dropped. A gap is an error (`sequence_gap`): the socket closes, the link survives, the bridge resumes.

### 4.2 Liveness

A TCP write succeeds as soon as the data reaches the sender's own buffer, and behind a tunnel the server's socket goes to a local `cloudflared` that is always alive. So the server never trusts its own writes. It only trusts what comes back from the bridge.

- **Bridge heartbeat.** The bridge sends something at least every 10 s: a `msg`, an `ack`, or a `ping`. When it has nothing else to say, it sends an `ack` with its current position, which is both a heartbeat and a confirmation.
- **Server rule.** Nothing received from the bridge for 25 s (two missed heartbeats plus margin) → the link is **detached**. The server closes the socket.
- **Send window.** The server stops writing to the socket when it has more than 1,000 messages or 4 MB unacked. It keeps buffering. Writing resumes as acks arrive. This stops the server from pushing into a dead connection, and it also slows a fast agent down to the speed of a slow client without losing anything.
- **The other direction.** The server answers `ping` with `pong` and sends its own `ping` after 10 s of silence, so the bridge can spot a dead server the same way (nothing for 25 s → reconnect).
- 10 s heartbeats also keep Cloudflare (100 s idle limit) and most proxies from closing quiet sockets.

A detached link only stops sending. The agent is not touched (`docs/design.md` 3.1).

### 4.3 What the server keeps

- Every message the bridge has not acked, in order: in memory up to 8 MB, then on disk up to `spool_limit`.
- The bridge's last ack. On resume, the bridge sends `Actp-Last-Seq`; the server replays everything after it, then continues live (section 5).
- Acked messages are dropped. The bridge already has them.

## 5. Resume

The bridge reconnects to the same path with `Actp-Link-Id` and `Actp-Last-Seq`. On `101` the server sends every `msg` with `seq > Actp-Last-Seq`, then continues. The bridge resends everything the server has not acked. Duplicates are dropped by 4.1.

If the link is attached to another socket, the server closes the old one with code `4001` and keeps the new one.

## 6. Error codes and close codes

| `error.code` | Meaning |
| --- | --- |
| `agent_exited` | `data` has `exitCode` and the stderr tail. Link ends. |
| `spool_full` | Output spool full while detached. Link ends. |
| `server_shutdown` | Link ends. |
| `ended_by_admin` | Link ends. |
| `sequence_gap` | Link survives. |
| `protocol_error` | Malformed frame. Link survives. |

WebSocket close codes: `1000` after `close`, `4001` replaced by a newer socket, `4002` link ended, `4003` protocol error (link survives).

## 7. Limits

- One frame: at most 16 MB.
- Replay buffer per link: kept in memory up to 8 MB, then spilled to disk up to `spool_limit` (default 1 GB).

## 8. Likely future changes

- Adopt the official ACP web transport as the base once it is stable, and keep only what it lacks (resume, auth) as extras.
- Add an HTTP POST plus event-stream variant for networks that block WebSockets.
- Compression for large session replays.

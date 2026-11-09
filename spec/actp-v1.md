# ACTP v1 – ACP over the network

Status: draft 1 (2026-11-09)

ACTP carries the Agent Client Protocol (ACP) between machines. It lets an ACP client use an ACP agent that runs on another host, with authentication, discovery, and connections that survive network drops.

This document is the standard. It does not depend on any one implementation. The `actp` binary in this repository is the reference implementation; see `docs/implementation.md`.

The words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

## 1. Overview

```
 ACTP client ──── ACTP (WebSocket over TLS) ────► ACTP server ──── ACP (stdio) ────► ACP agent
 (native)                                          (agent host)
```

- An **ACTP server** runs on the agent host. It starts ACP agents and exposes them over the network.
- An **ACTP client** connects to a server and speaks ACP to an agent through it. Any application can be a native ACTP client.
- A **bridge** is an ACTP client that exposes a remote agent as a local stdio ACP agent. It lets existing stdio ACP clients use remote agents without changes. A bridge is an ordinary ACTP client; this spec has no special rules for it.

ACTP does not change ACP. Every ACP message is carried unchanged, except for the few server rewrites in section 8.

### 1.1 Goals

- Any ACP agent can be served. Any ACP client can use it, natively or through a bridge.
- A dropped connection does not end the agent's work. The client reconnects and continues where it left off.
- Agent-side resources (files, terminals, processes) stay on the agent host.
- Simple enough to implement in a few hundred lines in any language with a WebSocket library.

### 1.2 Out of scope for v1

Load balancing, failover, server-to-server session sync, Streamable HTTP, and user management. Section 12 lists how v1 leaves room for them.

## 2. Terms

| Term | Meaning |
| --- | --- |
| Agent | An ACP agent program the server can start. Identified by an **agent id** (`[a-z0-9][a-z0-9_-]{0,63}`). |
| Link | One ACP connection between a client and one agent process, held by the server. It starts with ACP `initialize` and can carry many ACP sessions. A link has a **link id** and can outlive many WebSocket connections. |
| Socket | One WebSocket connection. A link is attached to at most one socket at a time. |
| Grace period | How long the server keeps a link alive while no socket is attached. |
| Workspace | A named folder on the agent host that agents may work in. |
| Message | One JSON-RPC 2.0 message (request, response or notification). |
| Frame | One WebSocket text frame carrying one ACTP envelope (section 6). |

## 3. Transport

- ACTP v1 runs over WebSocket (RFC 6455). Every frame is a UTF-8 text frame holding exactly one JSON object.
- Over any network other than loopback, the connection MUST use TLS (`wss://`).
- Binary frames MUST be ignored.
- The WebSocket subprotocol is `actp.v1`. A client MUST offer it. A server MUST select it or refuse the upgrade.

## 4. HTTP endpoints

All paths are relative to the server's **base URL**, for example `https://agents.example.com` or `https://example.com/actp`.

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /actp/v1/info` | no | Server metadata. |
| `GET /actp/v1/agents` | yes | Agents the caller may use. |
| `GET /actp/v1/agents/{agentId}/link` | yes | WebSocket upgrade. Opens or resumes a link. |

A server MAY serve other paths. A server MAY also serve `GET /health` returning `200` for monitoring.

### 4.1 `GET /actp/v1/info`

```json
{
  "actp": ["1"],
  "name": "workstation",
  "auth": ["bearer"],
  "gracePeriodSeconds": 600,
  "extensions": []
}
```

- `actp` – protocol versions the server supports. MUST contain `"1"`.
- `name` – display name. Optional.
- `auth` – supported auth schemes (section 5).
- `gracePeriodSeconds` – how long links survive without a socket.
- `extensions` – names of optional extensions the server supports (section 11).

Clients MUST ignore unknown fields here and in every other ACTP JSON object.

### 4.2 `GET /actp/v1/agents`

```json
{
  "agents": [
    {
      "id": "claude",
      "name": "Claude Code",
      "description": "Anthropic's coding agent",
      "status": "ready",
      "workspaces": [
        { "name": "website", "default": true },
        { "name": "docs" }
      ],
      "agentInfo": { "name": "claude-code-acp", "version": "0.12.0" },
      "agentCapabilities": { "loadSession": true }
    }
  ]
}
```

- `id` (required), `name`, `description`.
- `status` (required): `ready`, `auth_required`, or `unavailable`.
  - `auth_required` SHOULD include `authHint`: text from the agent's ACP `authMethods[].description`, for example "Run `claude /login` on the agent host".
  - `unavailable` SHOULD include `error`.
- `workspaces`: the workspaces this caller may use with this agent. At most one has `default: true`.
- `agentInfo`, `agentCapabilities`: from the agent's last ACP `initialize` response, if the server has one. They are hints. The real values come from `initialize` on the link.

The list MUST contain only agents the caller is allowed to use.

## 5. Authentication

- v1 defines one scheme, `bearer`: `Authorization: Bearer <token>` on every authenticated request, including the WebSocket upgrade.
- Token format, storage and issuing are up to the server. Tokens SHOULD have at least 128 bits of entropy.
- Missing or invalid token → `401`. Valid token without access to the agent → `403`.
- A server MAY accept unauthenticated requests from loopback only.
- Clients that cannot set headers on a WebSocket upgrade (browsers) are out of scope for v1.

The server decides per token which agents, workspaces and limits apply. A token identifies a **client**, not a person.

## 6. Envelope

Every frame, in both directions, is an envelope object with a type field `t`.

| `t` | Fields | Meaning |
| --- | --- | --- |
| `msg` | `seq`, `ack`, `msg` | One ACP JSON-RPC message in `msg`. |
| `ack` | `ack` | Acknowledgement with no message. |
| `ping` | – | Keepalive request. |
| `pong` | – | Keepalive reply. |
| `close` | `reason` (optional) | The sender ends the link on purpose. |
| `error` | `code`, `message`, `data` (optional) | Link-level failure. The sender closes the socket after it. |

Example:

```json
{ "t": "msg", "seq": 42, "ack": 17, "msg": { "jsonrpc": "2.0", "method": "session/update", "params": {} } }
```

Receivers MUST ignore unknown fields and MUST ignore envelopes with an unknown `t`.

### 6.1 Sequencing

- Each side numbers its own `msg` envelopes with `seq`, starting at 1 for a new link and increasing by exactly 1. Numbering continues across sockets for the life of the link.
- `ack` is the highest `seq` the sender has received from the other side **and processed** (handed to the agent, or to the client application). `0` means none.
- Each side MUST keep every `msg` it sent until the other side acks it.
- A receiver MUST drop a `msg` whose `seq` is not higher than the last one it processed. A gap (a `seq` more than one higher) is a protocol error: send `error` with code `sequence_gap` and close the socket. The link stays alive; the client resumes.
- Each side SHOULD send an ack (in a `msg` or an `ack` envelope) within 1 second of receiving a `msg`, and at least every 50 messages.

### 6.2 Keepalive

Each side SHOULD send `ping` after 20 seconds without sending anything and MUST answer `ping` with `pong`. If nothing at all arrives for 60 seconds, the side SHOULD treat the socket as dropped. Sending something every 20 seconds keeps common proxies and tunnels from closing idle sockets.

## 7. Links

### 7.1 Opening a link

The client sends a WebSocket upgrade to `/actp/v1/agents/{agentId}/link` with:

| Header | Required | Meaning |
| --- | --- | --- |
| `Sec-WebSocket-Protocol` | yes | `actp.v1` |
| `Authorization` | yes* | Bearer token (*unless the server allows loopback without auth). |
| `Actp-Client-Name` | no | Display name for logs and UIs, for example `bot-vps`. |
| `Actp-Link-Id` | resume only | The link to resume. |
| `Actp-Last-Seq` | resume only | Highest server `seq` the client has processed. |

On a new link the server MUST start (or assign) an agent process and answer `101` with:

- `Actp-Link-Id`: a new opaque id, at least 128 bits of randomness. Clients MUST treat it as a secret bound to their token.
- `Actp-Grace-Period`: grace period in seconds for this link.

The first message the client sends on a new link MUST be ACP `initialize`.

Upgrade failures:

| Status | Meaning |
| --- | --- |
| `401` / `403` | Section 5. |
| `404` | Unknown agent id. |
| `409` | Resume refused: link belongs to another token. |
| `410` | Resume refused: link unknown, ended, or its replay buffer no longer covers `Actp-Last-Seq`. |
| `429` | Too many links. SHOULD include `Retry-After`. |
| `503` | Agent unavailable (failed to start). Body SHOULD be `{"error": "..."}`. |

### 7.2 Resuming a link

To resume, the client opens a new socket to the same path with `Actp-Link-Id` and `Actp-Last-Seq`.

On success the server answers `101` and then:

1. Sends every `msg` with `seq > Actp-Last-Seq`, in order.
2. Continues normally.

The client MUST then resend every `msg` it sent that the server has not acked, in order. The server's first envelope tells the client the server's current `ack`. Duplicates are dropped by rule 6.1.

If the link is attached to another socket when a resume arrives, the server MUST close the older socket with WebSocket close code `4001` and attach the new one.

A client MAY store the link id and last seq on disk. This lets an application restart and resume its links, within the grace period.

### 7.3 While detached

When a socket drops without a `close` envelope, the link becomes **detached**:

- The agent process keeps running. Its output is buffered for replay.
- Requests from the agent to the client (for example `session/request_permission`) stay pending. The agent waits, as it would for a slow human.
- The server MUST keep the link for at least the advertised grace period, unless the replay buffer overflows. In that case it MAY end the link early.

### 7.4 Ending a link

A link ends when:

1. Either side sends a `close` envelope.
2. The grace period passes with no socket attached.
3. The agent process exits.
4. The server ends it for its own reasons (shutdown, admin action, buffer overflow).

When the **server** ends a link that still has an agent process, it MUST settle the agent first, in this order:

1. Answer every pending `session/request_permission` with `{"outcome": {"outcome": "cancelled"}}`.
2. Answer every other pending agent→client request: elicitation requests with `{"action": "cancel"}`, all others with a JSON-RPC error.
3. Send ACP `session/cancel` for every session with a running turn.
4. Send ACP `session/close` for every open session, if the agent supports it.
5. Stop the agent process.

Errors in steps 3 and 4 MUST NOT stop the sequence.

If a socket is attached, the server SHOULD send an `error` envelope (or `close` when the client asked for it) before closing the socket. Codes:

| Code | Meaning |
| --- | --- |
| `agent_exited` | The agent process exited. `data` SHOULD include `exitCode` and the tail of stderr. |
| `grace_expired` | Not sent (no socket). A later resume gets `410`. |
| `buffer_overflow` | Replay buffer full while detached. |
| `server_shutdown` | Server is stopping. |
| `ended_by_admin` | Ended by an operator. |
| `sequence_gap` | Section 6.1. The link survives. |
| `protocol_error` | Malformed envelope. The link survives. |

WebSocket close codes: `1000` after a `close` envelope, `4001` replaced by a newer socket, `4002` link ended (after an `error`), `4003` protocol error (link survives).

### 7.5 Client behaviour on drop

A client SHOULD reconnect with exponential backoff and jitter (for example 0.5 s up to 15 s) until the grace period has passed. During that time it keeps accepting messages from its application and buffers them.

If resume fails with `410`, or the link ends, the client MUST treat every ACP request it is still waiting on as failed. A bridge SHOULD answer those requests to its local client with JSON-RPC error code `-32000` and a message starting with `remote session lost:`.

A client that wants to continue after a lost link opens a new link and uses ACP `session/load` or `session/resume`, if the agent supports them.

## 8. Server rewrites

The server reads the ACP traffic on a link and changes only what this section lists. Everything else MUST pass through unchanged: ids, unknown methods, unknown fields, extension methods (for example `elicitation/create`, `_x.ai/*`), and JSON-RPC request cancellation in both directions.

### 8.1 Client capabilities

The agent's files and processes live on the agent host. A remote client cannot serve them correctly.

- In the `initialize` request, the server MUST remove `clientCapabilities.fs` and `clientCapabilities.terminal` before passing it to the agent.
- If the agent still sends an `fs/*` or `terminal/*` request, the server MUST answer it with JSON-RPC `methodNotFound` (-32601) and MUST NOT forward it.
- All other client capabilities MUST pass through. They change agent behaviour (for example, some agents only ask structured questions when `elicitation.form` is present).

Clients SHOULD NOT advertise `fs` or `terminal` over ACTP.

### 8.2 Working directory

ACP `session/new`, `session/load`, `session/resume` and `session/list` carry a `cwd`. A path on the client machine usually means nothing on the agent host.

ACTP defines a workspace URI: `actp://<workspace>/<optional/sub/path>`.

The server MUST resolve `cwd` in this order:

1. An `actp://` URI → the workspace's path plus the sub path. The sub path MUST NOT leave the workspace.
2. An absolute path inside a workspace the caller may use → unchanged.
3. Any other value → server-defined mapping, then the caller's default workspace if one exists.
4. Otherwise → reject the request with JSON-RPC `invalidParams` (-32602) and a message starting with `cwd not allowed:`.

Paths MUST be normalized and symlinks resolved before the check.

In responses and notifications that carry a `cwd` the server resolved, the server SHOULD write back the value the client sent, so the client sees its own form.

Clients SHOULD send `actp://` URIs when they know the workspace. Clients that cannot (unchanged stdio clients behind a bridge) rely on rules 3 and 4, or on a bridge that rewrites `cwd` for them.

### 8.3 MCP servers

A `stdio` entry in ACP `mcpServers` asks the agent host to run a command. The server MUST NOT pass `stdio` MCP servers to the agent unless the caller is explicitly allowed to. It MAY pass `http` and `sse` entries. Removed entries SHOULD be logged.

### 8.4 Server policy

A server MAY answer agent→client requests itself, based on its own policy (for example auto-deny permission requests for a token). When it does, it MUST still send the agent a valid ACP response, and SHOULD log the decision. It MUST NOT send the client a request it already answered.

## 9. Ordering

- Within a link, messages in each direction MUST be delivered in `seq` order.
- The server MUST forward agent messages in the order the agent wrote them. In ACP this keeps `session/update` notifications before the `session/prompt` response, and `session/load` replay before the `session/load` response.

## 10. Limits

- A server SHOULD bound the replay buffer per link (for example 8 MB or 10,000 messages) and the number of links per token and per agent.
- A single envelope MUST NOT be larger than 16 MB. Servers MAY set a lower limit and SHOULD advertise it as `maxFrameBytes` in `/actp/v1/info`.

## 11. Versioning and extensions

- The version is in the path (`/actp/v1/`) and the subprotocol (`actp.v1`). Breaking changes get a new version.
- New optional fields can be added to any ACTP object without a version change. Receivers ignore unknown fields.
- Optional features are named extensions, listed in `/actp/v1/info` `extensions`. Extension names use reverse domain style for third parties (`com.example.feature`) and plain names for ones defined by this project.
- New envelope types for an extension MUST only be sent after the other side has shown support for that extension.

## 12. Room for later

v1 is designed so these can be added as extensions:

- **Load balancing and failover** – a client with several servers for the same agent picks one per link. No server change needed. Failover of a live link needs session sync.
- **Server-to-server session sync** – lets ACP `session/load` work on a server other than the one that created the session.
- **Streamable HTTP** – the same link and envelope model over POST plus SSE, with `Last-Event-ID` = last `seq`.
- **More auth schemes** – listed in `info.auth`.

## 13. Security considerations

- Agents run with the rights of the server's OS user. Anyone holding a token for an agent can make it read, write and run anything that user can, inside and possibly outside the workspace, depending on the agent. Workspaces limit the agent's starting point, not its power. Issue tokens accordingly.
- Link ids are bearer secrets for a live session. Resume MUST also check the token (`409`).
- Removing `fs`/`terminal` (8.1) and `stdio` MCP servers (8.3) stops a client from using the server as a remote shell **through ACP itself**. It does not limit the agent.
- TLS is required off loopback (section 3).

## 14. Conformance

An implementation conforms to ACTP v1 if it passes the conformance suite in `conformance/` for its role (server or client). The suite uses a scripted ACP agent and covers: info and agents endpoints, auth errors, link open and resume, sequencing and duplicates, gap handling, keepalive, detach and grace expiry, the settle order in 7.4, and every rewrite in section 8.

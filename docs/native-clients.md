# Native ACTP clients: a guide for implementers

This guide is for people and coding agents who want an ACP client to talk to an `actp serve` directly, without spawning the `actp` bridge. It describes the `actp.v1` wire format as the code in this repository implements it, and everything a client has to do to be as reliable as the bridge.

**Use the bridge if you can.** Spawning `actp <agent>@<server>` gives you all of this for free, as a local stdio ACP agent. Go native when spawning a process is not an option, or when you want link state (connected, reconnecting, lost) in your own UI.

**Compatibility promise.** Servers accept `actp.v1` for all of actp 1.x. A newer wire format would come with a new subprotocol name (`actp.v2`) and be negotiated; a client that only offers `actp.v1` keeps working. Fields may be added to frames and JSON bodies at any time: ignore what you do not know.

Reference implementations to read: [`internal/wire/wire.go`](../internal/wire/wire.go) (both sides of the envelope), [`internal/bridge/bridge.go`](../internal/bridge/bridge.go) (a complete client), and [`api/openapi.yaml`](../api/openapi.yaml) (the HTTP endpoints).

## 1. The model in one paragraph

A **link** is one ACP connection to one agent process on the server. You open it with a WebSocket upgrade, and the first ACP message you send on it is `initialize`. The link can carry many ACP sessions, and it outlives WebSockets: when the socket drops, the agent keeps working and the server keeps its output; you reconnect with the link id and the last sequence number you processed, and both sides resend what the other missed. Every ACP message travels in a numbered envelope. You never change the ACP messages themselves.

## 2. Before you start: discovery and auth

Every request needs `Authorization: Bearer <token>`, except `GET /health`. There is no exception for local connections.

| Request | Use |
| --- | --- |
| `GET /health` | `{"ok":true}` when an actp server answers. A bare 404 means something else answered (often an old quick-tunnel URL). |
| `GET /api/v1/info` | Server name, actp version, `wireVersions` (newest first), `promptTimeoutSeconds`, `publicUrl`. |
| `GET /api/v1/agents` | The agents this token may use: `id`, `name`, `status` (`ready`, `auth_required` with `authHint`, `unavailable` with `error`, `unknown`), `workspaces` (one may have `"default": true`), and the agent's last `agentCapabilities`. |

Show `authHint` to the user when an agent is `auth_required`: the login has to happen on the server machine.

## 3. Opening a link

```
GET {base}/actp/v1/agents/{agentId}/link
Upgrade: websocket
Sec-WebSocket-Protocol: actp.v1
Authorization: Bearer actp_…
Actp-Client-Name: my-app on laptop        (optional, shown in the server's dashboard)
```

`{base}` is the server URL (`https://…`; use `wss://` for the socket). The server answers `101` with:

| Response header | Meaning |
| --- | --- |
| `Actp-Link-Id` | The link id. A secret bound to your token: keep it to resume, never log it. |
| `Actp-Last-Seq` | The highest of your sequence numbers the server has processed (`0` on a new link). |
| `Actp-Prompt-Timeout` | Seconds an unanswered prompt waits for you after a drop. |

Errors come before the upgrade, as HTTP statuses with a JSON body `{"error": "<code>", "message": "…"}`:

| Status | Meaning | What to do |
| --- | --- | --- |
| 401 | Missing or wrong token | Stop. Ask for a token. |
| 403 | Token may not use this agent | Stop. |
| 404 with JSON | Unknown agent | Stop. Re-read `/api/v1/agents`. |
| 404 without JSON | No actp server at this URL | Stop. The URL is wrong or a quick tunnel restarted. |
| 409 | Resume refused: the link belongs to another token | Stop. |
| 410 | Resume refused: the link has ended | The session is lost (section 8). |
| 426 | Not a WebSocket upgrade, or no common wire version | Stop. Upgrade your client or the server. |
| 429 | Too many links | Retry after `Retry-After` seconds. |
| 503 | The agent failed to start | Stop. Show `message`. |
| 5xx, network errors | Temporary | Retry with backoff. |

**Browsers cannot do this**: the browser WebSocket API cannot set `Authorization`. Native clients run in Node, Electron's main process, Go, Python, Rust and the like.

## 4. Frames

Every WebSocket message is a UTF-8 text frame holding one JSON object. Binary frames are ignored.

| `t` | Fields | Meaning |
| --- | --- | --- |
| `msg` | `seq`, `ack`, `msg` | One ACP JSON-RPC message in `msg`, unchanged. |
| `ack` | `ack` | Acknowledgement with no message. Also your heartbeat. |
| `ping` | – | Liveness probe. Answer with `pong`. |
| `pong` | – | Answer to `ping`. |
| `bye` | – | Client → server: "my user has left". See section 7. |
| `error` | `code`, `message`, `data` | Link-level failure. The socket closes after it. |

```json
{"t":"msg","seq":42,"ack":17,"msg":{"jsonrpc":"2.0","method":"session/update","params":{}}}
{"t":"ack","ack":17}
```

`ack` and `seq` may be left out when they are 0. Ignore unknown fields and unknown `t` values.

## 5. Sequencing: the rules that make resume work

Keep these per link, across sockets:

| State | Meaning |
| --- | --- |
| `nextSeq` | Your last assigned sequence number. Starts at 0; the first message is 1. |
| `outbox` | Messages you sent that the server has not acked, in order. |
| `peerAck` | The highest of your `seq` the server has acked. |
| `lastRecv` | The highest server `seq` you have **processed** (handed to your ACP layer). |

Rules:

1. **Sending:** `nextSeq += 1`, append `{seq, msg}` to `outbox`, and write `{"t":"msg","seq":…,"ack":lastRecv,"msg":…}` if a socket is open.
2. **Receiving `msg`:** first apply its `ack` (rule 4). Then:
   - `seq <= lastRecv`: a duplicate after a resume. Drop it.
   - `seq == lastRecv + 1`: hand `msg` to your ACP layer, **then** set `lastRecv = seq`.
   - `seq > lastRecv + 1`: a gap. Close the socket with code 4003 and resume (section 6).
   - Do the check, the delivery and the update as one step: never deliver the same `seq` twice, even if a new socket opens while you are still handling a message from the old one.
3. **Acking:** acks are cumulative (`ack: 120` confirms 1 to 120). Ack within 1 s of receiving a message, or after every 50 messages, whichever comes first. Any `msg` you send carries your current `ack`, so a separate `ack` frame is only needed when you have nothing else to send.
4. **Receiving an `ack`** (in any frame): if it is higher than `peerAck`, set `peerAck` and drop those messages from `outbox`.
5. **Send window:** keep at most 1,000 messages or 4 MB unacked on the wire. Above that, keep queuing in `outbox` but stop writing until acks arrive.

## 6. Liveness and resume

**Do not trust writes.** A WebSocket write succeeds as soon as the bytes reach your own buffer, and through a tunnel there is always a live relay in between. Only what comes back proves the other side is there.

- **Heartbeat:** if you have sent nothing for 10 s, send `{"t":"ack","ack":lastRecv}`.
- **Dead socket:** if nothing at all has arrived for 25 s, close the socket (code 4004) and resume. The server applies the same rule to you and marks the link *detached*; the agent keeps working.
- **Answer `ping` with `pong`.**

**Resume** = open a new socket to the same URL with two more headers:

```
Actp-Link-Id: <the id from the first upgrade>
Actp-Last-Seq: <lastRecv>
```

On `101`:

1. Read the response's `Actp-Last-Seq`. Apply it like an ack (rule 4): it is the highest of your messages the server has processed.
2. Resend everything left in `outbox`, in order, with their original `seq`.
3. The server resends everything after your `Actp-Last-Seq`. Rule 2 drops anything you already had.

Retry with exponential backoff and jitter (0.5 s, doubling, up to 30 s). Give up after about 10 minutes of trying, measured on a clock that does not run while the machine sleeps, and treat the session as lost (section 8). Stop at once on 401, 403, 404, 409, 410 and 426.

If a second socket resumes the same link, the server closes the older one with code 4001. Only one socket per link is ever live.

## 7. Ending a link: say goodbye

When your user closes the conversation or your app quits, flush the `outbox`, then send `{"t":"bye"}` and close with code 1000. The server then treats the link as **unattended**:

- the agent finishes its current turn (or the server cancels it, if the agent is set to `on_client_exit: cancel`);
- anything the agent asks the client from then on (permissions, questions) is answered "cancelled" at once;
- once the turn is done, the server closes the sessions and stops the agent. The work stays in the agent's session store.

To stop work rather than leave, send ACP `session/cancel` (stops the turn) or `session/close` (ends the session) **before** the bye, like any ACP client would.

If you cannot send a bye (your process is killed), the link is only *detached*: the server keeps it for `idle_close` (10 minutes by default) once nothing is running, or for `prompt_timeout` if a prompt is waiting. When your app starts again, it does not resume the old link: it opens a new one and uses ACP `session/load` (section 9).

## 8. When the link is lost

A link is lost when a resume gets `410`, or an `error` frame arrives with one of these codes:

| `error.code` | Meaning |
| --- | --- |
| `agent_exited` | The agent process exited. `data` has `exitCode` and `stderr` (the last 8 KB). |
| `link_ended` | The server ended the link (idle, prompt timeout, unattended turn done). `message` says which. |
| `ended_by_admin` | Someone pressed "End" in the server's dashboard. |
| `server_shutdown` | The server is stopping. |
| `spool_full` | You were away too long and the server's buffer for you filled up. |

`sequence_gap` and `protocol_error` do **not** end the link: resume.

When the agent exits or the link ends while you are away, the server keeps the output you have not received for a while. Resuming then delivers it, followed by the `error` frame. Process everything before you act on the error.

When the link is lost, answer every ACP request your UI is still waiting for (for example `session/prompt`) with an error, so nothing hangs. The bridge uses code `-32000` and a message starting with `remote session lost:`. Then offer to continue with a new link and `session/load`.

## 9. ACP over ACTP: what the server changes

ACP messages pass through unchanged, except for these. Build your client with them in mind.

- **Files and terminals stay on the server.** The server removes `clientCapabilities.fs` and `clientCapabilities.terminal` from your `initialize`, and answers any `fs/*` or `terminal/*` request itself. Do not advertise them. You still see every tool call, command and output in `session/update`.
- **Other client capabilities pass through**, and they change agent behaviour. Advertise `elicitation.form` only if you answer `elicitation/create`.
- **Working folders (`cwd`).** Your local path means nothing on the server. Send `actp://<workspace>` or `actp://<workspace>/<sub/path>`, with a workspace name from `/api/v1/agents`. An absolute path inside an allowed workspace also works. Anything else is rejected with `-32602` and a message starting with `cwd not allowed:`, unless the token has a mapping or a fallback.
- **MCP servers.** By default the server drops `stdio` entries and `http`/`sse` entries that point at `localhost`: they would run on, or point at, the server machine.
- **Permissions** may be answered by the server's policy (`auto_allow`, `auto_deny`) without reaching you.
- **Terminal login hints** (`_meta.terminal-auth` in `authMethods`) are removed: a login has to happen on the server machine.
- **Loading a session that is still running elsewhere** (for example on a link your app left behind when it crashed) returns `-32000` `session still running on the agent host`. The old link is marked unattended; retry after its turn ends.
- `$/cancel_request` and extension methods (`_x.ai/*`, `elicitation/create`, …) pass through in both directions. If the agent cancels a request it sent you, remove the prompt from your UI.

## 10. Reference implementation (TypeScript, Node)

This is a compact, working shape for a native client, using the [`ws`](https://github.com/websockets/ws) package. It handles framing, acks, heartbeats, the send window, resume, bye and loss. Wire your ACP layer (for example `ClientSideConnection` from `@agentclientprotocol/sdk`, on top of a stream adapter) to `send()` and the `message` event.

```ts
import WebSocket from "ws";
import { EventEmitter } from "node:events";

type Frame = { t: string; seq?: number; ack?: number; msg?: unknown; code?: string; message?: string; data?: unknown };

const HEARTBEAT_MS = 10_000, DEAD_MS = 25_000, ACK_DELAY_MS = 1_000, ACK_EVERY = 50;
const WINDOW_MSGS = 1_000, WINDOW_BYTES = 4 << 20, MAX_BACKOFF_MS = 30_000, GIVE_UP_MS = 10 * 60_000;
const PERMANENT = new Set([401, 403, 404, 409, 410, 426]);
const LINK_ENDING = new Set(["agent_exited", "link_ended", "ended_by_admin", "server_shutdown", "spool_full"]);

export class ActpLink extends EventEmitter {
  // events: "message" (ACP message object), "state" ("connecting" | "connected" | "reconnecting"), "lost" (reason string)
  private ws?: WebSocket;
  private linkId?: string;
  private nextSeq = 0;
  private outbox: { seq: number; raw: string; size: number }[] = [];
  private peerAck = 0;
  private sentSeq = 0;
  private lastRecv = 0;
  private ackedOut = 0;
  private lastHeard = 0;
  private lastSent = 0;
  private ackTimer?: NodeJS.Timeout;
  private tick?: NodeJS.Timeout;
  private closing = false;
  private lost = false;

  constructor(private opts: { baseUrl: string; agent: string; token: string; clientName?: string }) {
    super();
  }

  async open(): Promise<void> {
    this.emit("state", "connecting");
    await this.connect(); // throws on the first failure, so a bad URL or token fails fast
  }

  /** Queue an ACP message for the agent. */
  send(msg: unknown): void {
    if (this.lost) throw new Error("link lost");
    const seq = ++this.nextSeq;
    const raw = JSON.stringify(msg);
    this.outbox.push({ seq, raw, size: Buffer.byteLength(raw) });
    this.flush();
  }

  /** The user left: flush, say bye, close. */
  async bye(): Promise<void> {
    this.closing = true;
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    this.flush(true);
    ws.send(JSON.stringify({ t: "bye" }));
    ws.close(1000);
  }

  private url(): string {
    const u = new URL(this.opts.baseUrl.replace(/\/$/, "") + `/actp/v1/agents/${encodeURIComponent(this.opts.agent)}/link`);
    u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
    return u.toString();
  }

  private connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = { Authorization: `Bearer ${this.opts.token}` };
      if (this.opts.clientName) headers["Actp-Client-Name"] = this.opts.clientName;
      if (this.linkId) {
        headers["Actp-Link-Id"] = this.linkId;
        headers["Actp-Last-Seq"] = String(this.lastRecv);
      }
      const ws = new WebSocket(this.url(), ["actp.v1"], { headers });
      ws.on("unexpected-response", (_req, res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          let code = "";
          try { code = JSON.parse(body).error ?? ""; } catch {}
          const err = Object.assign(new Error(`HTTP ${res.statusCode}${code ? ` (${code})` : ""}`), {
            status: res.statusCode ?? 0,
            actp: code !== "",
          });
          reject(err);
        });
      });
      ws.on("upgrade", (res) => {
        this.linkId = String(res.headers["actp-link-id"] ?? this.linkId);
        const last = Number(res.headers["actp-last-seq"] ?? 0);
        this.applyAck(last);
        this.sentSeq = this.peerAck; // resend everything the server has not processed
      });
      ws.on("open", () => {
        this.ws = ws;
        this.lastHeard = this.lastSent = Date.now();
        this.ackedOut = 0; // announce our position on the new socket
        this.emit("state", "connected");
        this.startTick();
        this.flush();
        this.sendAck();
        resolve();
      });
      ws.on("message", (data, isBinary) => {
        if (isBinary) return;
        this.lastHeard = Date.now();
        this.onFrame(JSON.parse(data.toString()) as Frame);
      });
      ws.on("close", () => this.onClose(ws));
      ws.on("error", (e) => { if (!this.ws) reject(e); });
    });
  }

  private onFrame(f: Frame): void {
    switch (f.t) {
      case "msg": {
        if (f.ack) this.applyAck(f.ack);
        const seq = f.seq ?? 0;
        if (seq <= this.lastRecv) return; // duplicate after a resume
        if (seq !== this.lastRecv + 1) { this.ws?.close(4003, "sequence gap"); return; }
        this.emit("message", f.msg); // deliver first ...
        this.lastRecv = seq; // ... then count it as processed
        if (this.lastRecv - this.ackedOut >= ACK_EVERY) this.sendAck();
        else this.ackTimer ??= setTimeout(() => this.sendAck(), ACK_DELAY_MS);
        return;
      }
      case "ack": if (f.ack) this.applyAck(f.ack); return;
      case "ping": this.write({ t: "pong" }); return;
      case "error":
        if (f.code && LINK_ENDING.has(f.code)) this.lose(f.message ?? f.code);
        return; // sequence_gap / protocol_error: the socket closes and we resume
    }
  }

  private applyAck(a: number): void {
    if (a <= this.peerAck) return;
    this.peerAck = Math.min(a, this.nextSeq);
    while (this.outbox.length && this.outbox[0].seq <= this.peerAck) this.outbox.shift();
    if (this.sentSeq < this.peerAck) this.sentSeq = this.peerAck;
    this.flush();
  }

  private flush(ignoreWindow = false): void {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    let inflight = 0;
    for (const it of this.outbox) if (it.seq <= this.sentSeq) inflight += it.size;
    for (const it of this.outbox) {
      if (it.seq <= this.sentSeq) continue;
      if (!ignoreWindow && (this.sentSeq - this.peerAck >= WINDOW_MSGS || inflight >= WINDOW_BYTES)) break;
      ws.send(`{"t":"msg","seq":${it.seq},"ack":${this.lastRecv},"msg":${it.raw}}`);
      this.sentSeq = it.seq;
      this.ackedOut = this.lastRecv;
      this.lastSent = Date.now();
      inflight += it.size;
    }
  }

  private sendAck(): void {
    clearTimeout(this.ackTimer);
    this.ackTimer = undefined;
    this.write({ t: "ack", ack: this.lastRecv });
    this.ackedOut = this.lastRecv;
  }

  private write(f: Frame): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(f));
      this.lastSent = Date.now();
    }
  }

  private startTick(): void {
    clearInterval(this.tick);
    this.tick = setInterval(() => {
      const now = Date.now();
      if (now - this.lastHeard > DEAD_MS) this.ws?.close(4004, "peer silent");
      else if (now - this.lastSent >= HEARTBEAT_MS) this.sendAck();
    }, 1_000);
  }

  private async onClose(ws: WebSocket): Promise<void> {
    if (this.ws !== ws) return;
    this.ws = undefined;
    clearInterval(this.tick);
    if (this.closing || this.lost) return;
    this.emit("state", "reconnecting");
    const start = performance.now(); // monotonic; pauses while the machine sleeps on most platforms
    let delay = 500;
    while (!this.closing && !this.lost) {
      await new Promise((r) => setTimeout(r, delay / 2 + Math.random() * delay));
      try { await this.connect(); return; } catch (e: any) {
        if (PERMANENT.has(e.status)) {
          this.lose(e.status === 404 && !e.actp ? "no actp server answers at this URL" : e.message);
          return;
        }
        if (performance.now() - start > GIVE_UP_MS) { this.lose("server unreachable"); return; }
        delay = Math.min(delay * 2, MAX_BACKOFF_MS);
      }
    }
  }

  private lose(reason: string): void {
    if (this.lost) return;
    this.lost = true;
    clearInterval(this.tick);
    this.ws?.close(1000);
    this.emit("lost", reason); // answer pending ACP requests with an error, then offer session/load
  }
}
```

This code was run against `actp serve` and the scripted agent with the socket killed mid-turn: it reconnected, received all chunks once and in order, and the turn ended with `end_turn`. It uses TypeScript parameter properties, so with Node's built-in TypeScript support run it with `--experimental-transform-types` (or compile it as usual).

Points that are easy to get wrong:

- Deliver a message to your ACP layer **before** you count it as processed. If your process dies in between, the server resends it.
- Keep `outbox` until it is acked, not until it is written.
- On resume, apply the response's `Actp-Last-Seq` before you resend.
- Handle messages from the socket strictly in order. With an async ACP layer, queue them; do not process two at once.

## 11. Test checklist

Run an `actp serve` against the scripted test agent in this repository. It reacts to prompt text: `echo <text>`, `slow <n>` (n chunks, 100 ms apart), `permission`, `ask`, `fs`, `caps`, `cwd`, `crash`, `burst-crash <n>`.

```bash
go build -o actp ./cmd/actp && go build -o actp-testagent ./cmd/actp-testagent
```

Give the server an agent with `command: ./actp-testagent` and a workspace, create a token with `actp token create`, and run `actp serve`. Then check that your client:

1. Lists agents with `GET /api/v1/agents` and shows `auth_required` hints.
2. Runs `initialize`, `session/new` with `actp://<workspace>`, and `echo hello` gets `hello` back.
3. Answers a `permission` prompt, and the agent receives the answer.
4. Does not advertise `fs` or `terminal` (`caps` echoes what the agent got).
5. With `slow 20`, **cut the connection mid-turn** (for example through a TCP proxy you can kill, or by turning Wi-Fi off). All 20 chunks arrive once and in order, and the turn ends with `end_turn`.
6. Same, but **freeze** the connection without closing it (a proxy that drops bytes). Your client notices within about 25 s and resumes.
7. Sends `bye` when the user closes the conversation, and a later `session/load` on a new link shows the finished turn.
8. With `crash`, reports the session as lost with the agent's stderr, and answers the pending `session/prompt` with an error.
9. With `burst-crash 300`, receives all 300 chunks before the loss.
10. A wrong token fails at once with 401, and a URL with no server says so instead of "unknown agent".

The Go end-to-end tests in [`internal/e2e`](../internal/e2e) do all of this against the bridge, including a TCP proxy that can cut or freeze connections. They are the best model for your own tests.

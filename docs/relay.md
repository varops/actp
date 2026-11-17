# Relay mode

**Rust only.** Relay mode and the relay (`actp-relay`) exist only in the Rust build (`rust/`). The Go `actp serve` does not read the `relay` section and refuses a config file that has one.

In relay mode, a machine does not listen for connections. It connects out to one relay over WSS on port 443, and callers reach it through that relay. This suits a fleet of laptops: nothing listens on a laptop, so there are no firewall rules, no Wi-Fi isolation problems and no VPN, and only one server (the relay) faces callers.

```
 caller (actp bridge, IT app)                 relay (one, client-hosted)                 laptop
 ────────────────────────────                 ──────────────────────────                 ─────────────────────
 https://relay/m/<machine>/… ──── TLS ────►   routes by machine address   ◄── WSS out, device certificate ── actp serve (relay mode)
```

## What the relay does and does not do

- **It routes.** A caller asks for `/m/<machine>/<path>`. The relay forwards the request, headers and all, to that machine as `<path>`, over a stream the machine opens for it. The caller's credentials reach the machine untouched, and the machine checks them. The relay never decides who may use a machine.
- **It knows the machines by their device certificates.** Machines log in with the organization's device certificate over mutual TLS. The machine's address is a name in that certificate (the common name by default). The relay never assigns addresses.
- **It knows who is online,** and when each machine was last seen.
- **It holds the org-wide stop.** One switch drops every session on every machine and refuses new ones until it is released. Machines are told, and end their sessions themselves too.
- **It writes its half of the audit:** which caller connected to which machine, when and for how long, and every stop and release, with who and why. Ids, addresses, times and byte counts only, never what a session carries.

### What a compromised relay can do

The relay sees the traffic it routes in plaintext, credentials included. Someone who controls the relay can therefore:

- read every session, and act inside any session a real caller opened;
- keep the credentials callers present and use them again, against any machine that accepts them, for as long as they stay valid. With actp tokens that is until the token is revoked, on every machine that has it;
- send a caller to a different machine than the one it asked for, or answer as the machine itself, because the caller does not check which machine it reached.

What it cannot do is get a machine to accept credentials the machine would refuse. Org mode, where callers present signed papers instead of tokens, can narrow the reuse to papers that are bound to one machine and expire within minutes. Until callers check the machine end to end (an open question), host the relay like any other server IT relies on, and prefer org mode over shared actp tokens.

## The machine

Add a `relay` section to the server config. Nothing else changes: agents, workspaces, tokens and every check apply as before. `listen`, `tls_cert` and `tls_key` are not used, and a tunnel cannot be on.

```yaml
server:
  relay:
    url: wss://relay.example.com          # the relay: wss://host[:port], no path
    cert: /etc/actp/device.pem            # the device certificate, leaf first, then intermediates
    key: /etc/actp/device.key
    ca: /etc/actp/relay-ca.pem            # roots for the relay's certificate (default: the OS store)
  agents: …
  tokens: …
```

`actp serve` then connects to the relay and keeps the connection up. After a drop it reconnects, waiting 1 s, then 2 s, and so on up to 30 s, with some jitter so a fleet does not reconnect in step. Sessions survive a drop as usual: the bridge reconnects through the relay and catches up.

Set `ca` to the private CA that signs the relay's certificate. With the OS store, any publicly trusted certificate for the relay's hostname would be accepted as the relay.

The machine checks what the relay tells it: the first message must be the hello, with a well-formed machine address, and the machine dials nothing but the configured relay URL. It opens at most 64 relayed connections at once.

The device key is read from a PEM file. Keys that the OS keeps non-exportable (the macOS keychain, the Windows certificate store) need a signer that uses the key store; the `actp_server::relay` API takes any `rustls::ClientConfig`, so an embedding program can supply one.

## The relay

```yaml
# actp-relay.yaml
listen: 0.0.0.0:443
tls_cert: /etc/actp-relay/relay.pem       # the relay's own certificate
tls_key: /etc/actp-relay/relay.key
device_ca: /etc/actp-relay/device-ca.pem  # roots of the org's device certificates
device_crls: []                           # optional revocation lists (PEM or DER)
machine_name: cn                          # cn, dns or uri: which certificate name is the address
blocked_machines: []                      # addresses refused even with a valid certificate
state_dir: /var/lib/actp-relay            # stop.json, machines.json
log_dir: /var/log/actp-relay              # audit.jsonl
max_streams_per_machine: 32
caller_rate: {per_second: 20, burst: 60}  # per caller IP, for /m/… and the management API
max_connections: 20000                    # connections held at once by anyone but machines
max_connections_per_ip: 1000              # the same per IP address (IPv6: per /64)
audit_max_mb: 100                         # audit.jsonl is rotated at this size; ten old files are kept
admin_tokens:
  - name: dave                            # recorded with every stop and release
    hash: sha256:…                        # from `actp-relay token create`
```

```bash
actp-relay serve --config /etc/actp-relay/actp-relay.yaml
```

The relay must terminate TLS itself: a TLS proxy in front of it would hide the device certificates. It serves from the root path only.

`SIGHUP` reloads the blocked machines, the admin tokens, the rate limits, `max_connections_per_ip`, the device roots and the revocation lists. The listen address, the folders, `audit_max_mb` and `max_connections` need a restart.

The connection limits count every connection from the moment it is accepted, before the TLS handshake (which may take 5 s), and for as long as it lives, sessions included. A connection that proves itself a machine with a valid device certificate stops counting, so callers filling the limits do not keep laptops from reconnecting once their handshake is through. A refused connection is closed at once and recorded as `connection_refused` (throttled).

Device certificates are checked again, not only when a machine connects. The relay checks a machine's certificate against the roots and revocation lists in force on every request it makes, on every reload, and every ten seconds. A machine that is now blocked, or whose certificate has expired or been revoked, is taken off the list at once and cut off with its sessions (links), and cannot come back. A plain request already being answered, such as a listing of agents, finishes. TLS sessions are never resumed, so a reconnect always presents the certificate again.

With `machine_name: uri`, only URIs without a path work as addresses (`urn:device:1234`, not `spiffe://acme/dev/1`), because an address cannot contain `/`.

Any certificate under `device_ca` counts as a machine, so use roots that sign only device certificates, not ones that also sign user or Wi-Fi certificates. Revocation lists are checked for the device certificate itself, not its issuers, and a list past its next-update time no longer counts: every machine is then refused and cut off until a fresh list is in place and the relay reloads.

A machine address has 1 to 253 characters: letters, digits and `.`, `-`, `_`, `@`, `:`, `+`, `~`. A certificate whose name does not fit, or that carries more than one name of the chosen kind, is refused. Addresses are compared exactly.

### Callers

Point the bridge at the machine's address under the relay:

```bash
actp claude@https://relay.example.com/m/C02XK1ABJG5H --token-env ACTP_TOKEN
```

| Answer | Meaning |
| --- | --- |
| `503 machine_offline` | The machine is not connected to the relay. |
| `503 org_stopped` | The org-wide stop is on. |
| `429 machine_busy` | Too many callers are using the machine (`max_streams_per_machine`). |
| `504 machine_timeout` | The machine did not open a stream or answer in time. |
| `429 rate_limited` | Too many requests from this IP address (`caller_rate`). |

The relay itself asks callers for nothing; the machine checks them. So anyone who can reach the relay can learn whether a machine of a given address is online, and can make machines do the work of opening a stream for each request, within `caller_rate`. `caller_rate` and `max_connections_per_ip` count per IP address (per /64 for IPv6), so callers behind one NAT address share them. The rate limit covers every route except the machines' own: `/health` and unknown paths too. Keep the relay off the open internet where the org can.

A session ends at the relay when either side closes, when its machine's control connection is lost (the machine is offline), when the machine is blocked or its certificate stops being valid, or on the org-wide stop. Idle TCP connections are probed with keepalives, so a laptop that vanishes mid-session is noticed within a few minutes.

Anything else comes from the machine itself.

### Management

All three need an admin token (`Authorization: Bearer …`).

```bash
curl -H "Authorization: Bearer $ADMIN" https://relay.example.com/relay/v1/machines
```

```json
{
  "stop": {"stopped": false, "by": "", "reason": "", "at": ""},
  "machines": [
    {"machine": "C02XK1ABJG5H", "online": true, "connected_since": "2026-11-16T09:12:03.120Z",
     "first_seen": "2026-11-02T08:00:41.000Z", "last_seen": "2026-11-16T10:40:00.512Z", "sessions": 1}
  ]
}
```

```bash
curl -X POST -H "Authorization: Bearer $ADMIN" -d '{"reason": "suspicious activity on the IT account"}' https://relay.example.com/relay/v1/stop
```

```bash
curl -X POST -H "Authorization: Bearer $ADMIN" -d '{"reason": "account secured"}' https://relay.example.com/relay/v1/release
```

`GET /relay/v1/stop` shows the stop. A reason is required for both. The stop takes effect at once and is written to `state_dir/stop.json`, so it survives a restart; if that file cannot be read, the relay starts with the stop on. If the stop cannot be written, the answer is `500 stop_not_saved` (the stop still holds) and the relay keeps trying every few seconds. A release is written before it takes effect, so a release that cannot be recorded does not happen (`500 not_released`).

Keep `state_dir` with the relay: a relay that starts without its `stop.json` knows of no stop, and its hello releases the stop on every machine that connects.

### Audit

`log_dir/audit.jsonl`, one JSON object per line:

| Event | Fields |
| --- | --- |
| `machine_online`, `machine_replaced` | `machine`, `remote` |
| `machine_offline` | `machine`, `seconds`, `reason` (`closed`, `silent`, `blocked`, `certificate_invalid`, `relay stopping`, …) |
| `machine_refused` | `remote`, `route`, `reason`, and `machine` when the certificate named one |
| `session_open` | `session`, `machine`, `remote`, `agent`, `link` (first 8 characters), `resumed`, `client_name` |
| `session_closed` | `session`, `machine`, `seconds`, `bytes_to_machine`, `bytes_to_caller`, `reason` (`closed`, `org_stop`, `machine_offline`, `blocked`, `certificate_invalid`, `relay_stopping`, `error`, `upgrade_failed`) |
| `caller_answered` | `machine`, `remote`, `route` (the path as the machine routes it, without the query), `status`: every link request that did not become a session, and every request the machine refused (throttled like a refusal) |
| `connection_refused` | `remote` (the address, or the IPv6 /64, at its limit) |
| `caller_refused` | `machine`, `remote`, `reason` |
| `caller_rate_limited` | `remote` |
| `org_stop` | `by`, `reason`, `sessions_dropped` |
| `org_stop_not_saved`, `org_stop_saved` | `error` / nothing |
| `org_release` | `by`, `reason` |
| `admin_refused` | `remote`, `route` |
| `config_reloaded` | `blocked_machines`, `machines_cut` |
| `refusals_not_logged` | `kind`, `count` |

Of each refusal kind (`caller_refused`, `caller_rate_limited`, `connection_refused`, `machine_refused`, `admin_refused`, and `caller_answered` with a status of 400 or more), at most 20 a minute are written, across all callers; the rest are counted in `refusals_not_logged`. A flood of refusals therefore leaves only a count of everyone's refusals for that minute; sessions, machines and the stop are always recorded.

The stop's own events (`org_stop`, `org_release`, `org_stop_not_saved`, `org_stop_saved`) are also written to `log_dir/org_stops.jsonl`, which is never rotated, so no flood of other events can push them out.

`client_name` is what the caller says about itself; the relay does not check it. The machine's own audit log records who the machine authenticated.

## Protocol

Between a machine and the relay (`actp_proto::relay`):

1. The machine opens `wss://<relay>/relay/v1/connect` with its device certificate and the WebSocket subprotocol `actp-relay.v1`. The relay answers with `{"type":"hello","machine":"<address>","stopped":<bool>}` and pings every 15 s; the machine pings every 20 s. Either side drops a connection that stays silent too long.
2. When a caller arrives, the relay sends `{"type":"open","stream":"<64 hex>"}`. The machine opens `wss://<relay>/relay/v1/stream/<id>` with its certificate and subprotocol `actp-relay-stream.v1`. Only the machine that was asked can take the stream. Binary messages on it carry the caller's HTTP connection byte for byte, and the machine serves it like any other connection. Closing the stream closes both directions: a half-closed connection is not kept half open.
3. `{"type":"stop"}` and `{"type":"release"}` carry the org-wide stop, and so does the hello's `stopped`. While it is on, the machine ends every link and refuses new links and resumes with `503 org_stopped`, even if the relay goes on routing callers to it.

Unknown message types are ignored, so a newer relay can add messages.

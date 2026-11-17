# Relay mode and org mode

**Rust only.** Relay mode, org mode and the relay (`actp-relay`) exist only in the Rust build (`rust/`). The Go `actp serve` does not read the `relay` or `org` sections and refuses a config file that has one.

In relay mode, a machine does not listen for connections. It connects out to one relay over WSS on port 443, and callers reach it through that relay. This suits a fleet of laptops: nothing listens on a laptop, so there are no firewall rules, no Wi-Fi isolation problems and no VPN, and only one server (the relay) faces callers.

Everything between a caller and a machine is encrypted end to end. The caller opens TLS through the relay straight to the machine and checks the machine's device certificate; the relay carries bytes it cannot read or change.

```
 caller (actp bridge, IT app)                    relay (one, client-hosted)                  laptop
 ────────────────────────────                    ──────────────────────────                  ─────────────────────
 tunnel to <machine>, caller certificate ──►     routes by machine address    ◄── WSS out, device certificate ── actp serve
   └── TLS 1.3 inside the tunnel, straight to the laptop's device certificate ─────────────────────────────────►  (relay mode)
```

## What the relay does and does not do

- **It routes.** A caller opens a tunnel to `/relay/v1/tunnel/<machine>`. The relay asks that machine for a stream and joins the two. Inside the tunnel the caller runs TLS 1.3 to the machine; requests, answers and credentials (actp tokens, signed papers) travel inside it, and the machine checks the credentials. The relay sees none of it and never decides who may use a machine.
- **It checks who may open tunnels.** Callers present a caller certificate from the org's caller roots (`caller_ca`), which share no root with the device roots. A stranger cannot open streams to laptops through the relay, and neither can a laptop with its device certificate.
- **It knows the machines by their device certificates.** Machines log in with the organization's device certificate over mutual TLS. The machine's address is a name in that certificate (the common name by default). The relay never assigns addresses.
- **It knows who is online,** and when each machine was last seen.
- **It holds the org-wide stop.** One switch drops every session on every machine and refuses new ones until it is released. Machines are told, and end their sessions themselves too.
- **It writes its half of the audit:** which caller (by its certificate) connected to which machine, when and for how long, and every stop and release, with who and why. Ids, addresses, times and byte counts only: what a session carries is encrypted, and the relay never has it.

### What a compromised relay can do

Someone who controls the relay holds its certificate, the routing table and the stop. Because the caller's TLS ends at the machine, they still cannot:

- **read** a session or the credentials in it: they see TLS records, not requests, answers, tokens or papers;
- **change** anything: a changed byte fails the TLS record check, and the connection breaks;
- **send a caller to another machine, or answer as the machine:** the caller accepts only a certificate from the org's device roots that names the machine it asked for. Another machine's real certificate, a forged one or the relay's own all fail the handshake;
- **reuse a caller's credentials**, since they never see them.

What they can do:

- refuse, delay or drop connections, and hold back the org-wide stop or release it;
- see who called which machine, when, for how long and how many bytes moved (what the relay's own audit records);
- open tunnels to machines themselves, which get them a TLS connection to a machine and nothing more without credentials the machine accepts.

Keep the device roots and the caller roots apart, protect the caller certificates' keys (they are what the relay checks), make callers check device revocation lists themselves (the relay's lists do not protect a caller from a compromised relay), and keep the relay off the open internet where the org can.

Two things the whole design rests on:

- **Machine names nobody can change.** A caller knows it reached the machine because the certificate names it. Use an identifier fixed by the hardware or the MDM (the serial number, the hardware UUID), never a computer name a user can edit: a laptop renamed after another, with a certificate re-issued to match, would pass as it. The relay records both certificates' fingerprints in `machine_replaced` when a second certificate claims a live machine's name.
- **Separate certificate hierarchies.** `device_ca` and `caller_ca` must be separate hierarchies, neither above the other. The relay refuses to start when they share a root (compared by subject and key, so a re-issued root counts) or one root is issued by the other, and refuses at every connection a certificate that is valid as both kinds (nesting deeper than the roots show). Callers check machines against the device roots only, so they rely on this too.

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

`actp serve` then connects to the relay and keeps the connection up. Every caller the relay sends opens TLS 1.3 on its stream, and the machine answers with the same device certificate (`cert`, `key`), so callers know they reached this machine. Nothing but a caller that completes that handshake reaches the server. After a drop it reconnects, waiting 1 s, then 2 s, and so on up to 30 s, with some jitter so a fleet does not reconnect in step. Sessions survive a drop as usual: the bridge reconnects through the relay and catches up.

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
caller_ca: /etc/actp-relay/caller-ca.pem  # roots of the caller certificates (the IT app's); no root shared with device_ca
caller_crls: []                           # optional revocation lists for caller certificates
caller_name: cn                           # which caller certificate name names the caller (audit, blocks, limits)
blocked_callers: []                       # callers refused even with a valid certificate
state_dir: /var/lib/actp-relay            # stop.json, machines.json
log_dir: /var/log/actp-relay              # audit.jsonl
max_streams_per_machine: 32
max_streams_per_caller: 8                 # streams one caller may have to one machine at once
caller_rate: {per_second: 20, burst: 60}  # per caller IP, for tunnels and the management API
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

The relay must terminate TLS itself: a TLS proxy in front of it would hide the device certificates. It serves from the root path only, and only TLS 1.3, so client certificates (which name every machine and caller) are never sent in the clear.

A caller's name follows the same rules as a machine address (below); a caller certificate whose name does not is refused. `blocked_machines` and `blocked_callers` are compared exactly, case included.

`SIGHUP` reloads the blocked machines and callers, the `issuer` section, the admin tokens, the rate limits, `max_connections_per_ip`, the device and caller roots and the revocation lists. The listen address, the folders, `audit_max_mb` and `max_connections` need a restart.

The connection limits count every connection from the moment it is accepted, before the TLS handshake (which may take 5 s), and for as long as it lives, sessions included. A connection that proves itself a machine with a valid device certificate stops counting, so callers filling the limits do not keep laptops from reconnecting once their handshake is through. A refused connection is closed at once and recorded as `connection_refused` (throttled).

Device certificates are checked again, not only when a machine connects. The relay checks a machine's certificate against the roots and revocation lists in force on every request it makes, on every reload, and every ten seconds. A machine that is now blocked, or whose certificate has expired or been revoked, is taken off the list at once and cut off with its sessions (links), and cannot come back. A plain request already being answered, such as a listing of agents, finishes. TLS sessions are never resumed, so a reconnect always presents the certificate again.

With `machine_name: uri`, only URIs without a path work as addresses (`urn:device:1234`, not `spiffe://acme/dev/1`), because an address cannot contain `/`.

Any certificate under `device_ca` counts as a machine, so use roots that sign only device certificates, not ones that also sign user or Wi-Fi certificates. Revocation lists are checked for the device certificate itself, not its issuers, and a list past its next-update time no longer counts: every machine is then refused and cut off until a fresh list is in place and the relay reloads.

A machine address has 1 to 253 characters: letters, digits and `.`, `-`, `_`, `@`, `:`, `+`, `~`. A certificate whose name does not fit, or that carries more than one name of the chosen kind, is refused. Addresses are compared exactly.

### Callers

A caller needs a caller certificate from `caller_ca`, the relay's roots (or the OS store), and the org's device roots, to check the machine:

```bash
actp claude@https://relay.example.com --relay-machine C02XK1ABJG5H \
  --relay-cert it-bridge.pem --relay-key it-bridge.key --relay-ca relay-ca.pem \
  --device-ca device-ca.pem --token-env ACTP_TOKEN
```

`--device-crl FILE` (repeatable) gives the device revocation lists, re-read before every connection; the bridge refuses to start without one unless told `--no-device-crl`, because only a caller's own check keeps a compromised relay from presenting a revoked machine certificate. `--machine-name cn|dns|uri` says which certificate name is the address, and must match the relay's `machine_name`. The Go `actp` has none of this. A program using the bridge library sets `actp_client::Options::relay` to an `actp_client::RelayRoute` (`RelayRoute::from_files` builds one from the same files).

The caller opens `wss://<relay>/relay/v1/tunnel/<machine>` (subprotocol `actp-relay-tunnel.v1`) with its caller certificate. Inside the tunnel it opens TLS 1.3 (ALPN `actp-e2e.v1`, required by both ends; no session resumption) and accepts the machine's certificate only if it chains to the device roots, is not revoked by the given lists, is valid for client use (as at the relay) and names exactly the machine asked for. Then it speaks actp as usual.

| Answer | Meaning |
| --- | --- |
| `401 caller_certificate_required` | No client certificate. |
| `403 bad_caller_certificate` | Not a usable caller certificate: a device certificate, one no longer valid, one valid as both kinds, or one whose name is not a valid caller name. |
| `403 caller_blocked` | The caller is in `blocked_callers`. |
| `503 machine_offline` | The machine is not connected to the relay. |
| `503 org_stopped` | The org-wide stop is on. |
| `429 machine_busy` | Too many callers are using the machine (`max_streams_per_machine`). |
| `429 caller_busy` | This caller already has `max_streams_per_caller` streams to the machine. |
| `504 machine_timeout` | The machine did not open a stream in time. A stop, the machine going offline, or the caller being blocked meanwhile answers at once instead. |
| `429 rate_limited` | Too many requests from this IP address (`caller_rate`). |

Caller certificates are checked again on every tunnel request, on every reload and every ten seconds; a caller whose certificate is revoked, expires or is blocked is cut off with its sessions. `caller_rate` and `max_connections_per_ip` count per IP address (per /64 for IPv6), so callers behind one NAT address share them; the rate limit covers every route except the machines' own.

A session ends at the relay when either side closes, when its machine's control connection is lost (the machine is offline), when the machine or the caller is blocked or its certificate stops being valid, or on the org-wide stop. Idle TCP connections are probed with keepalives, so a laptop that vanishes mid-session is noticed within a few minutes.

Anything else comes from the machine itself.

### The issuer pass-through

Laptops sometimes need to ask the organization's identity service something (for example, whether the person whose papers they hold has been revoked), and they cannot reach it. With an `issuer` section, a machine can ask it through the relay:

```yaml
issuer:
  url: https://idm.internal:8788          # the identity service (http:// on loopback only)
  ca: /etc/actp-relay/idm-ca.pem          # roots for its certificate; required for https
  headers:                                # the relay's own credentials there
    X-Example-Caller: relay
    X-Example-Secret: env:RELAY_IDM_SECRET   # env:NAME reads an environment variable
  paths: [/v1/generation/signed]          # the only paths forwarded, exactly
  rate: {per_second: 1, burst: 10}        # per machine
  timeout_seconds: 5
```

A machine sends `GET /relay/v1/issuer/<path>?<query>` with its device certificate (callers and strangers are refused, and blocked machines as on every machine route). If `<path>` is one of `paths`, the relay asks `GET <url><path>?<query>` with the configured headers and hands back the status and the body (at most 64 KB) as JSON. Nothing else from the machine is forwarded (not its headers, not a body), and nothing else of the answer comes back.

| Answer | Meaning |
| --- | --- |
| `404 issuer_path_not_forwarded` | The path is not in `paths`. |
| `414 issuer_query_too_long` | The query is over 2048 bytes. |
| `429 issuer_rate_limited` | This machine asked too often (`rate`). |
| `503 issuer_busy` | 32 questions are already in flight. |
| `502 issuer_unavailable` | The identity service could not be reached, did not answer in time, or answered more than 64 KB. |
| `404 not_found` | No `issuer` section. |

The relay sees the questions and the answers, so only forward questions whose answers a machine can check itself: an answer signed by the identity service and bound to a nonce the machine chose cannot be forged or replayed by the relay, only withheld. Refusals are recorded as `issuer_refused` (machine and reason, throttled); questions themselves are not recorded, as their queries name people. A reload replaces the section; one that cannot be used (a missing roots file, an unset variable) leaves the old one in force and logs an error.

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
| `machine_online` | `machine`, `remote` |
| `machine_replaced` | `machine`, `remote`, `old_certificate`, `new_certificate` (SHA-256 fingerprints) |
| `machine_offline` | `machine`, `seconds`, `reason` (`closed`, `silent`, `blocked`, `certificate_invalid`, `relay stopping`, …) |
| `machine_refused` | `remote`, `route`, `reason`, and `machine` when the certificate named one |
| `session_open` | `session`, `machine`, `caller`, `remote` |
| `session_closed` | `session`, `machine`, `caller`, `seconds`, `bytes_to_machine`, `bytes_to_caller`, `reason` (`closed`, `org_stop`, `machine_offline`, `blocked`, `certificate_invalid`, `caller_blocked`, `caller_certificate_invalid`, `relay_stopping`, `error`, `upgrade_failed`) |
| `connection_refused` | `remote` (the address, or the IPv6 /64, at its limit) |
| `caller_refused` | `caller` (when its certificate named one), `machine` (when one was reached), `remote`, `reason` |
| `caller_rate_limited` | `remote` |
| `issuer_refused` | `machine`, `reason` |
| `org_stop` | `by`, `reason`, `sessions_dropped` |
| `org_stop_not_saved`, `org_stop_saved` | `error` / nothing |
| `org_release` | `by`, `reason` |
| `admin_refused` | `remote`, `route` |
| `config_reloaded` | `blocked_machines`, `blocked_callers` |
| `refusals_not_logged` | `kind`, `count` |

Of each refusal kind (`caller_refused`, `caller_rate_limited`, `connection_refused`, `machine_refused`, `admin_refused`, `issuer_refused`), at most 20 a minute are written, across all callers; the rest are counted in `refusals_not_logged`. A flood of refusals therefore leaves only a count of everyone's refusals for that minute; sessions, machines and the stop are always recorded.

The stop's own events (`org_stop`, `org_release`, `org_stop_not_saved`, `org_stop_saved`) are also written to `log_dir/org_stops.jsonl`, which is never rotated, so no flood of other events can push them out.

What a caller asked of a machine (which agent, which link) is inside the encryption: the machine's own audit log records it, with who the machine authenticated.

## Org mode

In org mode a machine accepts signed papers from the organization's identity service instead of actp tokens. Nobody on the way vouches for a caller, the relay included: the machine checks the papers itself. Org mode is Rust only, like relay mode, and the two are meant to be used together.

Checking papers is split in two:

- **A papers verifier** knows the issuer. It checks the signature, freshness and whatever else the issuer requires (for example that the person is still who the papers say), and answers with who the caller is, which machine the papers are for, and what they grant. It is supplied by the program that embeds `actp-server`, as an `actp_server::org::PapersVerifier`. actp ships no verifier for a real identity service; `actp_server::org::testing::SharedSecret`, behind the crate's `testing` feature, is for tests. `actp serve` has no verifier, so it refuses a config with an `org` section, and so does a config reload.
- **actp** then checks, whatever the verifier said: that the papers name this machine, and that they carry the required grant as exactly `true`.

```yaml
server:
  relay: …
  org:
    machine: C02XK1ABJG5H                 # this machine's address: the name in its device certificate
    require_grant: machines.operate       # the grant papers must carry, as true
    access:                               # what a caller with good papers may use here
      agents: [it-agent]
      workspaces: [it]
      default_workspace: it
  agents: …
  workspaces: …
```

There are no `tokens` in org mode (a config with both is refused), and no tunnel. A program that runs the server with an `org` section and no verifier fails to start; a reload that would turn org mode on without one is refused and the old config kept.

A verifier has 10 s. If it times out, or says the issuer cannot be asked just now, the caller gets `503 auth_unavailable` with `Retry-After` on any route, not a refusal. A bridge reconnecting to an open session keeps trying, so the session survives a short outage of the identity service; a bridge that is just starting reports the error. The server logs these at `warn`, once a minute. A verifier must not block (the time limit covers its future only), and one that asks its issuer online should cache or limit, since anyone who can reach the machine can present papers.

In relay mode the machine also compares `org.machine` with the address the relay knows it by. While they differ, every caller is refused (`org_machine_mismatch`, logged at `warn`): a config copied from another machine must not accept papers meant for that machine.

A caller id must be 1 to 256 characters of letters, digits and `.`, `_`, `-`, `@`, `+`, `:`, `=`; papers naming anything else are refused.

A caller sends its papers as the bearer token (`Authorization: Bearer <papers>`), in whatever encoding the verifier reads; papers over 32 KB are refused. The caller then gets `access`, under the name `papers:<caller id>`. Only the same person can resume a link, and link limits count per person. Papers are checked on every request, so a dropped connection is resumed with fresh papers: the bridge library takes a `token_source` that fetches them before each connection. As with revoked tokens, a connection already open runs until it closes. Revoking someone stops their new connections and resumes as soon as the verifier sees it: at once if it asks the issuer each time, when the papers expire if it only checks signatures.

Links belong to a person, but the agent's sessions do not: everyone who gets in with the same `access` can list, load, continue or delete the sessions on that machine, as with a shared token. Callers who must not see each other's work need separate machines.

The machine's audit log records `auth_refused` with the reason and the caller for papers that are genuine but do not let the caller in: `papers_other_machine`, `papers_no_grant`, or a verifier's own code when it names the caller (the test verifier's `papers_expired`). Papers nobody vouches for (`papers_malformed`, a bad signature, an issuer that cannot be asked, `no_papers_verifier`) are refused without an audit line, as unknown tokens are, so they cannot fill the log. The same person refused for the same reason is written once a minute, with `repeats` counting the ones left out. `link_opened` names the caller as `papers:<caller id>`. Token names starting with `papers:` are reserved, and an empty `org:` section is an error, not a quiet return to tokens.

## Protocol

Between a machine and the relay (`actp_proto::relay`):

1. The machine opens `wss://<relay>/relay/v1/connect` with its device certificate and the WebSocket subprotocol `actp-relay.v2` (v1 carried plain HTTP on its streams; a v1 machine and a v2 relay refuse each other). The relay answers with `{"type":"hello","machine":"<address>","stopped":<bool>}` and pings every 15 s; the machine pings every 20 s. Either side drops a connection that stays silent too long.
2. A caller opens `wss://<relay>/relay/v1/tunnel/<machine>` with its caller certificate and subprotocol `actp-relay-tunnel.v1`. The relay sends the machine `{"type":"open","stream":"<64 hex>"}`; the machine opens `wss://<relay>/relay/v1/stream/<id>` with its certificate and subprotocol `actp-relay-stream.v2`. Only the machine that was asked can take the stream. The relay answers the caller's upgrade once the stream is there, and joins the two: binary messages on both carry the same bytes, the caller's TLS to the machine (`actp_proto::e2e`), which the machine answers with its device certificate and then serves like any other connection. Closing either side closes both directions: a half-closed connection is not kept half open.
3. `{"type":"stop"}` and `{"type":"release"}` carry the org-wide stop, and so does the hello's `stopped`. While it is on, the machine ends every link and refuses new links and resumes with `503 org_stopped`, even if the relay goes on routing callers to it.

Unknown message types are ignored, so a newer relay can add messages.

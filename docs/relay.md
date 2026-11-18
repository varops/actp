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
- **It writes its half of the audit:** which caller (by its certificate) connected to which machine, when and for how long, whom the caller said it acted for, and every stop and release, with who and why. Ids, addresses, names, times and byte counts only: what a session carries is encrypted, and the relay never has it.
- **It answers only admins and operators** about any of this. An operator is a caller certificate the configuration gives a role (`operators`), such as the IT app's; every other caller certificate opens tunnels and nothing more (under Management and operators, below).

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

- **Machine names nobody can change.** A caller knows it reached the machine because the certificate names it. Use an identifier fixed by the hardware or the MDM (the serial number, the hardware UUID), never a computer name a user can edit: a laptop renamed after another, with a certificate re-issued to match, would pass as it. The relay pins each name to the key it was first seen with (below), so a second certificate for a name with another key is refused, and it records both certificates' fingerprints in `machine_replaced` when a second certificate claims a live machine's name.
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
max_connections_per_machine: 64           # connections one machine may hold before they become its control connection or streams
machine_key_renewal_days: 0               # off: a new key needs the old key's proof (key continuity) or an admin; set, see Key pinning
tunnel_idle_seconds: 600                  # a tunnel that carries nothing either way for this long is cut (at least 60)
audit_max_mb: 100                         # audit.jsonl is rotated at this size; ten old files are kept
admin_tokens:
  - name: dave                            # recorded with every stop and release
    hash: sha256:…                        # from `actp-relay token create`
operators:                                # callers with a role at the relay; none by default
  - caller: it-bridge                     # the caller's name, as caller_name reads it
    may: [machines, audit, stop, release]
  - caller: manager
    may: [machines]
    certificates: [sha256:…]              # optional: only these certificates count as this operator
```

```bash
actp-relay serve --config /etc/actp-relay/actp-relay.yaml
```

The relay must terminate TLS itself: a TLS proxy in front of it would hide the device certificates. It serves from the root path only, and only TLS 1.3, so client certificates (which name every machine and caller) are never sent in the clear.

A caller's name follows the same rules as a machine address (below); a caller certificate whose name does not is refused. `blocked_machines` and `blocked_callers` are compared exactly, case included.

`SIGHUP` reloads the blocked machines and callers, the `issuer` section, the admin tokens, the operators, the rate limits, `max_connections_per_ip`, `max_connections_per_machine`, `machine_key_renewal_days`, `tunnel_idle_seconds` (for new tunnels), the device and caller roots and the revocation lists. The listen address, the folders, `audit_max_mb` and `max_connections` need a restart.

The connection limits count every connection from the moment it is accepted, before the TLS handshake (which may take 5 s), and for as long as it lives, sessions included. A connection that proves itself a machine, with a valid device certificate whose key is the one its name is pinned to (below), stops counting, so callers filling the limits do not keep laptops from reconnecting once their handshake is through. It counts against `max_connections_per_machine` instead until it becomes the machine's control connection or a stream, so one machine cannot hold thousands of idle connections. A certificate for the name with another key counts as anyone's, so it cannot fill the machine's places. A refused connection is closed at once and recorded as `connection_refused` (throttled), with the machine when it was the machine's limit.

A tunnel that carries no bytes either way for `tunnel_idle_seconds` is cut (`session_closed` with reason `idle`): a caller or machine gone quiet without closing does not hold one of the machine's streams for ever. Live sessions are not affected: ACP links send heartbeats every 10 s, and the machine closes an HTTP connection that sends nothing for 10 s itself.

Device certificates are checked again, not only when a machine connects. The relay checks a machine's certificate against the roots and revocation lists in force on every request it makes, on every reload, and every ten seconds. A machine that is now blocked, or whose certificate has expired or been revoked, is taken off the list at once and cut off with its sessions (links), and cannot come back. A plain request already being answered, such as a listing of agents, finishes. TLS sessions are never resumed, so a reconnect always presents the certificate again.

With `machine_name: uri`, only URIs without a path work as addresses (`urn:device:1234`, not `spiffe://acme/dev/1`), because an address cannot contain `/`.

Any certificate under `device_ca` counts as a machine, so use roots that sign only device certificates, not ones that also sign user or Wi-Fi certificates. Revocation lists are checked for the device certificate itself, not its issuers, and a list past its next-update time no longer counts: every machine is then refused and cut off until a fresh list is in place and the relay reloads.

#### Key pinning

The first device certificate the relay sees for a machine name pins the name to that certificate's public key (its SubjectPublicKeyInfo, by SHA-256), kept in `state_dir/machines.json` with the certificate's validity. A certificate for the same name with the same key, re-issued or renewed, is taken as before. A certificate with another key, though the org's CA signed it, is refused: its connection counts as anyone's, its requests get `403 machine_key_changed`, and `machine_key_refused` records both keys, once a minute per machine with a count of the rest.

A machine moves its name to a new key by **key continuity**, with the old key's proof. The MDM puts the renewed certificate and its key next to the current ones, as `<cert>.next` and `<key>.next` (the paths in the machine's `relay:` section, plus `.next`). The machine checks for them every minute while connected. When it finds them, it reads the pair once and checks that the key is the certificate's. It then writes the pair's exact bytes beside the current files as `.staged`, both synced, the key readable by its owner only on Unix (on Windows the folder's access list applies, so keep the folder private). If that cannot be done (a folder it may not write, a full disk), it asks nothing. Then:

1. It asks the relay for a nonce: `POST /relay/v1/rekey/challenge`, on its current, pinned certificate. The answer is `{"nonce": "<64 hex>"}`. A nonce is good once, for this machine, for 60 seconds. At most four are open per machine (`429 too_many_challenges`), and 10 000 in all.
2. It signs, with the current key, `actp-relay-rekey-v1\n<address>\n<nonce>\n` followed by the new leaf certificate's DER. It posts `{"certificates": [<base64 DER>, …], "nonce", "scheme", "signature"}` to `POST /relay/v1/rekey`. `scheme` is the TLS signature scheme number: Ed25519, ECDSA P-256 or P-384, or RSA-PSS SHA-256.
3. The relay moves the pin only when every check holds:
   - the nonce is fresh, and was given to this machine;
   - the new certificate is a valid device certificate now, for the same address, with another key;
   - the signature verifies with the pinned key.

   The nonce is used up whatever the outcome, so a proof cannot be replayed.
4. The pin moves to the new key. It is saved to `machines.json` before the relay answers; if it cannot be saved, the old pin stays and the answer is `503 rekey_not_saved`. `machine_key_continued` records both keys, and the machine's open nonces are dropped.
5. The machine switches to the new identity in memory, for both its TLS to the relay and the end-to-end TLS to callers, and reconnects with it. Only then does it put the staged files in place over the current ones: key, then certificate, and if the certificate cannot follow, the old key goes back. It removes the `.next` pair if it still holds what was proved. The old key is not kept. A `.next` pair that is already the identity in use (delivered again) is only put in place: no request, no reconnect. Until it reconnects, its connection on the old key stays up; the relay cuts it within about ten seconds (`machine_offline`, reason `key_changed`), and a stream dialed on it meanwhile is refused (`machine_key_refused`).

If something goes wrong after the relay moved the pin (its answer was lost, the files could not be put in place, the machine restarted), the relay refuses the old key at the next connection with `403 machine_key_changed`. On that answer, and at most once every ten minutes, the machine tries its `.next` pair, and keeps it, putting it in place, if the relay takes it. The same path takes up a key an admin re-pinned the machine to, as long as the `.next` pair is there. While the pin is still on the old key (the old certificate expired, say), each such try is refused and recorded as `machine_key_refused` with the machine's own `.next` key. At start, the machine repairs the one state a swap cut short leaves: the `.next` key already in place and the old certificate not yet replaced; it puts the `.next` certificate in place too. Any other unusable pair is left as it is, so the old key, the only one that can prove a move, is never lost.

The answers:
- `403` with `rekey_nonce_unknown`, `rekey_certificate_invalid`, `rekey_other_machine`, `rekey_same_key`, `rekey_signature_invalid` or `rekey_not_pinned`, recorded as `machine_refused` with that reason;
- `400` for a malformed request, `405` for anything but `POST`, `429 too_many_challenges`, `503 rekey_not_saved`, not recorded;
- the routes' own `403 machine_key_changed`, `machine_blocked` or `bad_device_certificate` when the connection's certificate is not the machine's pinned one, recorded as for any route.

The machine tries again a minute later. A certificate for the name with a new key and no such proof, from the org's own CA included, is never taken: it cannot even ask for a nonce.

**Renewal window, off by default.** An operator may set `machine_key_renewal_days` (at most 90). A certificate with another key is then also taken without the proof when all of these hold: the pinned certificate expires within that many days (or has expired); the new certificate was issued after the pinned one; and it expires after it. `machine_key_renewed` records it, and the old key's connection is cut (`key_renewed`). The relay warns at start and on reload while the window is above 0. Inside the window, the relay cannot tell a renewal from a second certificate issued at the same time by mistake or by someone who reached the MDM; the real laptop would then be cut off and refused. Use it only for machines that cannot do key continuity.

When a machine cannot prove its new key (it was offline past its certificate's expiry, was reinstalled, or lost its key), an admin re-pins it. With the new certificate in the machine's `.next` files, the machine takes it up by itself once re-pinned; otherwise the new certificate goes in place of the old on the machine. Best, re-pin it to the new key itself (the SHA-256 of its public key, as lowercase hex):

```bash
curl -X POST -H "Authorization: Bearer $ADMIN" -d '{"machine": "C02XK1ABJG5H", "reason": "reinstalled, ticket 4411", "key": "9f86d0…"}' https://relay.example.com/relay/v1/repin
```

The machine's current connection is cut, and only that key is taken from then on. Without `key`, the next certificate seen for the name is pinned, whoever presents it: revoke the old certificate first when its key may be in someone else's hands. The answer says whether the name was pinned (`{"machine": …, "was_pinned": true}`), and `machine_repinned` records who, why and the key. `GET /relay/v1/machines` shows each name's pinned `key` and its `key_until`.

`machines.json` holds the pins. If it cannot be read or is damaged, the relay refuses to start and leaves the file as it is: restore it, or move it aside to pin every machine afresh. Pinning is trust on first use: it protects a name from the moment the relay first sees it, not before.

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
| `400 bad_on_behalf_of` | `X-Actp-On-Behalf-Of` sent twice, or not 1 to 256 bytes of UTF-8 without control, invisible or direction-changing characters. |

A caller that acts for a person (an IT bridge operating a laptop as one IT person) says so with `X-Actp-On-Behalf-Of: <who>` on the tunnel request (`RelayRoute::on_behalf_of` in the library). Nobody checks it: the relay records it with the session, and passes it to the machine with the caller's name and certificate fingerprint in `open`, and the machine records them with the link (`relay_on_behalf_of`). It must not hold control, invisible or direction-changing characters, so a log shows what was sent. It makes a misuse traceable, not impossible: what the machine trusts is still the credentials inside the TLS.

Caller certificates are checked again on every tunnel request, on every reload and every ten seconds; a caller whose certificate is revoked, expires or is blocked is cut off with its sessions. `caller_rate` and `max_connections_per_ip` count per IP address (per /64 for IPv6), so callers behind one NAT address share them; the rate limit covers every route except the machines' own.

A session ends at the relay when either side closes, when its machine's control connection is lost (the machine is offline), when the machine or the caller is blocked or its certificate stops being valid, or on the org-wide stop. Idle TCP connections are probed with keepalives, so a laptop that vanishes mid-session is noticed within a few minutes.

Anything else comes from the machine itself.

### The issuer pass-through

Laptops sometimes need to ask the organization's identity service something (for example, whether the person whose papers they hold has been revoked), and they cannot reach it. With an `issuer` section, a machine can ask it through the relay:

```yaml
issuer:
  url: https://idm.internal:8788          # the identity service (http:// only to a loopback address, such as 127.0.0.1)
  ca: /etc/actp-relay/idm-ca.pem          # roots for its certificate; required for https
  headers:                                # the relay's own credentials there
    X-Example-Caller: relay
    X-Example-Secret: file:/etc/actp-relay/idm-secret   # file:PATH (read again on reload) or env:NAME (read at start)
  paths: [/v1/generation/signed]          # the only paths forwarded, exactly
  rate: {per_second: 1, burst: 10}        # per machine
  timeout_seconds: 5
```

A machine sends `GET /relay/v1/issuer/<path>?<query>` with its device certificate (callers and strangers are refused, and blocked machines as on every machine route). If `<path>` is one of `paths`, the relay asks `GET <url><path>?<query>` with the configured headers, plus `X-Relay-Machine: <the machine's name>` from its certificate (which the machine cannot set or change), and hands back the status (200 to 599 only) and the body (at most 64 KB) as JSON. Nothing else from the machine is forwarded (not its headers, not a body), and nothing else of the answer comes back.

| Answer | Meaning |
| --- | --- |
| `404 issuer_path_not_forwarded` | The path is not in `paths`. |
| `414 issuer_query_too_long` | The query is over 2048 bytes. |
| `429 issuer_rate_limited` | This machine asked too often (`rate`). Every request counts, refused ones included. |
| `503 issuer_busy` | This machine has 2 questions in flight, or all machines together 32. |
| `502 issuer_unavailable` | The identity service could not be reached, did not answer in time, answered more than 64 KB, or answered with a status outside 200 to 599. |
| `404 not_found` | No `issuer` section. |

The relay sees the questions and the answers, so only forward questions whose answers a machine can check itself: an answer signed by the identity service and bound to a nonce the machine chose cannot be forged or replayed by the relay, only withheld. Every answered question is recorded as `issuer_asked` (machine, path and status) and every refusal as `issuer_refused` (machine and reason, throttled); never a query, as queries name people. The identity service sees `X-Relay-Machine` too, so it can log and limit per machine although the credentials are the relay's. Only forward questions any machine may ask about anyone: a compromised laptop can ask them.

A reload replaces the section and reads `file:` secrets again, so a secret can be rotated without a restart (`env:` values cannot change without one). The rate limits and in-flight counts carry over. A section that cannot be used (a missing file, an unset variable) leaves the old one in force, logs an error and records `issuer_reload_refused`.

### Management and operators

Who is online, the audit, and the org-wide stop are answered only to:

- **an admin**, with an admin token (`Authorization: Bearer …`), from anywhere that can reach the relay;
- **an operator**: a caller whose certificate is valid now, not blocked, and named in `operators` with the permission the route needs. The IT app is the usual operator; a dashboard that only shows who is online gets `machines` alone.

| Route | Admin | Operator needs |
| --- | --- | --- |
| `GET /relay/v1/machines` | yes | `machines` |
| `GET /relay/v1/audit` | yes | `audit` |
| `GET /relay/v1/stop` | yes | any permission |
| `POST /relay/v1/stop` | yes | `stop` |
| `POST /relay/v1/release` | yes | `release` |
| `POST /relay/v1/repin` | yes | never: admins only |

A request with an `Authorization` header is an admin's, judged by the token alone: a wrong token is refused even on an operator's certificate. Without one, the caller certificate decides. Everyone else is refused and gets nothing but the error:

| Answer | Meaning |
| --- | --- |
| `401 unauthorized` | No certificate and no token, or a wrong token. Recorded as `admin_refused`. |
| `403 bad_caller_certificate`, `403 caller_blocked` | A device certificate (a machine), a caller certificate that became invalid after the connection was made, or a blocked caller. Recorded as `caller_refused`. |
| `403 not_an_operator` | A valid caller certificate the configuration gives no role: it may open tunnels, and nothing here. Recorded as `operator_refused`. |
| `403 operator_certificate_not_listed` | The operator has `certificates`, and this is not one of them. Recorded as `operator_refused`. |
| TLS handshake fails | A caller certificate that is expired, revoked, or not from `caller_ca` is refused before any HTTP, so the client sees a TLS or connection error, not a status. |
| `403 operator_not_permitted` | An operator without the permission this route needs. Recorded as `operator_refused`. |

Roles are checked on every request against the configuration in force, so a reload that removes an operator, blocks it or revokes its certificate takes effect on connections already open. `relay_started` and every `config_reloaded` record the operators and what each may do.

An operator is matched by the name in its caller certificate. Any root in `caller_ca` can issue a certificate with that name, so either keep `caller_ca` to roots that control the names they issue, or list the operator's `certificates` (SHA-256 of the DER, `sha256:<hex>`; renewed certificates must be added before the old ones expire).

The operator role is org-wide: an operator sees every machine the relay knows and the whole audit. Which machines a person may operate is the IT app's to check (with the identity service) before it shows them, and the machine's to enforce (org mode); the relay knows programs by their certificates, not people.

#### Who is online

```bash
curl -H "Authorization: Bearer $ADMIN" https://relay.example.com/relay/v1/machines
```

```json
{
  "stop": {"stopped": false, "by": "", "by_kind": "", "on_behalf_of": null, "reason": "", "at": ""},
  "machines": [
    {"machine": "C02XK1ABJG5H", "online": true, "connected_since": "2026-11-16T09:12:03.120Z",
     "first_seen": "2026-11-02T08:00:41.000Z", "last_seen": "2026-11-16T10:40:00.512Z", "sessions": 1,
     "key": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "key_until": "2027-11-02T08:00:00.000Z"}
  ]
}
```

Every machine the relay has seen is listed. `last_seen` is now while a machine is online; once it goes, it is when the relay last heard from it (it is saved to `machines.json` about once a minute, so after a restart it can be up to a minute early). `sessions` counts the callers connected to it now.

`?machine=<address>` (repeatable, up to 1000) lists only those machines, and `?online=true` or `?online=false` only those online or offline. Percent-encode values (`+` is a plus, not a space). Any other parameter, or a malformed one, is `400 bad_query`, never ignored.

#### The audit

```bash
curl --cert it-bridge.pem --key it-bridge.key "https://relay.example.com/relay/v1/audit?kind=sessions&machine=C02XK1ABJG5H&limit=50"
```

```json
{
  "events": [
    {"event": "session_closed", "time": "2026-11-18T10:41:07.512331Z", "session": 42, "machine": "C02XK1ABJG5H",
     "caller": "it-bridge", "on_behalf_of": "dave@example.com", "opened_at": "2026-11-18T10:32:15.003Z",
     "seconds": 532, "bytes_to_machine": 18320, "bytes_to_caller": 90211, "reason": "org_stop"},
    {"event": "session_open", "time": "2026-11-18T10:32:15.004102Z", "session": 42, "machine": "C02XK1ABJG5H",
     "caller": "it-bridge", "caller_certificate": "3b1f…", "on_behalf_of": "dave@example.com"}
  ],
  "more": false,
  "next": null
}
```

The relay's half of the audit, newest first, from `audit.jsonl` and its rotated files. Only these events, with only these fields (the file has more, such as remote addresses, refusals and errors, for the relay's admins):

- `sessions`: `session_open` and `session_closed` (fields as in the table below, without `remote`): who connected to which machine, for whom, when and for how long, and how it ended.
- `stops`: `org_stop`, `org_release` (who, as what, for whom, why), `org_stop_not_saved` and `org_stop_saved`.
- `stops` also has `org_stop_repeated`: the stop pressed again while on (the first record stays).
- `machines`: `machine_online` (without `remote`), `machine_offline`, `machine_replaced`, and every change to a pinned key: `machine_repinned` (an admin's override), `machine_key_continued`, `machine_key_renewed`, `machine_key_refused`.
- `config`: `relay_started` and `config_reloaded`, with the operators and what each may do.

Parameters, each at most once (`kind` may repeat):

| Parameter | Meaning |
| --- | --- |
| `kind` | `sessions`, `stops`, `machines`, `config`, or several (`kind=sessions,stops`). Default: all. |
| `machine`, `caller`, `on_behalf_of` | Only events naming exactly this machine, caller or person. Events without the field are left out: `machine=…` shows that machine's sessions, and a stop's effect on it as `session_closed` with reason `org_stop`, not the stop itself. `caller` also matches the stops and releases that operator pressed (`by`). |
| `since` | RFC 3339 in UTC (`Z`): events at or after it. |
| `before` | RFC 3339 in UTC: events before it. |
| `cursor` | The previous page's `next`: go on from where it ended. |
| `limit` | 1 to 1000; default 100. |

When `more` is true, ask again with the same parameters and `cursor` set to `next`. The cursor is a position in the log (which file, by its first line, and where in it), so pages neither repeat nor skip an event, also while the relay writes and rotates, and also over lines written by older relays, whose times are in milliseconds and not always in order. A cursor whose file has been rotated away gives an empty last page: everything older went with it. The audit keeps `audit_max_mb` times eleven at most, so the oldest events go first.

A page reads at most 64 MB of the log; one that reaches that ends early, possibly with no events, with `more` and a `next` to go on from. So a narrow filter over a large log takes several requests; `since` ends the reading of each file this relay wrote early (older relays' files, whose times are not always in order, are read through). Two queries run at once; a third gets `503 audit_busy` with `Retry-After`. New lines' `time` is in microseconds and later than the line before it, also across rotations and restarts.

What a caller did on a machine (which runbook, consent, the result) is inside the end-to-end encryption: the machine's own audit records it. The two halves meet on the session: the machine's `link_opened` carries `relay_caller`, `relay_caller_certificate` and `relay_on_behalf_of`, the same as the relay's `session_open`.

#### The org-wide stop

```bash
curl -X POST -H "Authorization: Bearer $ADMIN" -d '{"reason": "suspicious activity on the IT account"}' https://relay.example.com/relay/v1/stop
```

```bash
curl -X POST --cert it-bridge.pem --key it-bridge.key -H "X-Actp-On-Behalf-Of: dana@example.com" \
  -d '{"reason": "account secured"}' https://relay.example.com/relay/v1/release
```

`GET /relay/v1/stop` shows the stop. A reason (1 to 1000 bytes) is required for both. An operator must also say whom it acts for, with `X-Actp-On-Behalf-Of` (as on a tunnel request); without it the answer is `400 on_behalf_of_required`, since a caller certificate names a program, not a person. An admin may send it too. The stop records:

```json
{"stop": {"stopped": true, "by": "it-bridge", "by_kind": "operator", "on_behalf_of": "dana@example.com",
          "reason": "suspicious activity on the IT account", "at": "2026-11-18T10:41:07.511Z"}}
```

`by` is the admin token's name or the operator's caller name, and `by_kind` says which (`admin`, `operator`, or `relay` when the relay turned the stop on itself because `stop.json` could not be read). Nobody checks `on_behalf_of`; the relay records it as the IT app said it, and the IT app is what vouches for the person. Pressing the stop while it is on keeps the first record and answers with it; the second press is recorded as `org_stop_repeated`. A release is recorded with its own `by`, `by_kind` and `on_behalf_of`. Stops and releases are written to the audit in the order they took effect; the stop cuts every session before anything is written, so a slow disk does not delay it.

The stop takes effect at once: every session ends (`session_closed`, reason `org_stop`), every machine is told and ends its own links, and every new tunnel is refused with `503 org_stopped` until the release. It is written to `state_dir/stop.json`, so it survives a restart; if that file cannot be read, the relay starts with the stop on. If the stop cannot be written, the answer is `500 stop_not_saved` (the stop still holds) and the relay keeps trying every few seconds. A release is written before it takes effect, so a release that cannot be recorded does not happen (`500 not_released`).

Keep `state_dir` with the relay: a relay that starts without its `stop.json` knows of no stop, and its hello releases the stop on every machine that connects.

#### Re-pinning

Admins only; see Key pinning, above.

#### For programs

`actp_client::ops::RelayOps` (Rust) calls all of this with a caller certificate or an admin token: `machines`, `audit`, `stop_state`, `stop` and `release`, with `on_behalf_of` for the person.

### Audit

`log_dir/audit.jsonl`, one JSON object per line, each with `event` and `time` (RFC 3339 in UTC, microseconds, later than the line before it). Session ids are unique only while the relay runs (they start again after a restart); `session_closed` carries `opened_at`, so it answers who, which machine, when and how long on its own:

| Event | Fields |
| --- | --- |
| `machine_online` | `machine`, `remote` |
| `machine_replaced` | `machine`, `remote`, `old_certificate`, `new_certificate` (SHA-256 fingerprints) |
| `machine_offline` | `machine`, `seconds`, `reason` (`closed`, `silent`, `blocked`, `certificate_invalid`, `key_changed`, `key_renewed`, `repinned`, `relay stopping`, …) |
| `machine_refused` | `remote`, `route`, `reason`, and `machine` when the certificate named one |
| `session_open` | `session`, `machine`, `caller`, `caller_certificate` (SHA-256), `on_behalf_of` (when the caller named one), `remote` |
| `session_closed` | `session`, `machine`, `caller`, `on_behalf_of` (when the caller named one), `opened_at`, `seconds`, `bytes_to_machine`, `bytes_to_caller`, `reason` (`closed`, `idle`, `org_stop`, `machine_offline`, `blocked`, `certificate_invalid`, `caller_blocked`, `caller_certificate_invalid`, `relay_stopping`, `error`, `upgrade_failed`) |
| `connection_refused` | `remote` (the address, or the IPv6 /64, at its limit), and `machine` when it was the machine's limit |
| `machine_key_continued` | `machine`, `old_key`, `new_key` (SHA-256 of the public keys): the pin moved with the old key's proof |
| `machine_key_renewed` | `machine`, `old_key`, `new_key`: the pin moved by the renewal window |
| `machine_key_refused` | `machine`, `pinned_key`, `presented_key`, `repeats` (refusals left out in the minute before) |
| `machine_repinned` | `machine`, `by`, `reason`, `key` (or null), `was_pinned` |
| `caller_refused` | `caller` (when its certificate named one), `machine` (when one was reached), `remote`, `reason` |
| `caller_rate_limited` | `remote` |
| `issuer_asked` | `machine`, `path`, `status` |
| `issuer_refused` | `machine`, `reason` |
| `issuer_reload_refused` | `error` |
| `org_stop` | `by`, `by_kind` (`admin` or `operator`), `caller_certificate` (an operator's, SHA-256), `on_behalf_of` (when given), `reason`, `sessions_dropped` |
| `org_stop_not_saved`, `org_stop_saved` | `error` / nothing |
| `org_release` | `by`, `by_kind`, `caller_certificate`, `on_behalf_of`, `reason` |
| `org_stop_repeated` | as `org_stop`: the stop pressed again while on |
| `admin_refused` | `remote`, `route` |
| `operator_refused` | `caller`, `remote`, `route`, `reason` (`not_an_operator`, `operator_certificate_not_listed`, `operator_not_permitted`) |
| `relay_started` | `operators` (each `caller`, `may`, and how many `certificates`) |
| `config_reloaded` | `blocked_machines`, `blocked_callers` (counts), `operators` (as in `relay_started`) |
| `refusals_not_logged` | `kind`, `count` |

Of each refusal kind (`caller_refused`, `caller_rate_limited`, `connection_refused`, `machine_refused`, `admin_refused`, `operator_refused`, `issuer_refused`), at most 20 a minute are written, across all callers; the rest are counted in `refusals_not_logged`. A flood of refusals therefore leaves only a count of everyone's refusals for that minute; sessions, machines and the stop are always recorded. `machine_key_refused` has its own limit, once a minute per machine, so a second key for a name cannot be hidden in a flood of other refusals.

The stop's own events (`org_stop`, `org_stop_repeated`, `org_release`, `org_stop_not_saved`, `org_stop_saved`) are also written to `log_dir/org_stops.jsonl`, which is never rotated, so no flood of other events can push them out.

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

The machine's audit log records `auth_refused` with the reason and the caller for papers that are genuine but do not let the caller in: `papers_other_machine`, `papers_no_grant`, or a verifier's own code when it names the caller (the test verifier's `papers_expired`). Papers nobody vouches for (`papers_malformed`, a bad signature, an issuer that cannot be asked, `no_papers_verifier`) are refused without an audit line, as unknown tokens are, so they cannot fill the log. The same person refused for the same reason is written once a minute, with `repeats` counting the ones left out. `link_opened` names the caller as `papers:<caller id>`. On a relayed connection `link_opened` and `link_resumed` also carry what the relay reported about who opened the stream: `relay_report` (`given`; `none` when the relay said nothing, as older relays do; `malformed` when it said something in a shape no relay gives: what is in shape is kept, the rest left out), `relay_caller`, `relay_caller_certificate` and `relay_on_behalf_of` (empty where it said none). They are for tracing, never for deciding: a relay could lie, and `relay_on_behalf_of` is what the caller said, not who the papers name (`token`). Every resume over a relay is recorded, from wherever it picks up; a direct one, as in the Go server, only past the start. `auth_refused` does not carry them: a refusal is tied to the caller through the relay's `session_open`. Token names starting with `papers:` are reserved, and an empty `org:` section is an error, not a quiet return to tokens.

## Protocol

Between a machine and the relay (`actp_proto::relay`):

1. The machine opens `wss://<relay>/relay/v1/connect` with its device certificate and the WebSocket subprotocol `actp-relay.v2` (v1 carried plain HTTP on its streams; a v1 machine and a v2 relay refuse each other). The relay answers with `{"type":"hello","machine":"<address>","stopped":<bool>}` and pings every 15 s; the machine pings every 20 s. Either side drops a connection that stays silent too long.
2. A caller opens `wss://<relay>/relay/v1/tunnel/<machine>` with its caller certificate and subprotocol `actp-relay-tunnel.v1`. The relay sends the machine `{"type":"open","stream":"<64 hex>","opened_by":{"caller":"<name>","caller_certificate":"<64 hex>","on_behalf_of":"<who>"}}` (`opened_by` and `on_behalf_of` may be absent; older relays send neither, and older machines ignore them); the machine opens `wss://<relay>/relay/v1/stream/<id>` with its certificate and subprotocol `actp-relay-stream.v2`. Only the machine that was asked can take the stream. The relay answers the caller's upgrade once the stream is there, and joins the two: binary messages on both carry the same bytes, the caller's TLS to the machine (`actp_proto::e2e`), which the machine answers with its device certificate and then serves like any other connection. Closing either side closes both directions: a half-closed connection is not kept half open.
3. `{"type":"stop"}` and `{"type":"release"}` carry the org-wide stop, and so does the hello's `stopped`. While it is on, the machine ends every link and refuses new links and resumes with `503 org_stopped`, even if the relay goes on routing callers to it.

Unknown message types are ignored, so a newer relay can add messages.
